package pe

import (
	"bytes"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func requireNativeWindows(t *testing.T) {
	t.Helper()
	if os.Getenv("GO_PE_NATIVE_VALIDATION") != "1" {
		t.Skip("set GO_PE_NATIVE_VALIDATION=1 in an x64 MSVC developer environment")
	}
}

func TestNativeWindowsCompilers(t *testing.T) {
	requireNativeWindows(t)
	for _, compiler := range []string{"cl.exe", "clang-cl.exe"} {
		t.Run(compiler, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "fixture.c")
			// Only this benign source is executed, never the signed compiler sample below.
			if err := os.WriteFile(source, []byte("int Answer(void) { return 42; }\n"), 0600); err != nil {
				t.Fatal(err)
			}
			definition := filepath.Join(dir, "fixture.def")
			if err := os.WriteFile(definition, []byte("LIBRARY fixture\nEXPORTS\nAnswer @1\nForwarded=KERNEL32.GetCurrentProcessId @2 PRIVATE\n"), 0600); err != nil {
				t.Fatal(err)
			}
			dll := filepath.Join(dir, "fixture.dll")
			cmd := exec.Command(compiler, "/nologo", "/LD", "/GS-", source, "/link", "/NOENTRY", "/NODEFAULTLIB", "kernel32.lib", "/OUT:"+dll, "/DEF:"+definition)
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("compile: %v\n%s", err, out)
			}
			data, err := os.ReadFile(dll)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("compiler=%s bytes=%d sha256=%x", compiler, len(data), sha256.Sum256(data))
			f, err := New(data)
			if err != nil {
				t.Fatal(err)
			}
			exports, err := f.Exports(data)
			if err != nil || exports == nil {
				t.Fatalf("exports: %v", err)
			}
			loaded, err := syscall.LoadDLL(dll)
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.Release()
			foundAnswer, foundForwarded := false, false
			for _, symbol := range exports.Symbols {
				for _, name := range symbol.Names {
					proc, err := loaded.FindProc(name)
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "Answer":
						foundAnswer = true
						if symbol.Forwarded || proc.Addr() != uintptr(loaded.Handle)+uintptr(symbol.RVA) {
							t.Fatal("Answer RVA differs from loader address")
						}
						value, _, _ := proc.Call()
						if value != 42 {
							t.Fatalf("Answer=%d", value)
						}
					case "Forwarded":
						foundForwarded = true
						if !symbol.Forwarded || symbol.Forwarder != "KERNEL32.GetCurrentProcessId" {
							t.Fatalf("forwarder=%+v", symbol)
						}
						value, _, _ := proc.Call()
						if value != uintptr(os.Getpid()) {
							t.Fatalf("forwarded PID=%d", value)
						}
					default:
						t.Fatalf("unexpected export %q", name)
					}
				}
			}
			if !foundAnswer || !foundForwarded {
				t.Fatal("missing expected exports")
			}
			if result := nativeWinVerifyTrust(t, dll); result != 0x800b0100 {
				t.Fatalf("unsigned DLL WinVerifyTrust=%#x, want TRUST_E_NOSIGNATURE", result)
			}
		})
	}
}

// Layouts match wintrust.h on Windows amd64. Keep this test architecture-specific.
type nativeTrustFile struct {
	Size         uint32
	Path         *uint16
	File         uintptr
	KnownSubject *syscall.GUID
}
type nativeTrustData struct {
	Size                   uint32
	Policy, SIP            uintptr
	UI, Revocation, Choice uint32
	File                   *nativeTrustFile
	StateAction            uint32
	State                  uintptr
	URL                    *uint16
	Flags, Context         uint32
	SignatureSettings      uintptr
}

func nativeWinVerifyTrust(t *testing.T, path string) uint32 {
	t.Helper()
	path16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	file := nativeTrustFile{Path: path16}
	file.Size = uint32(unsafe.Sizeof(file))
	// WINTRUST_ACTION_GENERIC_VERIFY_V2; no UI, no revocation, cache-only retrieval.
	action := syscall.GUID{Data1: 0x00aac56b, Data2: 0xcd44, Data3: 0x11d0, Data4: [8]byte{0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
	data := nativeTrustData{UI: 2, Choice: 1, File: &file, StateAction: 1, Flags: 0x10 | 0x1000}
	data.Size = uint32(unsafe.Sizeof(data))
	proc := syscall.NewLazyDLL("wintrust.dll").NewProc("WinVerifyTrust")
	result, _, _ := proc.Call(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	data.StateAction = 2
	proc.Call(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	runtime.KeepAlive(path16)
	return uint32(result)
}

func TestNativeWindowsSignedImage(t *testing.T) {
	requireNativeWindows(t)
	path := os.Getenv("GO_PE_SIGNED_FIXTURE")
	if path == "" {
		t.Fatal("GO_PE_SIGNED_FIXTURE is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("path=%s bytes=%d sha256=%x", path, len(data), sha256.Sum256(data))
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.VerifyAuthenticode(data, AuthenticodeVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signatures) == 0 {
		t.Fatal("fixture must contain an embedded signature")
	}
	timestamps := 0
	for _, signature := range result.Signatures {
		if signature.Digest.Status != AuthenticodeStatusValid || len(signature.Signers) == 0 {
			t.Fatalf("digest/signers: %+v", signature)
		}
		for _, signer := range signature.Signers {
			if signer.Binding.Status != AuthenticodeStatusValid || signer.CMS.Status != AuthenticodeStatusValid || signer.Trust.Status != AuthenticodeStatusUnchecked {
				t.Fatalf("signer: %+v", signer)
			}
			for _, stamp := range signer.Timestamps {
				timestamps++
				t.Logf("timestamp kind=%v time=%s", stamp.Kind, stamp.SigningTime)
				if stamp.Imprint.Status != AuthenticodeStatusValid || stamp.CMS.Status != AuthenticodeStatusValid || stamp.Trust.Status != AuthenticodeStatusUnchecked {
					t.Fatalf("timestamp: %+v", stamp)
				}
			}
		}
	}
	if timestamps == 0 {
		t.Fatal("fixture must contain a timestamp")
	}
	if status := nativeWinVerifyTrust(t, path); status != 0 {
		t.Fatalf("original WinVerifyTrust=%#x", status)
	}
	modified := bytes.Clone(data)
	changed := false
	for _, section := range f.Sections {
		if section.SizeOfRawData > 0 && uint64(section.PointerToRawData) < uint64(len(modified)) {
			modified[section.PointerToRawData] ^= 1
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("no backed section to modify")
	}
	result, err = f.VerifyAuthenticode(modified, AuthenticodeVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, signature := range result.Signatures {
		if signature.Digest.Status != AuthenticodeStatusInvalid {
			t.Fatal("modified digest not rejected")
		}
	}
	copyPath := filepath.Join(t.TempDir(), "modified.exe")
	if err := os.WriteFile(copyPath, modified, 0600); err != nil {
		t.Fatal(err)
	}
	if status := nativeWinVerifyTrust(t, copyPath); status != 0x80096010 {
		t.Fatalf("modified WinVerifyTrust=%#x, want TRUST_E_BAD_DIGEST", status)
	}
}
