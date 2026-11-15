package pe_test

import (
	"crypto/md5" // #nosec G501 -- Test vector verification for imphash.
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401 -- Test vector verification for imphash.
	return hex.EncodeToString(sum[:])
}

func TestImphashLibraries(t *testing.T) {
	// Empty or symbol-less inputs must return ("", false) instead of md5("").
	if got, ok := pe.Imphash(nil); ok || got != "" {
		t.Fatalf("Imphash(nil) = (%q, %t), want (\"\", false)", got, ok)
	}
	if got, ok := pe.Imphash([]pe.ImportLibrary{{DLL: "empty.dll"}}); ok || got != "" {
		t.Fatalf("Imphash(empty symbols) = (%q, %t), want (\"\", false)", got, ok)
	}

	cases := []struct {
		name string
		libs []pe.ImportLibrary
		want string
	}{
		{
			name: "named_case_folding_and_extension_stripping",
			libs: []pe.ImportLibrary{
				{DLL: "KERNEL32.DLL", Symbols: []pe.ImportSymbol{{Name: "VirtualAlloc"}, {Name: "VirtualFree"}}},
				{DLL: "Sample.Ext.OCX", Symbols: []pe.ImportSymbol{{Name: "DllRegisterServer"}}},
				{DLL: "driver.SYS", Symbols: []pe.ImportSymbol{{Name: "IoCreateDevice"}}},
				{DLL: "custom.drv", Symbols: []pe.ImportSymbol{{Name: "Entry"}}},
				{DLL: "Example.dllx", Symbols: []pe.ImportSymbol{{Name: "Export"}}},
			},
			want: md5Hex("kernel32.virtualalloc,kernel32.virtualfree,sample.ext.dllregisterserver,driver.iocreateDevice,custom.drv.entry,example.export"),
		},
		{
			name: "ws2_wsock_and_oleaut_ordinals_and_nul_truncation",
			libs: []pe.ImportLibrary{
				{DLL: "WS2_32.DLL", Symbols: []pe.ImportSymbol{
					{ByOrdinal: true, Ordinal: 1},
					{ByOrdinal: true, Ordinal: 501},
				}},
				{DLL: "wsock32.dll", Symbols: []pe.ImportSymbol{
					{ByOrdinal: true, Ordinal: 115},
				}},
				{DLL: "OLEAUT32.DLL", Symbols: []pe.ImportSymbol{
					{ByOrdinal: true, Ordinal: 2},
					{ByOrdinal: true, Ordinal: 999},
				}},
				{DLL: "other.dll\x00ignored", Symbols: []pe.ImportSymbol{
					{Name: "FuncA\x00trailing"},
					{ByOrdinal: true, Ordinal: 7},
				}},
			},
			want: md5Hex("ws2_32.accept,ws2_32.ord501,wsock32.wsastartup,oleaut32.sysallocstring,oleaut32.ord999,other.funca,other.ord7"),
		},
		{
			name: "duplicates_and_order_preserved",
			libs: []pe.ImportLibrary{
				{DLL: "a.dll", Symbols: []pe.ImportSymbol{{Name: "F"}, {Name: "F"}}},
				{DLL: "a.dll", Symbols: []pe.ImportSymbol{{Name: "G"}}},
			},
			want: md5Hex("a.f,a.f,a.g"),
		},
	}

	// Ensure lowercase spelling matches written lowercase expectations above.
	cases[0].want = md5Hex(strings.ToLower("kernel32.virtualalloc,kernel32.virtualfree,sample.ext.dllregisterserver,driver.iocreateDevice,custom.drv.entry,example.export"))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pe.Imphash(tc.libs)
			if !ok || got != tc.want {
				t.Fatalf("Imphash() = (%q, %t), want (%q, true)", got, ok, tc.want)
			}
		})
	}
}

func TestFileImphash(t *testing.T) {
	// Zero-import image returns ErrNoImports rather than md5("").
	for _, is64 := range []bool{false, true} {
		noImports := testfixture.Minimal(is64, 1)
		f, err := pe.New(noImports)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.Imphash(noImports); got != "" || !errors.Is(err, pe.ErrNoImports) {
			t.Fatalf("zero-import PE64=%t Imphash = (%q, %v), want ErrNoImports", is64, got, err)
		}
	}

	// Nil File returns ErrInvalidHeader.
	var nilFile *pe.File
	if _, err := nilFile.Imphash(nil); !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil File Imphash err = %v, want ErrInvalidHeader", err)
	}

	// Malformed imports propagate ErrInvalidImport / ErrOutOfBounds rather than ErrNoImports.
	bad := testfixture.Imports(false, 1, 1)
	// Point import descriptor directory RVA out of bounds (directory at offset 256).
	binary.LittleEndian.PutUint32(bad[256:], 0x7fffffff)
	bf, err := pe.New(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bf.Imphash(bad); err == nil || errors.Is(err, pe.ErrNoImports) {
		t.Fatalf("malformed imports Imphash err = %v", err)
	}

	// Valid PE32 and PE32+ binaries match Imphash(f.Imports(data)) and stay safe concurrently.
	want := md5Hex("lib0.function0,lib0.function1,lib1.function0,lib1.function1")
	for _, is64 := range []bool{false, true} {
		data := testfixture.Imports(is64, 2, 2)
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.Imphash(data)
		if err != nil || got != want {
			t.Fatalf("PE64=%t File.Imphash = (%q, %v), want (%q, nil)", is64, got, err, want)
		}
		libs, err := f.Imports(data)
		if err != nil {
			t.Fatal(err)
		}
		libDigest, ok := pe.Imphash(libs)
		if !ok || libDigest != got {
			t.Fatalf("Imphash(libs) = (%q, %t), want %q", libDigest, ok, got)
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				d, err := f.Imphash(data)
				if err != nil || d != want {
					t.Errorf("concurrent Imphash = (%q, %v), want %q", d, err, want)
				}
			})
		}
		wg.Wait()
	}

	// Empty-descriptor image (zero descriptors, non-empty import dir) returns ErrNoImports.
	emptyDesc := testfixture.Minimal(false, 1)
	binary.LittleEndian.PutUint32(emptyDesc[256:], 0x1000)
	binary.LittleEndian.PutUint32(emptyDesc[260:], 20)
	edf, err := pe.New(emptyDesc)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := edf.Imphash(emptyDesc); got != "" || !errors.Is(err, pe.ErrNoImports) {
		t.Fatalf("empty descriptor Imphash = (%q, %v), want ErrNoImports", got, err)
	}
}

func BenchmarkImphash(b *testing.B) {
	data := testfixture.Imports(true, 8, 32)
	f, err := pe.New(data)
	if err != nil {
		b.Fatal(err)
	}
	libs, err := f.Imports(data)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("FromLibraries", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if sum, ok := pe.Imphash(libs); !ok || sum == "" {
				b.Fatalf("Imphash = (%q, %t)", sum, ok)
			}
		}
	})

	b.Run("FileImphash", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if sum, err := f.Imphash(data); err != nil || sum == "" {
				b.Fatalf("File.Imphash = (%q, %v)", sum, err)
			}
		}
	})

	noImports := testfixture.Minimal(true, 1)
	nf, err := pe.New(noImports)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("NoImports", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := nf.Imphash(noImports); !errors.Is(err, pe.ErrNoImports) {
				b.Fatalf("expected ErrNoImports, got %v", err)
			}
		}
	})
}
