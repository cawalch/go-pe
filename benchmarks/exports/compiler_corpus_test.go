package exports_test

import (
	"bytes"
	"crypto/sha256"
	stdpe "debug/pe"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	gope "github.com/cawalch/go-pe"
)

// Build benign real linker output instead of checking in executables or fetching
// an unversioned binary corpus. Never execute the resulting Windows programs.
func TestGoCompilerCorpus(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"go-pe validation fixture\") }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			output := filepath.Join(dir, arch+".exe")
			args := []string{"build", "-trimpath", "-buildvcs=false", "-o", output}
			if arch == "amd64" {
				args = append(args, "-ldflags=-s -w")
			}
			args = append(args, source)
			cmd := exec.Command("go", args...)
			for _, env := range os.Environ() {
				key := strings.SplitN(env, "=", 2)[0]
				switch key {
				case "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOEXPERIMENT":
					continue
				}
				cmd.Env = append(cmd.Env, env)
			}
			cmd.Env = append(cmd.Env, "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOEXPERIMENT=")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build: %v\n%s", err, out)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("arch=%s stripped=%t bytes=%d sha256=%x", arch, arch == "amd64", len(data), sha256.Sum256(data))
			f, err := gope.New(data)
			if err != nil {
				t.Fatal(err)
			}
			oracle, err := stdpe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = oracle.Close() }()
			if f.FileHeader.Machine != oracle.Machine || len(f.Sections) != len(oracle.Sections) {
				t.Fatal("header mismatch")
			}
			// Compare actual field values, not only section and import counts.
			for i, section := range f.Sections {
				want := oracle.Sections[i]
				if section.Name != want.Name || section.VirtualAddress != want.VirtualAddress || section.VirtualSize != want.VirtualSize || section.PointerToRawData != want.Offset || section.SizeOfRawData != want.Size || section.Characteristics != want.Characteristics {
					t.Fatalf("section %d differs", i)
				}
			}
			imports, err := f.Imports(data)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, lib := range imports {
				for _, sym := range lib.Symbols {
					if !sym.ByOrdinal {
						got = append(got, sym.Name+":"+lib.DLL)
					}
				}
			}
			want, err := oracle.ImportedSymbols()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 || !reflect.DeepEqual(got, want) {
				t.Fatalf("imports differ: got %v want %v", got, want)
			}
			if f.InputTruncated() {
				t.Fatal("complete compiler output marked truncated")
			}
			peOffset := int(binary.LittleEndian.Uint32(data[60:]))
			sectionStart := peOffset + 24 + int(f.FileHeader.SizeOfOptionalHeader)
			headerEnd := sectionStart + 40*len(f.Sections)
			for _, end := range []int{peOffset + 3, sectionStart - 1, headerEnd - 1} {
				if partial, err := gope.New(data[:end]); err == nil || partial != nil {
					t.Fatalf("accepted truncated headers at %d", end)
				}
			}
			partial, err := gope.New(data[:headerEnd])
			// Unstripped output has long section names in the missing COFF
			// string table. Header-only parsing cannot resolve those names.
			if arch != "amd64" {
				if partial != nil || !errors.Is(err, gope.ErrOutOfBounds) {
					t.Fatalf("missing COFF strings: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !partial.InputTruncated() {
					t.Fatal("missing section bodies not reported")
				}
				if libs, err := partial.Imports(data[:headerEnd]); err == nil || libs != nil {
					t.Fatal("accepted missing import payload")
				}
			}
			bad := bytes.Clone(data)
			bad[peOffset] ^= 0xff
			if result, err := gope.New(bad); result != nil || !errors.Is(err, gope.ErrInvalidMagic) {
				t.Fatalf("bad signature: %v", err)
			}
		})
	}
}
