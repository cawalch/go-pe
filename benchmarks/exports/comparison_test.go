package exports_test

import (
	"bytes"
	"crypto/sha256"
	stdpe "debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	binjectpe "github.com/Binject/debug/pe"
	velocidex "github.com/Velocidex/go-pe"
	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
	saferwalllog "github.com/saferwall/pe/log"
)

type discardLogger struct{}

func (discardLogger) Log(saferwalllog.Level, ...any) error { return nil }

func fastHeaderOptions() *saferwall.Options {
	return &saferwall.Options{
		Fast:                       true,
		DisableCertValidation:      true,
		DisableSignatureValidation: true,
		Logger:                     discardLogger{},
	}
}

func importOptions() *saferwall.Options {
	opts := exportOptions()
	opts.OmitExportDirectory = true
	opts.OmitImportDirectory = false
	opts.Logger = discardLogger{}
	return opts
}

func gorootFixture(tb testing.TB, name string) []byte {
	tb.Helper()
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		tb.Fatalf("locate Go toolchain fixtures: %v", err)
	}
	path := filepath.Join(strings.TrimSpace(string(root)), "src", "debug", "pe", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

func TestCrossLibraryHeadersAndImports(t *testing.T) {
	type fixture struct {
		name string
		data []byte
	}
	fixtures := []fixture{
		{"SyntheticPE32_8Sec", testfixture.Minimal(false, 8)},
		{"SyntheticPE64_8Sec", testfixture.Minimal(true, 8)},
		{"SyntheticPE32_Imports16", testfixture.Imports(false, 1, 16)},
		{"SyntheticPE64_Imports16", testfixture.Imports(true, 1, 16)},
		{"gcc-386-mingw-exec", gorootFixture(t, "gcc-386-mingw-exec")},
		{"gcc-amd64-mingw-exec", gorootFixture(t, "gcc-amd64-mingw-exec")},
		{"gcc-386-mingw-no-symbols-exec", gorootFixture(t, "gcc-386-mingw-no-symbols-exec")},
	}

	for _, fx := range fixtures {
		sum := sha256.Sum256(fx.data)
		t.Run(fx.name, func(t *testing.T) {
			t.Logf("size=%d sha256=%s", len(fx.data), hex.EncodeToString(sum[:]))

			gp, err := gope.New(fx.data)
			if err != nil {
				t.Fatalf("go-pe New: %v", err)
			}
			stdF, err := stdpe.NewFile(bytes.NewReader(fx.data))
			if err != nil {
				t.Fatalf("debug/pe NewFile: %v", err)
			}
			defer func() { _ = stdF.Close() }()

			binF, err := binjectpe.NewFile(bytes.NewReader(fx.data))
			if err != nil {
				t.Fatalf("Binject NewFile: %v", err)
			}
			defer func() { _ = binF.Close() }()

			swF, err := saferwall.NewBytes(fx.data, fastHeaderOptions())
			if err != nil {
				t.Fatalf("saferwall NewBytes: %v", err)
			}
			if err := swF.Parse(); err != nil {
				t.Fatalf("saferwall Fast Parse: %v", err)
			}

			vxF, err := velocidex.NewPEFile(bytes.NewReader(fx.data))
			if err != nil {
				t.Fatalf("Velocidex NewPEFile: %v", err)
			}

			if len(gp.Sections) != len(stdF.Sections) || len(gp.Sections) != len(binF.Sections) ||
				len(gp.Sections) != len(swF.Sections) || len(gp.Sections) != len(vxF.Sections) {
				t.Fatalf("section counts differ: go-pe=%d debug/pe=%d binject=%d saferwall=%d velocidex=%d",
					len(gp.Sections), len(stdF.Sections), len(binF.Sections), len(swF.Sections), len(vxF.Sections))
			}

			libs, err := gp.Imports(fx.data)
			if err != nil {
				t.Fatalf("go-pe Imports: %v", err)
			}
			stdSyms, err := stdF.ImportedSymbols()
			if err != nil {
				t.Fatalf("debug/pe ImportedSymbols: %v", err)
			}
			binSyms, err := binF.ImportedSymbols()
			if err != nil {
				t.Fatalf("Binject ImportedSymbols: %v", err)
			}

			swImpF, err := saferwall.NewBytes(fx.data, importOptions())
			if err != nil {
				t.Fatalf("saferwall import NewBytes: %v", err)
			}
			if err := swImpF.Parse(); err != nil {
				t.Fatalf("saferwall import Parse: %v", err)
			}

			var named []string
			gotNamed := 0
			for _, lib := range libs {
				for _, sym := range lib.Symbols {
					if !sym.ByOrdinal {
						gotNamed++
						named = append(named, sym.Name+":"+lib.DLL)
					}
				}
			}
			if !reflect.DeepEqual(named, stdSyms) || !reflect.DeepEqual(named, binSyms) {
				t.Fatalf("named imports differ: go-pe=%v debug/pe=%v binject=%v", named, stdSyms, binSyms)
			}
			if len(libs) != len(swImpF.Imports) {
				t.Fatalf("import DLL counts differ: go-pe=%d saferwall=%d", len(libs), len(swImpF.Imports))
			}
			for i, swLib := range swImpF.Imports {
				if libs[i].DLL != swLib.Name {
					t.Fatalf("DLL[%d] = %q, saferwall = %q", i, libs[i].DLL, swLib.Name)
				}
				if len(libs[i].Symbols) != len(swLib.Functions) {
					t.Fatalf("import[%d] symbol counts differ: go-pe=%d saferwall=%d", i, len(libs[i].Symbols), len(swLib.Functions))
				}
				for j, swSym := range swLib.Functions {
					sym := libs[i].Symbols[j]
					if sym.ByOrdinal != swSym.ByOrdinal || (sym.ByOrdinal && uint32(sym.Ordinal) != swSym.Ordinal) || (!sym.ByOrdinal && (sym.Name != swSym.Name || sym.Hint != swSym.Hint)) {
						t.Fatalf("import[%d][%d] differs: go-pe=%+v saferwall=%+v", i, j, sym, swSym)
					}
					if !sym.HasIATSlot || sym.IATSlotRVA != swSym.ThunkRVA {
						t.Fatalf("import[%d][%d] IATSlotRVA=%#x (has=%t), saferwall ThunkRVA=%#x", i, j, sym.IATSlotRVA, sym.HasIATSlot, swSym.ThunkRVA)
					}
				}
			}
			if gotNamed != len(vxF.Imports) {
				t.Logf("note: Velocidex imports=%d vs named=%d", len(vxF.Imports), gotNamed)
			}
		})
	}
}

func TestMalformedLimitAndNonPESemantics(t *testing.T) {
	nonPE := bytes.Repeat([]byte("NOT_PE_HEADER_DATA"), 256)
	coffObj := gorootFixture(t, "gcc-amd64-mingw-obj")
	vmlinuz := gorootFixture(t, "vmlinuz-4.15.0-47-generic")
	overSections := testfixture.Minimal(true, gope.MaxSections+1)
	overImports := testfixture.Imports(true, 1, gope.MaxImportSymbols+1)

	overExports := testfixture.Exports(true, 1)
	binary.LittleEndian.PutUint32(overExports[532:], gope.MaxExportSymbols+1)

	unmappedImport := testfixture.Imports(true, 1, 2)
	binary.LittleEndian.PutUint32(unmappedImport[524:], 0xffff0000)

	cases := []struct {
		name string
		data []byte
	}{
		{"NonPE4KiB", nonPE},
		{"COFFObject_amd64", coffObj},
		{"VmlinuzStub", vmlinuz},
		{"SectionLimit257", overSections},
		{"ImportLimit65537", overImports},
		{"ExportLimit65537", overExports},
		{"UnmappedImportDLL", unmappedImport},
	}

	for _, tc := range cases {
		sum := sha256.Sum256(tc.data)
		t.Run(tc.name, func(t *testing.T) {
			var gpErr, stdErr, binNewErr, binImpErr, swErr, vxErr error
			if f, err := gope.New(tc.data); err != nil {
				gpErr = err
			} else if _, err := f.Imports(tc.data); err != nil {
				gpErr = err
			} else if _, err := f.Exports(tc.data); err != nil {
				gpErr = err
			}

			if f, err := stdpe.NewFile(bytes.NewReader(tc.data)); err != nil {
				stdErr = err
			} else {
				_, stdErr = f.ImportedSymbols()
				_ = f.Close()
			}

			binNewErr, binImpErr = func() (newErr, impErr error) {
				defer func() {
					if r := recover(); r != nil {
						impErr = fmt.Errorf("panic: %v", r)
					}
				}()
				f, err := binjectpe.NewFile(bytes.NewReader(tc.data))
				if err != nil {
					return err, nil
				}
				defer func() { _ = f.Close() }()
				_, impErr = f.ImportedSymbols()
				return nil, impErr
			}()

			swErr = func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				f, err := saferwall.NewBytes(tc.data, importOptions())
				if err != nil {
					return err
				}
				return f.Parse()
			}()

			vxErr = func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				_, err = velocidex.NewPEFile(bytes.NewReader(tc.data))
				return err
			}()

			t.Logf("sha256=%s go-pe=%v | debug/pe=%v | binject=(%v, %v) | saferwall=%v | velocidex=%v",
				hex.EncodeToString(sum[:8]), gpErr, stdErr, binNewErr, binImpErr, swErr, vxErr)

			switch tc.name {
			case "NonPE4KiB":
				if !errors.Is(gpErr, gope.ErrNotPE) || stdErr == nil || binNewErr == nil || swErr == nil || vxErr == nil {
					t.Fatalf("unexpected non-PE acceptance")
				}
			case "COFFObject_amd64":
				if !errors.Is(gpErr, gope.ErrNotPE) || swErr == nil || vxErr == nil {
					t.Fatalf("expected PE-only parsers to reject COFF object")
				}
				if stdErr != nil || binNewErr != nil || binImpErr == nil {
					t.Fatalf("unexpected COFF object behavior: std=%v binNew=%v binImp=%v", stdErr, binNewErr, binImpErr)
				}
			case "VmlinuzStub":
				if gpErr != nil || stdErr != nil || binNewErr != nil || binImpErr == nil || swErr != nil || vxErr != nil {
					t.Fatalf("unexpected stub behavior: gp=%v std=%v bin=(%v,%v) sw=%v vx=%v", gpErr, stdErr, binNewErr, binImpErr, swErr, vxErr)
				}
			case "SectionLimit257":
				if !errors.Is(gpErr, gope.ErrSectionLimit) {
					t.Fatalf("expected ErrSectionLimit, got %v", gpErr)
				}
			case "ImportLimit65537":
				if !errors.Is(gpErr, gope.ErrImportLimit) {
					t.Fatalf("expected ErrImportLimit, got %v", gpErr)
				}
			case "ExportLimit65537":
				if !errors.Is(gpErr, gope.ErrExportLimit) {
					t.Fatalf("expected ErrExportLimit, got %v", gpErr)
				}
			case "UnmappedImportDLL":
				if !errors.Is(gpErr, gope.ErrOutOfBounds) {
					t.Fatalf("expected ErrOutOfBounds, got %v", gpErr)
				}
			}
		})
	}
}

var (
	benchSinkAny any
	benchSinkInt int
)

func measureRetainedBytes(t *testing.T, count int, build func() any) int64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	kept := make([]any, count)
	for i := range count {
		kept[i] = build()
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(kept)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return int64(after.HeapAlloc-before.HeapAlloc) / int64(count)
}

func TestRetainedBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping retained-heap measurement under -short")
	}
	const count = 100
	data := gorootFixture(t, "gcc-amd64-mingw-exec")
	optsFast := fastHeaderOptions()
	optsImp := importOptions()

	type retained struct {
		goPeHeaders    int64
		goPeImports    int64
		stdPe          int64
		binject        int64
		saferwallFast  int64
		saferwallImp   int64
		velocidexEager int64
	}
	r := retained{
		goPeHeaders: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := gope.New(buf)
			return f
		}),
		goPeImports: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := gope.New(buf)
			libs, _ := f.Imports(buf)
			return libs
		}),
		stdPe: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := stdpe.NewFile(bytes.NewReader(buf))
			_, _ = f.ImportedSymbols()
			return f
		}),
		binject: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := binjectpe.NewFile(bytes.NewReader(buf))
			_, _ = f.ImportedSymbols()
			return f
		}),
		saferwallFast: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := saferwall.NewBytes(buf, optsFast)
			_ = f.Parse()
			return f
		}),
		saferwallImp: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := saferwall.NewBytes(buf, optsImp)
			_ = f.Parse()
			return f
		}),
		velocidexEager: measureRetainedBytes(t, count, func() any {
			buf := append([]byte(nil), data...)
			f, _ := velocidex.NewPEFile(bytes.NewReader(buf))
			return f
		}),
	}
	t.Logf("Retained heap per instance (gcc-amd64-mingw-exec, input=%d B): go-pe(headers)=%d B, go-pe(imports)=%d B, debug/pe=%d B, Binject=%d B, saferwall(Fast)=%d B, saferwall(Imports)=%d B, Velocidex(Eager)=%d B",
		len(data), r.goPeHeaders, r.goPeImports, r.stdPe, r.binject, r.saferwallFast, r.saferwallImp, r.velocidexEager)
}

func BenchmarkHeaders(b *testing.B) {
	fixtures := []struct {
		name string
		data []byte
	}{
		{"SyntheticPE32_8Sec", testfixture.Minimal(false, 8)},
		{"SyntheticPE64_8Sec", testfixture.Minimal(true, 8)},
		{"GCC_386_MinGW", gorootFixture(b, "gcc-386-mingw-exec")},
		{"GCC_AMD64_MinGW", gorootFixture(b, "gcc-amd64-mingw-exec")},
	}
	optsFast := fastHeaderOptions()

	for _, fx := range fixtures {
		data := fx.data
		b.Run(fx.name, func(b *testing.B) {
			b.Run("go-pe", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := gope.New(data)
					if err != nil {
						b.Fatal(err)
					}
					benchSinkAny = f
				}
			})
			b.Run("debug-pe", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := stdpe.NewFile(bytes.NewReader(data))
					if err != nil {
						b.Fatal(err)
					}
					_ = f.Close()
					benchSinkAny = f
				}
			})
			b.Run("Binject", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := binjectpe.NewFile(bytes.NewReader(data))
					if err != nil {
						b.Fatal(err)
					}
					_ = f.Close()
					benchSinkAny = f
				}
			})
			b.Run("saferwall-Fast", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := saferwall.NewBytes(data, optsFast)
					if err != nil {
						b.Fatal(err)
					}
					if err := f.Parse(); err != nil {
						b.Fatal(err)
					}
					benchSinkAny = f
				}
			})
			b.Run("Velocidex-ReaderEager", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := velocidex.NewPEFile(bytes.NewReader(data))
					if err != nil {
						b.Fatal(err)
					}
					benchSinkAny = f
				}
			})
		})
	}
}

func BenchmarkImportsComparison(b *testing.B) {
	fixtures := []struct {
		name string
		data []byte
	}{
		{"SyntheticPE64_Symbols16", testfixture.Imports(true, 1, 16)},
		{"SyntheticPE64_Symbols256", testfixture.Imports(true, 1, 256)},
		{"SyntheticPE32_Symbols256", testfixture.Imports(false, 1, 256)},
		{"GCC_AMD64_MinGW", gorootFixture(b, "gcc-amd64-mingw-exec")},
	}
	optsImp := importOptions()

	for _, fx := range fixtures {
		data := fx.data
		b.Run(fx.name, func(b *testing.B) {
			b.Run("go-pe", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := gope.New(data)
					if err != nil {
						b.Fatal(err)
					}
					libs, err := f.Imports(data)
					if err != nil {
						b.Fatal(err)
					}
					benchSinkAny = libs
				}
			})
			b.Run("debug-pe", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := stdpe.NewFile(bytes.NewReader(data))
					if err != nil {
						b.Fatal(err)
					}
					syms, err := f.ImportedSymbols()
					if err != nil {
						b.Fatal(err)
					}
					_ = f.Close()
					benchSinkAny = syms
				}
			})
			b.Run("Binject", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := binjectpe.NewFile(bytes.NewReader(data))
					if err != nil {
						b.Fatal(err)
					}
					syms, err := f.ImportedSymbols()
					if err != nil {
						b.Fatal(err)
					}
					_ = f.Close()
					benchSinkAny = syms
				}
			})
			b.Run("saferwall-ImportsOnly", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := saferwall.NewBytes(data, optsImp)
					if err != nil {
						b.Fatal(err)
					}
					if err := f.Parse(); err != nil {
						b.Fatal(err)
					}
					benchSinkAny = f
				}
			})
			b.Run("Velocidex-ReaderEager", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := velocidex.NewPEFile(bytes.NewReader(data))
					if err != nil {
						b.Fatal(err)
					}
					benchSinkAny = f
				}
			})
		})
	}
}

func BenchmarkNonPEAndLimits(b *testing.B) {
	nonPE := bytes.Repeat([]byte("NOT_PE_HEADER_DATA"), 256)
	optsFast := fastHeaderOptions()
	optsExp := exportOptions()
	optsExp.Logger = discardLogger{}
	optsImp := importOptions()

	b.Run("NonPE4KiB", func(b *testing.B) {
		b.Run("go-pe", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := gope.New(nonPE)
				if err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("debug-pe", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := stdpe.NewFile(bytes.NewReader(nonPE))
				if err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("Binject", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := binjectpe.NewFile(bytes.NewReader(nonPE))
				if err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("saferwall-Fast", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, _ := saferwall.NewBytes(nonPE, optsFast)
				if err := f.Parse(); err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("Velocidex", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := velocidex.NewPEFile(bytes.NewReader(nonPE)); err == nil {
					b.Fatal("expected error")
				}
			}
		})
	})

	overSections := testfixture.Minimal(true, gope.MaxSections+1)
	b.Run(fmt.Sprintf("SectionLimit%d", gope.MaxSections+1), func(b *testing.B) {
		b.Run("go-pe-Reject", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := gope.New(overSections); err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("saferwall-Fast-Accept", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, _ := saferwall.NewBytes(overSections, optsFast)
				benchSinkAny = f.Parse()
			}
		})
	})

	overExports := testfixture.Exports(true, 1)
	binary.LittleEndian.PutUint32(overExports[532:], gope.MaxExportSymbols+1)
	b.Run(fmt.Sprintf("ExportLimit%d", gope.MaxExportSymbols+1), func(b *testing.B) {
		b.Run("go-pe-Reject", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := gope.New(overExports)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := f.Exports(overExports); err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("saferwall-ExportsOnly-Partial", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, _ := saferwall.NewBytes(overExports, optsExp)
				benchSinkAny = f.Parse()
			}
		})
	})

	overImports := testfixture.Imports(true, 1, gope.MaxImportSymbols+1)
	b.Run(fmt.Sprintf("ImportLimit%d", gope.MaxImportSymbols+1), func(b *testing.B) {
		b.Run("go-pe-Reject", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := gope.New(overImports)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := f.Imports(overImports); err == nil {
					b.Fatal("expected error")
				}
			}
		})
		b.Run("saferwall-ImportsOnly-Accept", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, _ := saferwall.NewBytes(overImports, optsImp)
				benchSinkAny = f.Parse()
			}
		})
	})

	// Separate file I/O + parsing vs in-memory parsing.
	path := filepath.Join(b.TempDir(), "gcc-amd64-mingw-exec")
	if err := os.WriteFile(path, gorootFixture(b, "gcc-amd64-mingw-exec"), 0600); err != nil {
		b.Fatal(err)
	}
	b.Run("FileIO_GCC_AMD64_MinGW", func(b *testing.B) {
		b.Run("ReadFileOnly", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				raw, err := os.ReadFile(path)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkAny = raw
			}
		})
		b.Run("go-pe-Open", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := gope.Open(path)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkAny = f
			}
		})
		b.Run("debug-pe-Open", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := stdpe.Open(path)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkInt += len(f.Sections)
				_ = f.Close()
			}
		})
	})
}
