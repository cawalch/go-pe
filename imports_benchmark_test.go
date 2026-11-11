package pe

import (
	"bytes"
	stdpe "debug/pe"
	"errors"
	"fmt"
	"testing"
)

func BenchmarkImports(b *testing.B) {
	for _, is64 := range []bool{false, true} {
		for _, count := range []int{16, 256} {
			data := buildImportsPE(is64, 1, count)
			f, err := New(data)
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("PE64=%t/Symbols%d", is64, count), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := f.Imports(data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
	b.Run("NoDirectory", func(b *testing.B) {
		data := buildMinimalPE(1)
		f, err := New(data)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := f.Imports(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Both paths parse headers and named imports from the same bytes. debug/pe
// returns joined function:DLL strings; go-pe returns structured, owned records
// and checks resource limits. This comparison doesn't cover malformed inputs.
func BenchmarkParseImports(b *testing.B) {
	for _, count := range []int{16, 256} {
		data := buildImportsPE(true, 1, count)
		b.Run(fmt.Sprintf("Symbols%d/go-pe", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := New(data)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := f.Imports(data); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("Symbols%d/debug-pe", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := stdpe.NewFile(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				_, err = f.ImportedSymbols()
				f.Close()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkImportSymbolLimit(b *testing.B) {
	data := buildImportsPE(true, 2, MaxImportSymbols/2+1)
	f, err := New(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := f.Imports(data); !errors.Is(err, ErrImportLimit) {
			b.Fatal(err)
		}
	}
}
