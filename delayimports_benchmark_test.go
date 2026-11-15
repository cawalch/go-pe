package pe_test

import (
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkDelayImports(b *testing.B) {
	absent := testfixture.Minimal(true, 1)
	af, err := pe.New(absent)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Absent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			libs, err := af.DelayImports(absent)
			if err != nil || libs != nil {
				b.Fatalf("DelayImports = (%+v, %v)", libs, err)
			}
		}
	})

	for _, is64 := range []bool{false, true} {
		attrs := uint32(1)
		name := "PE64RVA"
		if !is64 {
			attrs = 0
			name = "PE32VA"
		}
		data := testfixture.DelayImportsWithAttributes(is64, attrs, 2, 16)
		f, err := pe.New(data)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				libs, err := f.DelayImports(data)
				if err != nil || len(libs) != 2 {
					b.Fatalf("DelayImports = (%+v, %v)", libs, err)
				}
			}
		})
	}

	large := testfixture.DelayImports(true, 1, 256)
	lf, err := pe.New(large)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Symbols256", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			libs, err := lf.DelayImports(large)
			if err != nil || len(libs) != 1 || len(libs[0].Symbols) != 256 {
				b.Fatalf("DelayImports = (%+v, %v)", libs, err)
			}
		}
	})

	over := testfixture.DelayImports(true, 2, pe.MaxDelayImportSymbols/2+1)
	of, err := pe.New(over)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("OverLimit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			libs, err := of.DelayImports(over)
			if libs != nil || !errors.Is(err, pe.ErrDelayImportLimit) {
				b.Fatalf("DelayImports = (%+v, %v)", libs, err)
			}
		}
	})
}
