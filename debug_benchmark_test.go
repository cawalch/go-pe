package pe_test

import (
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkDebug(b *testing.B) {
	absent := testfixture.Minimal(true, 1)
	af, err := pe.New(absent)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Absent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entries, err := af.Debug(absent)
			if err != nil || entries != nil {
				b.Fatalf("Debug() = (%+v, %v)", entries, err)
			}
		}
	})

	rsds := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1, 2, 3, 4}, 2, []byte(`C:\src\bin\example.pdb`), true)},
	})
	rf, err := pe.New(rsds)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("RSDS", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entries, err := rf.Debug(rsds)
			if err != nil || len(entries) != 1 || entries[0].CodeView == nil {
				b.Fatalf("Debug() = (%+v, %v)", entries, err)
			}
		}
	})

	mixed := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1, 2, 3, 4}, 1, []byte(`C:\src\a.pdb`), true)},
		{Type: pe.DebugTypeVCFeature, SizeOfData: 20, KeepSize: true},
		{Type: pe.DebugTypePOGO, SizeOfData: 64, KeepSize: true},
		{Type: pe.DebugTypeRepro},
	})
	mf, err := pe.New(mixed)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Mixed4Entries", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entries, err := mf.Debug(mixed)
			if err != nil || len(entries) != 4 {
				b.Fatalf("Debug() = (%+v, %v)", entries, err)
			}
		}
	})

	overSpecs := make([]testfixture.DebugEntrySpec, pe.MaxDebugEntries+1)
	for i := range overSpecs {
		overSpecs[i] = testfixture.DebugEntrySpec{Type: pe.DebugTypeRepro}
	}
	over := testfixture.DebugPE(true, overSpecs)
	of, err := pe.New(over)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("OverLimit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entries, err := of.Debug(over)
			if entries != nil || !errors.Is(err, pe.ErrDebugLimit) {
				b.Fatalf("Debug() = (%+v, %v)", entries, err)
			}
		}
	})
}
