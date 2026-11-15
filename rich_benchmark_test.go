package pe_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkRichHeader(b *testing.B) {
	absent := testfixture.Minimal(true, 1)
	af, err := pe.New(absent)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Absent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rh, err := af.RichHeader(absent)
			if err != nil || rh != nil {
				b.Fatalf("RichHeader() = (%+v, %v)", rh, err)
			}
		}
	})

	for _, count := range []int{8, 64, 256} {
		entries := make([]testfixture.RichEntrySpec, count)
		for i := range entries {
			entries[i] = testfixture.RichEntrySpec{ToolID: uint16(i + 1), Version: 0x766f, Count: uint32(i + 1)}
		}
		data, _ := testfixture.RichPE(true, testfixture.RichOptions{Entries: entries})
		f, err := pe.New(data)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("Entries%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				rh, err := f.RichHeader(data)
				if err != nil || rh == nil || len(rh.Entries) != count || !rh.ChecksumValid {
					b.Fatalf("RichHeader() = (%+v, %v)", rh, err)
				}
			}
		})
	}

	over := make([]testfixture.RichEntrySpec, pe.MaxRichEntries+1)
	overData, _ := testfixture.RichPE(true, testfixture.RichOptions{Entries: over})
	of, err := pe.New(overData)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("OverLimit", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rh, err := of.RichHeader(overData)
			if rh != nil || !errors.Is(err, pe.ErrRichHeaderLimit) {
				b.Fatalf("RichHeader() = (%+v, %v)", rh, err)
			}
		}
	})
}
