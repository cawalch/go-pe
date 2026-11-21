package pe_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestLayoutAnomalies(t *testing.T) {
	var nilFile *pe.File
	if nilFile.LayoutAnomalies().Any() || nilFile.HasOverlappingSections() {
		t.Fatal("nil File reported layout anomalies")
	}

	var unparsed pe.File
	if unparsed.LayoutAnomalies().Any() || unparsed.HasOverlappingSections() {
		t.Fatal("unparsed File reported layout anomalies")
	}

	for _, is64 := range []bool{false, true} {
		data := testfixture.Minimal(is64, 2)
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		if a := f.LayoutAnomalies(); a.Any() {
			t.Fatalf("clean PE64=%t LayoutAnomalies = %+v, want none", is64, a)
		}
		if f.HasOverlappingSections() {
			t.Fatalf("clean PE64=%t HasOverlappingSections = true", is64)
		}

		// 1. Unaligned e_lfanew.
		f1 := *f
		f1.DOSHeader.AddressOfNewEXEHeader = 0x82
		if a := f1.LayoutAnomalies(); !a.UnalignedPEHeader || a.RawSectionOverlap || a.VirtualSectionOverlap {
			t.Fatalf("unaligned e_lfanew got %+v", a)
		}

		// 2. Section overlapping PE headers.
		f2 := *f
		f2.Sections = append([]pe.Section(nil), f.Sections...)
		f2.Sections[0].PointerToRawData = 0x40
		if a := f2.LayoutAnomalies(); !a.SectionHeaderOverlap {
			t.Fatalf("section/header overlap got %+v", a)
		}

		// 3. Raw section overlap (without mutating section order).
		f3 := *f
		f3.Sections = append([]pe.Section(nil), f.Sections...)
		f3.Sections[1].PointerToRawData = f3.Sections[0].PointerToRawData + 0x100
		if a := f3.LayoutAnomalies(); !a.RawSectionOverlap || a.VirtualSectionOverlap || !f3.HasOverlappingSections() {
			t.Fatalf("raw overlap got %+v", a)
		}

		// 4. Virtual section overlap.
		f4 := *f
		f4.Sections = append([]pe.Section(nil), f.Sections...)
		f4.Sections[1].VirtualAddress = f4.Sections[0].VirtualAddress + 0x800
		if a := f4.LayoutAnomalies(); !a.VirtualSectionOverlap || a.RawSectionOverlap || !f4.HasOverlappingSections() {
			t.Fatalf("virtual overlap got %+v", a)
		}
	}
}
