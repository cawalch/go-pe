package pe

import (
	"cmp"
	"slices"
)

// LayoutAnomalies reports non-fatal PE structural anomalies that commonly
// trigger parser differentials or Windows loader rejections.
type LayoutAnomalies struct {
	UnalignedPEHeader     bool
	RawSectionOverlap     bool
	VirtualSectionOverlap bool
	SectionHeaderOverlap  bool
}

// Any reports whether any layout anomaly was detected.
func (a LayoutAnomalies) Any() bool {
	return a.UnalignedPEHeader || a.RawSectionOverlap || a.VirtualSectionOverlap || a.SectionHeaderOverlap
}

type layoutSpan struct {
	start uint64
	end   uint64
}

// LayoutAnomalies inspects f's headers and section table without mutating f
// and reports structural anomalies (unaligned e_lfanew, sections overlapping
// PE headers, overlapping raw section ranges, and overlapping virtual section
// ranges). Returns zero value when f is nil or unparsed.
func (f *File) LayoutAnomalies() LayoutAnomalies {
	if err := f.validateParsedHeaders(); err != nil {
		return LayoutAnomalies{}
	}

	var out LayoutAnomalies
	if f.DOSHeader.AddressOfNewEXEHeader%4 != 0 {
		out.UnalignedPEHeader = true
	}

	headerEnd := certificateHeaderEnd(f)

	var rawSpans [MaxSections]layoutSpan
	var virtSpans [MaxSections]layoutSpan
	rawCount := 0
	virtCount := 0

	for i := range f.Sections {
		sec := &f.Sections[i]
		if sec.SizeOfRawData > 0 {
			start := uint64(sec.PointerToRawData)
			end := start + uint64(sec.SizeOfRawData)
			if start < headerEnd {
				out.SectionHeaderOverlap = true
			}
			rawSpans[rawCount] = layoutSpan{start: start, end: end}
			rawCount++
		}
		vSize := max(sec.VirtualSize, sec.SizeOfRawData)
		if vSize > 0 {
			vStart := uint64(sec.VirtualAddress)
			vEnd := vStart + uint64(vSize)
			virtSpans[virtCount] = layoutSpan{start: vStart, end: vEnd}
			virtCount++
		}
	}

	out.RawSectionOverlap = hasSpanOverlap(rawSpans[:rawCount])
	out.VirtualSectionOverlap = hasSpanOverlap(virtSpans[:virtCount])
	return out
}

// HasOverlappingSections reports whether any non-empty sections overlap in
// either raw file space or virtual address space.
func (f *File) HasOverlappingSections() bool {
	a := f.LayoutAnomalies()
	return a.RawSectionOverlap || a.VirtualSectionOverlap
}

func hasSpanOverlap(spans []layoutSpan) bool {
	if len(spans) < 2 {
		return false
	}
	slices.SortFunc(spans, func(a, b layoutSpan) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}
		return cmp.Compare(a.end, b.end)
	})
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return true
		}
	}
	return false
}
