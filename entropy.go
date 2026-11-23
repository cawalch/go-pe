package pe

import (
	"bytes"
	"fmt"
	"math"
)

// MaxSectionDataBytes limits the maximum raw section slice copied by
// [File.SectionData].
const MaxSectionDataBytes = MaxAuthenticodeDigestBytes

// ShannonEntropy computes the Shannon entropy of data in bits per byte
// ([0.0, 8.0]) without heap allocations. Returns 0 for an empty slice.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]uint64
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func (f *File) sectionRawBounds(data []byte, index int) (uint64, uint64, error) {
	if err := f.validateParsedHeaders(); err != nil {
		return 0, 0, err
	}
	if f.fileSize < 0 || int64(len(data)) != f.fileSize {
		return 0, 0, fmt.Errorf("%w: input size %d does not match parsed file size %d", ErrOutOfBounds, len(data), f.fileSize)
	}
	if index < 0 || index >= len(f.Sections) {
		return 0, 0, fmt.Errorf("%w: section index %d out of range [0, %d)", ErrOutOfBounds, index, len(f.Sections))
	}
	sec := &f.Sections[index]
	if sec.SizeOfRawData == 0 {
		return 0, 0, nil
	}
	start := uint64(sec.PointerToRawData)
	end := start + uint64(sec.SizeOfRawData)
	if end > uint64(len(data)) {
		return 0, 0, fmt.Errorf("%w: section %d raw range [%#x, %#x) exceeds input size %d", ErrOutOfBounds, index, start, end, len(data))
	}
	return start, end, nil
}

// SectionData returns a newly allocated copy of the raw bytes for section
// index, validating header state, input length, [MaxSectionDataBytes], and raw
// file bounds. Returns nil, nil when SizeOfRawData is zero.
func (f *File) SectionData(data []byte, index int) ([]byte, error) {
	start, end, err := f.sectionRawBounds(data, index)
	if err != nil {
		return nil, err
	}
	if start == end {
		return nil, nil
	}
	size := end - start
	if size > MaxSectionDataBytes {
		return nil, fmt.Errorf("%w: section %d raw size %d exceeds %d", ErrOutOfBounds, index, size, MaxSectionDataBytes)
	}
	return bytes.Clone(data[start:end]), nil
}

// SectionEntropy computes the Shannon entropy ([0.0, 8.0] bits/byte) of the
// raw bytes for section index without copying the section body. Returns 0, nil
// when SizeOfRawData is zero.
func (f *File) SectionEntropy(data []byte, index int) (float64, error) {
	start, end, err := f.sectionRawBounds(data, index)
	if err != nil {
		return 0, err
	}
	if start == end {
		return 0, nil
	}
	return ShannonEntropy(data[start:end]), nil
}

// OverlayEntropy computes the Shannon entropy ([0.0, 8.0] bits/byte) of any
// trailing overlay bytes beyond [File.DeclaredExtent] without copying the
// overlay. Returns (0, false, nil) when no overlay is present.
func (f *File) OverlayEntropy(data []byte) (float64, bool, error) {
	if err := f.validateParsedHeaders(); err != nil {
		return 0, false, err
	}
	if f.fileSize < 0 || int64(len(data)) != f.fileSize {
		return 0, false, fmt.Errorf("%w: input size %d does not match parsed file size %d", ErrOutOfBounds, len(data), f.fileSize)
	}
	offset, ok := f.OverlayOffset()
	if !ok {
		return 0, false, nil
	}
	return ShannonEntropy(data[offset:]), true, nil
}
