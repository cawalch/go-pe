package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// MaxSections bounds header parsing work and allocations, including malformed
// images. This is a parser resource limit, not a Windows loader compatibility rule.
const MaxSections = 256

// MaxSectionNameBytes bounds COFF long-name reads, including the NUL terminator.
const MaxSectionNameBytes = 256

// ErrSectionLimit indicates that the declared count exceeds MaxSections.
var ErrSectionLimit = errors.New("section count exceeds parser limit")

// SectionHeader represents a PE Section Header (40 bytes).
type SectionHeader struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// Section represents a parsed section with accessor helpers.
type Section struct {
	SectionHeader
	Index int
}

func parseSections(r *SafeReader, offset int64, count uint16, stringTableOffset int64) ([]Section, error) {
	if count > MaxSections {
		return nil, fmt.Errorf("%w: %d", ErrSectionLimit, count)
	}
	// Validate the entire declared table before allocating or returning a snapshot.
	table, err := r.Slice(offset, int64(count)*40)
	if err != nil {
		return nil, err
	}
	sections := make([]Section, count)

	for i := 0; i < int(count); i++ {
		b := table[i*40 : (i+1)*40]
		name, err := parseSectionName(b[:8], r, stringTableOffset)
		if err != nil {
			return nil, fmt.Errorf("section %d name: %w", i, err)
		}

		sec := Section{
			Index: i,
			SectionHeader: SectionHeader{
				Name:                 name,
				VirtualSize:          binary.LittleEndian.Uint32(b[8:12]),
				VirtualAddress:       binary.LittleEndian.Uint32(b[12:16]),
				SizeOfRawData:        binary.LittleEndian.Uint32(b[16:20]),
				PointerToRawData:     binary.LittleEndian.Uint32(b[20:24]),
				PointerToRelocations: binary.LittleEndian.Uint32(b[24:28]),
				PointerToLinenumbers: binary.LittleEndian.Uint32(b[28:32]),
				NumberOfRelocations:  binary.LittleEndian.Uint16(b[32:34]),
				NumberOfLinenumbers:  binary.LittleEndian.Uint16(b[34:36]),
				Characteristics:      binary.LittleEndian.Uint32(b[36:40]),
			},
		}
		sections[i] = sec
	}

	return sections, nil
}

func parseSectionName(raw []byte, r *SafeReader, stringTableOffset int64) (string, error) {
	// Long section names in COFF: starts with '/' followed by decimal offset into string table.
	if raw[0] == '/' && stringTableOffset > 0 {
		end := bytes.IndexByte(raw[1:], 0)
		if end < 0 {
			end = len(raw) - 1
		}
		offset, err := strconv.ParseUint(string(raw[1:1+end]), 10, 32)
		if err != nil || offset < 4 {
			return "", fmt.Errorf("%w: invalid COFF string offset", ErrInvalidHeader)
		}
		size, err := r.ReadUint32(stringTableOffset)
		if err != nil {
			return "", err
		}
		if offset >= uint64(size) {
			return "", fmt.Errorf("%w: COFF string offset exceeds table", ErrInvalidHeader)
		}
		if !r.CheckBounds(stringTableOffset, int64(size)) {
			return "", ErrOutOfBounds
		}
		limit := min(int64(size)-int64(offset), MaxSectionNameBytes)
		return r.ReadASCIIZ(stringTableOffset+int64(offset), limit)
	}

	// Standard 8-byte ASCII name (null-terminated if < 8 bytes).
	idx := bytes.IndexByte(raw, 0)
	if idx >= 0 {
		return string(raw[:idx]), nil
	}
	return string(raw), nil
}

// RVAToOffset maps an RVA to a byte present in the input. Header RVAs below
// SizeOfHeaders map directly. Otherwise the first section in table order whose
// max(VirtualSize, SizeOfRawData) span contains the RVA wins. Raw padding is
// addressable; virtual zero-fill, missing bytes and overflowing offsets are not.
// This is a file-byte mapping policy, not Windows loader emulation.
func (f *File) RVAToOffset(rva uint32) (uint32, bool) {
	if rva < f.OptionalHeader.SizeOfHeaders {
		if int64(rva) >= f.fileSize {
			return 0, false
		}
		return rva, true
	}
	for _, s := range f.Sections {
		if rva < s.VirtualAddress {
			continue
		}
		delta := uint64(rva) - uint64(s.VirtualAddress)
		if delta < uint64(max(s.VirtualSize, s.SizeOfRawData)) {
			offset := uint64(s.PointerToRawData) + delta
			if delta >= uint64(s.SizeOfRawData) || offset > math.MaxUint32 || offset >= uint64(f.fileSize) {
				return 0, false
			}
			return uint32(offset), true
		}
	}
	return 0, false
}

// OffsetToRVA maps an existing file byte in the headers or the first matching
// raw section to an RVA. Overlays and overflowing RVAs have no mapping. Because
// malformed sections can overlap, this need not invert RVAToOffset.
func (f *File) OffsetToRVA(offset uint32) (uint32, bool) {
	if int64(offset) >= f.fileSize {
		return 0, false
	}
	if offset < f.OptionalHeader.SizeOfHeaders {
		return offset, true
	}
	for _, s := range f.Sections {
		if offset < s.PointerToRawData {
			continue
		}
		delta := uint64(offset) - uint64(s.PointerToRawData)
		if delta < uint64(s.SizeOfRawData) {
			rva := uint64(s.VirtualAddress) + delta
			if rva > math.MaxUint32 {
				return 0, false
			}
			return uint32(rva), true
		}
	}
	return 0, false
}
