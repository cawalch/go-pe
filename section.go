package pe

import (
	"bytes"
	"fmt"
	"strconv"
)

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

func parseSections(r *SafeReader, offset int64, count uint16, stringTableOffset uint32) ([]Section, error) {
	// Upper bound sanity check on sections (PE specification recommends max 96).
	// We allow up to 256 for packed/adversarial samples.
	if count > 256 {
		return nil, fmt.Errorf("excessive section count: %d", count)
	}
	sections := make([]Section, 0, count)

	for i := 0; i < int(count); i++ {
		secOffset := offset + int64(i)*40
		b, err := r.Slice(secOffset, 40)
		if err != nil {
			break // Allow partial sections on truncated files
		}

		name := parseSectionName(b[:8], r, stringTableOffset)

		sec := Section{
			Index: i,
			SectionHeader: SectionHeader{
				Name:                 name,
				VirtualSize:          binaryLEUint32(b[8:12]),
				VirtualAddress:       binaryLEUint32(b[12:16]),
				SizeOfRawData:        binaryLEUint32(b[16:20]),
				PointerToRawData:     binaryLEUint32(b[20:24]),
				PointerToRelocations: binaryLEUint32(b[24:28]),
				PointerToLinenumbers: binaryLEUint32(b[28:32]),
				NumberOfRelocations:  binaryLEUint16(b[32:34]),
				NumberOfLinenumbers:  binaryLEUint16(b[34:36]),
				Characteristics:      binaryLEUint32(b[36:40]),
			},
		}
		sections = append(sections, sec)
	}

	return sections, nil
}

func parseSectionName(raw []byte, r *SafeReader, stringTableOffset uint32) string {
	// Long section names in COFF: starts with '/' followed by decimal offset into string table.
	if raw[0] == '/' && stringTableOffset > 0 {
		end := bytes.IndexByte(raw[1:], 0)
		if end < 0 {
			end = len(raw) - 1
		}
		if offset, err := strconv.ParseInt(string(raw[1:1+end]), 10, 64); err == nil {
			target := int64(stringTableOffset) + offset
			if str, err := r.ReadASCIIZ(target, 256); err == nil && len(str) > 0 {
				return str
			}
		}
	}

	// Standard 8-byte ASCII name (null-terminated if < 8 bytes).
	idx := bytes.IndexByte(raw, 0)
	if idx >= 0 {
		return string(raw[:idx])
	}
	return string(raw)
}

// RVAToOffset converts a Relative Virtual Address (RVA) to a raw file offset.
func (f *File) RVAToOffset(rva uint32) (uint32, bool) {
	for _, s := range f.Sections {
		// Section virtual memory span.
		vSize := s.VirtualSize
		if vSize == 0 {
			vSize = s.SizeOfRawData
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+vSize {
			offset := rva - s.VirtualAddress + s.PointerToRawData
			return offset, true
		}
	}
	return 0, false
}

// OffsetToRVA converts a raw file offset to an RVA.
func (f *File) OffsetToRVA(offset uint32) (uint32, bool) {
	for _, s := range f.Sections {
		if offset >= s.PointerToRawData && offset < s.PointerToRawData+s.SizeOfRawData {
			rva := offset - s.PointerToRawData + s.VirtualAddress
			return rva, true
		}
	}
	return 0, false
}
