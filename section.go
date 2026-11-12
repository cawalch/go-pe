package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// MaxSections limits the number of sections the parser accepts.
// The limit bounds parsing work and allocations; it doesn't describe a Windows
// loader requirement.
const MaxSections = 256

// MaxSectionNameBytes limits COFF long-name reads, including the NUL terminator.
const MaxSectionNameBytes = 256

// ErrSectionLimit indicates that the declared section count exceeds [MaxSections].
var ErrSectionLimit = errors.New("section count exceeds parser limit")

// SectionHeader contains the fields of a 40-byte PE section header.
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

// Section contains a section header and its zero-based index in the section table.
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
	// A COFF long name starts with '/' and a decimal offset into the string table.
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

	// An ordinary name occupies eight bytes and may end with NUL padding.
	idx := bytes.IndexByte(raw, 0)
	if idx >= 0 {
		return string(raw[:idx]), nil
	}
	return string(raw), nil
}

// RVAToOffset converts a relative virtual address to a file offset.
// Header RVAs below SizeOfHeaders map directly. For other RVAs, it selects the
// first section in table order whose max(VirtualSize, SizeOfRawData) range
// contains the RVA.
//
// For a section RVA, the byte must be in the section's raw data and within
// the original input. Raw alignment padding can map to an offset.
// Virtual zero-fill, missing bytes, and overflow return false.
// This method doesn't emulate the Windows loader.
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

// OffsetToRVA converts a file offset to a relative virtual address.
// It checks the headers, then the first matching raw section. Offsets outside
// the original input or those ranges, and RVAs that overflow, return false.
// If sections overlap, this method might not invert [File.RVAToOffset].
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

// rvaSpan bounds a read by the original file, supplied data, RVA address space,
// and selected mapping. It also stops before an earlier section takes priority.
func (f *File) rvaSpan(data []byte, rva uint32) ([]byte, error) {
	offset, ok := f.RVAToOffset(rva)
	fileEnd := min(f.fileSize, int64(len(data)), 1<<32)
	if !ok || int64(offset) >= fileEnd {
		return nil, ErrOutOfBounds
	}
	limit := min(fileEnd-int64(offset), 1<<32-int64(rva))
	if rva < f.OptionalHeader.SizeOfHeaders {
		limit = min(limit, int64(f.OptionalHeader.SizeOfHeaders-rva))
	} else {
		for _, section := range f.Sections {
			va := section.VirtualAddress
			size := max(section.VirtualSize, section.SizeOfRawData)
			if size == 0 {
				continue
			}
			if rva < va {
				limit = min(limit, int64(va-rva))
				continue
			}
			delta := rva - va
			if delta < size {
				// RVAToOffset has already checked that delta is in raw data.
				limit = min(limit, int64(section.SizeOfRawData-delta))
				break
			}
		}
	}
	return NewSafeReader(data).Slice(int64(offset), limit)
}
