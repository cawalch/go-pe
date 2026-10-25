package pe

import (
	"fmt"
	"os"
)

// File represents a parsed PE binary.
type File struct {
	DOSHeader      DOSHeader
	FileHeader     FileHeader
	OptionalHeader OptionalHeader
	Sections       []Section

	// Internal safe reader
	reader *SafeReader
}

// Open opens a named file and parses its PE headers and section table.
func Open(filename string) (*File, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return New(data)
}

// New parses a PE binary directly from an in-memory byte slice.
func New(data []byte) (*File, error) {
	r := NewSafeReader(data)

	// Step 1: Parse DOS Header
	dos, err := parseDOSHeader(r)
	if err != nil {
		return nil, err
	}

	// Step 2: Check PE Signature
	peOffset := int64(dos.AddressOfNewEXEHeader)
	sig, err := r.ReadUint32(peOffset)
	if err != nil || sig != PEMagic {
		return nil, ErrNotPE
	}

	// Step 3: Parse COFF File Header (20 bytes following PE\0\0)
	coffOffset := peOffset + 4
	coff, err := parseFileHeader(r, coffOffset)
	if err != nil {
		return nil, err
	}

	// Step 4: Parse Optional Header
	optOffset := coffOffset + 20
	opt, err := parseOptionalHeader(r, optOffset, coff.SizeOfOptionalHeader)
	if err != nil {
		return nil, err
	}

	// Step 5: Compute string table offset if COFF symbols are present
	var stringTableOffset uint32
	if coff.PointerToSymbolTable > 0 && coff.NumberOfSymbols > 0 {
		stringTableOffset = coff.PointerToSymbolTable + (coff.NumberOfSymbols * 18)
	}

	// Step 6: Parse Section Table
	sectionTableOffset := optOffset + int64(coff.SizeOfOptionalHeader)
	sections, err := parseSections(r, sectionTableOffset, coff.NumberOfSections, stringTableOffset)
	if err != nil {
		return nil, fmt.Errorf("parsing sections: %w", err)
	}

	return &File{
		DOSHeader:      dos,
		FileHeader:     coff,
		OptionalHeader: opt,
		Sections:       sections,
		reader:         r,
	}, nil
}

// IsDLL returns true if the Characteristics indicates a dynamic-link library.
func (f *File) IsDLL() bool {
	return f.FileHeader.Characteristics&CharacteristicsDLL != 0
}

// Is64Bit returns true if the binary targets 64-bit architecture (PE32+).
func (f *File) Is64Bit() bool {
	return f.OptionalHeader.Magic == OptionalHeaderMagicPE32P
}

// Is32Bit returns true if the binary targets 32-bit architecture (PE32).
func (f *File) Is32Bit() bool {
	return f.OptionalHeader.Magic == OptionalHeaderMagicPE32
}

// NumberOfSections returns the total count of parsed sections.
func (f *File) NumberOfSections() int {
	return len(f.Sections)
}

// SectionByName searches for the first section matching the given name.
func (f *File) SectionByName(name string) *Section {
	for i := range f.Sections {
		if f.Sections[i].Name == name {
			return &f.Sections[i]
		}
	}
	return nil
}
