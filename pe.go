package pe

import (
	"fmt"
	"os"
)

// File contains a snapshot of a PE image's headers and sections.
// If you don't modify its exported fields, you can read a File concurrently.
type File struct {
	DOSHeader      DOSHeader
	FileHeader     FileHeader
	OptionalHeader OptionalHeader
	Sections       []Section

	fileSize int64
}

// Open reads the entire named file into memory and parses its headers and
// section table. If you need to control input size or I/O, read the bytes
// in your application and pass them to [New].
func Open(filename string) (*File, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return New(data)
}

// New parses PE32 or PE32+ headers and the declared section table.
// It returns an error if the headers are incomplete or invalid. It doesn't
// validate the Windows loader's requirements or parse section bodies.
//
// New reads data synchronously. The returned [File] owns its metadata and section
// names and retains no reference to data. You can reuse or release data after
// New returns.
//
// If section bodies are truncated, you can still inspect their headers.
// Address translation returns offsets only for bytes within the original input.
func New(data []byte) (*File, error) {
	r := NewSafeReader(data)

	dos, err := parseDOSHeader(r)
	if err != nil {
		return nil, err
	}

	peOffset := int64(dos.AddressOfNewEXEHeader)
	if peOffset < 64 {
		return nil, fmt.Errorf("%w: PE header overlaps DOS header", ErrInvalidHeader)
	}
	sig, err := r.ReadUint32(peOffset)
	if err != nil {
		return nil, fmt.Errorf("reading PE signature: %w", err)
	}
	if sig != PEMagic {
		return nil, fmt.Errorf("%w: %w", ErrNotPE, ErrInvalidMagic)
	}

	// The 20-byte COFF file header follows the PE signature.
	coffOffset := peOffset + 4
	coff, err := parseFileHeader(r, coffOffset)
	if err != nil {
		return nil, err
	}

	optOffset := coffOffset + 20
	opt, err := parseOptionalHeader(r, optOffset, coff.SizeOfOptionalHeader)
	if err != nil {
		return nil, err
	}

	var stringTableOffset int64
	if coff.PointerToSymbolTable > 0 {
		// Widen before arithmetic; both COFF fields are untrusted uint32s.
		stringTableOffset = int64(coff.PointerToSymbolTable) + int64(coff.NumberOfSymbols)*18
	}

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
		fileSize:       int64(len(data)),
	}, nil
}

// IsDLL reports whether the COFF characteristics mark the image as a
// dynamic-link library (DLL).
func (f *File) IsDLL() bool {
	return f.FileHeader.Characteristics&CharacteristicsDLL != 0
}

// Is64Bit reports whether the file uses the PE32+ optional header format.
func (f *File) Is64Bit() bool {
	return f.OptionalHeader.Magic == OptionalHeaderMagicPE32P
}

// Is32Bit reports whether the file uses the PE32 optional header format.
func (f *File) Is32Bit() bool {
	return f.OptionalHeader.Magic == OptionalHeaderMagicPE32
}

// NumberOfSections returns the number of parsed sections.
func (f *File) NumberOfSections() int {
	return len(f.Sections)
}

// SectionByName returns a pointer into Sections for the first matching name,
// or nil. Modifying the returned section modifies the File.
func (f *File) SectionByName(name string) *Section {
	for i := range f.Sections {
		if f.Sections[i].Name == name {
			return &f.Sections[i]
		}
	}
	return nil
}
