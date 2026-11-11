package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrNotPE indicates a missing DOS or PE signature.
	ErrNotPE = errors.New("not a valid PE binary")
	// ErrShortDOS indicates fewer than 64 bytes are available for the DOS header.
	ErrShortDOS = errors.New("file too short for DOS header")
	// ErrInvalidMagic indicates a missing PE signature at e_lfanew.
	ErrInvalidMagic = errors.New("invalid PE signature")
	// ErrInvalidHeader indicates an unsupported or inconsistent header layout.
	ErrInvalidHeader = errors.New("invalid PE header")
)

// DOSHeader represents the standard MS-DOS header at file offset 0.
type DOSHeader struct {
	Magic                 uint16
	Cblp                  uint16
	Cp                    uint16
	Crlc                  uint16
	Cparhdr               uint16
	Minalloc              uint16
	Maxalloc              uint16
	Ss                    uint16
	Sp                    uint16
	Csum                  uint16
	Ip                    uint16
	Cs                    uint16
	Lfarlc                uint16
	Ovno                  uint16
	Res                   [4]uint16
	Oemid                 uint16
	Oeminfo               uint16
	Res2                  [10]uint16
	AddressOfNewEXEHeader uint32 // e_lfanew
}

// FileHeader contains the COFF file header of a PE image.
type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// DataDirectory describes the location and size of a data directory.
type DataDirectory struct {
	// VirtualAddress contains an RVA, except in the certificate directory,
	// where it contains a file offset. Don't pass a certificate directory's
	// VirtualAddress to [File.RVAToOffset].
	VirtualAddress uint32
	Size           uint32
}

// OptionalHeader contains the optional header fields for a PE32 or PE32+ image.
// Fields that differ in width use types large enough for either format.
type OptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // PE32 only
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectories             [NumberOfDataDirectories]DataDirectory
}

func parseDOSHeader(r *SafeReader) (DOSHeader, error) {
	if r.Size() < 64 {
		return DOSHeader{}, ErrShortDOS
	}
	b, _ := r.Slice(0, 64) // Size was checked above.
	if binary.LittleEndian.Uint16(b) != DOSMagic {
		return DOSHeader{}, ErrNotPE
	}
	dos := DOSHeader{
		Magic:                 binary.LittleEndian.Uint16(b[0:2]),
		Cblp:                  binary.LittleEndian.Uint16(b[2:4]),
		Cp:                    binary.LittleEndian.Uint16(b[4:6]),
		Crlc:                  binary.LittleEndian.Uint16(b[6:8]),
		Cparhdr:               binary.LittleEndian.Uint16(b[8:10]),
		Minalloc:              binary.LittleEndian.Uint16(b[10:12]),
		Maxalloc:              binary.LittleEndian.Uint16(b[12:14]),
		Ss:                    binary.LittleEndian.Uint16(b[14:16]),
		Sp:                    binary.LittleEndian.Uint16(b[16:18]),
		Csum:                  binary.LittleEndian.Uint16(b[18:20]),
		Ip:                    binary.LittleEndian.Uint16(b[20:22]),
		Cs:                    binary.LittleEndian.Uint16(b[22:24]),
		Lfarlc:                binary.LittleEndian.Uint16(b[24:26]),
		Ovno:                  binary.LittleEndian.Uint16(b[26:28]),
		Oemid:                 binary.LittleEndian.Uint16(b[36:38]),
		Oeminfo:               binary.LittleEndian.Uint16(b[38:40]),
		AddressOfNewEXEHeader: binary.LittleEndian.Uint32(b[60:64]),
	}
	for i := range dos.Res {
		dos.Res[i] = binary.LittleEndian.Uint16(b[28+i*2:])
	}
	for i := range dos.Res2 {
		dos.Res2[i] = binary.LittleEndian.Uint16(b[40+i*2:])
	}
	return dos, nil
}

func parseFileHeader(r *SafeReader, offset int64) (FileHeader, error) {
	b, err := r.Slice(offset, 20)
	if err != nil {
		return FileHeader{}, fmt.Errorf("reading file header: %w", err)
	}
	return FileHeader{
		Machine:              binary.LittleEndian.Uint16(b[0:2]),
		NumberOfSections:     binary.LittleEndian.Uint16(b[2:4]),
		TimeDateStamp:        binary.LittleEndian.Uint32(b[4:8]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(b[8:12]),
		NumberOfSymbols:      binary.LittleEndian.Uint32(b[12:16]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(b[16:18]),
		Characteristics:      binary.LittleEndian.Uint16(b[18:20]),
	}, nil
}

func parseOptionalHeader(r *SafeReader, offset int64, size uint16) (OptionalHeader, error) {
	if size < 2 {
		return OptionalHeader{}, fmt.Errorf("%w: missing optional header", ErrInvalidHeader)
	}
	b, err := r.Slice(offset, int64(size))
	if err != nil {
		return OptionalHeader{}, err
	}

	var opt OptionalHeader
	opt.Magic = binary.LittleEndian.Uint16(b)
	var directoryOffset int

	switch opt.Magic {
	case OptionalHeaderMagicPE32:
		if size < 96 {
			return OptionalHeader{}, fmt.Errorf("%w: PE32 optional header too short", ErrInvalidHeader)
		}
		opt.BaseOfData = binary.LittleEndian.Uint32(b[24:28])
		opt.ImageBase = uint64(binary.LittleEndian.Uint32(b[28:32]))
		opt.SizeOfStackReserve = uint64(binary.LittleEndian.Uint32(b[72:76]))
		opt.SizeOfStackCommit = uint64(binary.LittleEndian.Uint32(b[76:80]))
		opt.SizeOfHeapReserve = uint64(binary.LittleEndian.Uint32(b[80:84]))
		opt.SizeOfHeapCommit = uint64(binary.LittleEndian.Uint32(b[84:88]))
		opt.LoaderFlags = binary.LittleEndian.Uint32(b[88:92])
		opt.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(b[92:96])

		directoryOffset = 96

	case OptionalHeaderMagicPE32P:
		if size < 112 {
			return OptionalHeader{}, fmt.Errorf("%w: PE32+ optional header too short", ErrInvalidHeader)
		}
		opt.ImageBase = binary.LittleEndian.Uint64(b[24:32])
		opt.SizeOfStackReserve = binary.LittleEndian.Uint64(b[72:80])
		opt.SizeOfStackCommit = binary.LittleEndian.Uint64(b[80:88])
		opt.SizeOfHeapReserve = binary.LittleEndian.Uint64(b[88:96])
		opt.SizeOfHeapCommit = binary.LittleEndian.Uint64(b[96:104])
		opt.LoaderFlags = binary.LittleEndian.Uint32(b[104:108])
		opt.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(b[108:112])

		directoryOffset = 112

	default:
		return OptionalHeader{}, fmt.Errorf("%w: unsupported optional header magic 0x%x", ErrInvalidHeader, opt.Magic)
	}

	opt.MajorLinkerVersion = b[2]
	opt.MinorLinkerVersion = b[3]
	opt.SizeOfCode = binary.LittleEndian.Uint32(b[4:8])
	opt.SizeOfInitializedData = binary.LittleEndian.Uint32(b[8:12])
	opt.SizeOfUninitializedData = binary.LittleEndian.Uint32(b[12:16])
	opt.AddressOfEntryPoint = binary.LittleEndian.Uint32(b[16:20])
	opt.BaseOfCode = binary.LittleEndian.Uint32(b[20:24])
	opt.SectionAlignment = binary.LittleEndian.Uint32(b[32:36])
	opt.FileAlignment = binary.LittleEndian.Uint32(b[36:40])
	opt.MajorOperatingSystemVersion = binary.LittleEndian.Uint16(b[40:42])
	opt.MinorOperatingSystemVersion = binary.LittleEndian.Uint16(b[42:44])
	opt.MajorImageVersion = binary.LittleEndian.Uint16(b[44:46])
	opt.MinorImageVersion = binary.LittleEndian.Uint16(b[46:48])
	opt.MajorSubsystemVersion = binary.LittleEndian.Uint16(b[48:50])
	opt.MinorSubsystemVersion = binary.LittleEndian.Uint16(b[50:52])
	opt.Win32VersionValue = binary.LittleEndian.Uint32(b[52:56])
	opt.SizeOfImage = binary.LittleEndian.Uint32(b[56:60])
	opt.SizeOfHeaders = binary.LittleEndian.Uint32(b[60:64])
	opt.CheckSum = binary.LittleEndian.Uint32(b[64:68])
	opt.Subsystem = binary.LittleEndian.Uint16(b[68:70])
	opt.DllCharacteristics = binary.LittleEndian.Uint16(b[70:72])
	if err := parseDataDirectories(b[directoryOffset:], &opt); err != nil {
		return OptionalHeader{}, err
	}

	return opt, nil
}

func parseDataDirectories(data []byte, opt *OptionalHeader) error {
	if uint64(opt.NumberOfRvaAndSizes) > uint64(len(data)/8) {
		return fmt.Errorf("%w: data directories exceed optional header", ErrInvalidHeader)
	}
	count := opt.NumberOfRvaAndSizes
	if count > NumberOfDataDirectories {
		count = NumberOfDataDirectories
	}
	for i := uint32(0); i < count; i++ {
		entry := data[i*8 : (i+1)*8]
		opt.DataDirectories[i] = DataDirectory{
			VirtualAddress: binary.LittleEndian.Uint32(entry[0:4]),
			Size:           binary.LittleEndian.Uint32(entry[4:8]),
		}
	}
	return nil
}
