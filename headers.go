package pe

import (
	"errors"
	"fmt"
)

var (
	ErrNotPE        = errors.New("not a valid PE binary")
	ErrShortDOS     = errors.New("file too short for DOS header")
	ErrInvalidMagic = errors.New("invalid PE signature")
)

// DOSHeader represents the standard MS-DOS header at file offset 0.
type DOSHeader struct {
	Magic    uint16
	Cblp     uint16
	Cp       uint16
	Crlc     uint16
	Cparhdr  uint16
	Minalloc uint16
	Maxalloc uint16
	Ss       uint16
	Sp       uint16
	Csum     uint16
	Ip       uint16
	Cs       uint16
	Lfarlc   uint16
	Ovno     uint16
	Res      [4]uint16
	Oemid    uint16
	Oeminfo  uint16
	Res2     [10]uint16
	AddressOfNewEXEHeader uint32 // e_lfanew
}

// FileHeader represents the standard COFF File Header.
type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// DataDirectory represents an entry in the Optional Header data directory table.
type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// OptionalHeader represents the normalized PE Optional Header (handling both PE32 and PE32+).
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
	magic, err := r.ReadUint16(0)
	if err != nil || magic != DOSMagic {
		return DOSHeader{}, ErrNotPE
	}
	lfanew, err := r.ReadUint32(0x3c)
	if err != nil {
		return DOSHeader{}, err
	}
	return DOSHeader{
		Magic:                 magic,
		AddressOfNewEXEHeader: lfanew,
	}, nil
}

func parseFileHeader(r *SafeReader, offset int64) (FileHeader, error) {
	b, err := r.Slice(offset, 20)
	if err != nil {
		return FileHeader{}, fmt.Errorf("reading file header: %w", err)
	}
	return FileHeader{
		Machine:              binaryLEUint16(b[0:2]),
		NumberOfSections:     binaryLEUint16(b[2:4]),
		TimeDateStamp:        binaryLEUint32(b[4:8]),
		PointerToSymbolTable: binaryLEUint32(b[8:12]),
		NumberOfSymbols:      binaryLEUint32(b[12:16]),
		SizeOfOptionalHeader: binaryLEUint16(b[16:18]),
		Characteristics:      binaryLEUint16(b[18:20]),
	}, nil
}

func parseOptionalHeader(r *SafeReader, offset int64, size uint16) (OptionalHeader, error) {
	if size == 0 {
		return OptionalHeader{}, nil
	}
	if size < 2 {
		return OptionalHeader{}, errors.New("optional header too short")
	}
	magic, err := r.ReadUint16(offset)
	if err != nil {
		return OptionalHeader{}, err
	}

	var opt OptionalHeader
	opt.Magic = magic

	switch magic {
	case OptionalHeaderMagicPE32:
		if size < 96 {
			return OptionalHeader{}, errors.New("PE32 optional header truncated")
		}
		b, err := r.Slice(offset, int64(size))
		if err != nil {
			return OptionalHeader{}, err
		}
		opt.MajorLinkerVersion = b[2]
		opt.MinorLinkerVersion = b[3]
		opt.SizeOfCode = binaryLEUint32(b[4:8])
		opt.SizeOfInitializedData = binaryLEUint32(b[8:12])
		opt.SizeOfUninitializedData = binaryLEUint32(b[12:16])
		opt.AddressOfEntryPoint = binaryLEUint32(b[16:20])
		opt.BaseOfCode = binaryLEUint32(b[20:24])
		opt.BaseOfData = binaryLEUint32(b[24:28])
		opt.ImageBase = uint64(binaryLEUint32(b[28:32]))
		opt.SectionAlignment = binaryLEUint32(b[32:36])
		opt.FileAlignment = binaryLEUint32(b[36:40])
		opt.MajorOperatingSystemVersion = binaryLEUint16(b[40:42])
		opt.MinorOperatingSystemVersion = binaryLEUint16(b[42:44])
		opt.MajorImageVersion = binaryLEUint16(b[44:46])
		opt.MinorImageVersion = binaryLEUint16(b[46:48])
		opt.MajorSubsystemVersion = binaryLEUint16(b[48:50])
		opt.MinorSubsystemVersion = binaryLEUint16(b[50:52])
		opt.Win32VersionValue = binaryLEUint32(b[52:56])
		opt.SizeOfImage = binaryLEUint32(b[56:60])
		opt.SizeOfHeaders = binaryLEUint32(b[60:64])
		opt.CheckSum = binaryLEUint32(b[64:68])
		opt.Subsystem = binaryLEUint16(b[68:70])
		opt.DllCharacteristics = binaryLEUint16(b[70:72])
		opt.SizeOfStackReserve = uint64(binaryLEUint32(b[72:76]))
		opt.SizeOfStackCommit = uint64(binaryLEUint32(b[76:80]))
		opt.SizeOfHeapReserve = uint64(binaryLEUint32(b[80:84]))
		opt.SizeOfHeapCommit = uint64(binaryLEUint32(b[84:88]))
		opt.LoaderFlags = binaryLEUint32(b[88:92])
		opt.NumberOfRvaAndSizes = binaryLEUint32(b[92:96])

		// Data Directories start at offset 96.
		parseDataDirectories(b[96:], &opt)

	case OptionalHeaderMagicPE32P:
		if size < 112 {
			return OptionalHeader{}, errors.New("PE32+ optional header truncated")
		}
		b, err := r.Slice(offset, int64(size))
		if err != nil {
			return OptionalHeader{}, err
		}
		opt.MajorLinkerVersion = b[2]
		opt.MinorLinkerVersion = b[3]
		opt.SizeOfCode = binaryLEUint32(b[4:8])
		opt.SizeOfInitializedData = binaryLEUint32(b[8:12])
		opt.SizeOfUninitializedData = binaryLEUint32(b[12:16])
		opt.AddressOfEntryPoint = binaryLEUint32(b[16:20])
		opt.BaseOfCode = binaryLEUint32(b[20:24])
		opt.ImageBase = binaryLEUint64(b[24:32])
		opt.SectionAlignment = binaryLEUint32(b[32:36])
		opt.FileAlignment = binaryLEUint32(b[36:40])
		opt.MajorOperatingSystemVersion = binaryLEUint16(b[40:42])
		opt.MinorOperatingSystemVersion = binaryLEUint16(b[42:44])
		opt.MajorImageVersion = binaryLEUint16(b[44:46])
		opt.MinorImageVersion = binaryLEUint16(b[46:48])
		opt.MajorSubsystemVersion = binaryLEUint16(b[48:50])
		opt.MinorSubsystemVersion = binaryLEUint16(b[50:52])
		opt.Win32VersionValue = binaryLEUint32(b[52:56])
		opt.SizeOfImage = binaryLEUint32(b[56:60])
		opt.SizeOfHeaders = binaryLEUint32(b[60:64])
		opt.CheckSum = binaryLEUint32(b[64:68])
		opt.Subsystem = binaryLEUint16(b[68:70])
		opt.DllCharacteristics = binaryLEUint16(b[70:72])
		opt.SizeOfStackReserve = binaryLEUint64(b[72:80])
		opt.SizeOfStackCommit = binaryLEUint64(b[80:88])
		opt.SizeOfHeapReserve = binaryLEUint64(b[88:96])
		opt.SizeOfHeapCommit = binaryLEUint64(b[96:104])
		opt.LoaderFlags = binaryLEUint32(b[104:108])
		opt.NumberOfRvaAndSizes = binaryLEUint32(b[108:112])

		// Data Directories start at offset 112.
		parseDataDirectories(b[112:], &opt)

	default:
		return OptionalHeader{}, fmt.Errorf("unsupported optional header magic 0x%x", magic)
	}

	return opt, nil
}

func parseDataDirectories(data []byte, opt *OptionalHeader) {
	count := int(opt.NumberOfRvaAndSizes)
	if count > NumberOfDataDirectories {
		count = NumberOfDataDirectories
	}
	available := len(data) / 8
	if count > available {
		count = available
	}
	for i := 0; i < count; i++ {
		entry := data[i*8 : (i+1)*8]
		opt.DataDirectories[i] = DataDirectory{
			VirtualAddress: binaryLEUint32(entry[0:4]),
			Size:           binaryLEUint32(entry[4:8]),
		}
	}
}

func binaryLEUint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func binaryLEUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func binaryLEUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
