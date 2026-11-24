package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MaxLoadConfigBytes limits the maximum IMAGE_LOAD_CONFIG_DIRECTORY size
// accepted by [File.LoadConfig].
const MaxLoadConfigBytes = 4096

var (
	// ErrInvalidLoadConfig indicates malformed or truncated LoadConfig metadata.
	ErrInvalidLoadConfig = errors.New("invalid load config metadata")
	// ErrLoadConfigLimit indicates that LoadConfig parsing exceeded [MaxLoadConfigBytes].
	ErrLoadConfigLimit = errors.New("load config parser limit exceeded")
)

// LoadConfigDirectory describes key fields from IMAGE_LOAD_CONFIG_DIRECTORY32
// or IMAGE_LOAD_CONFIG_DIRECTORY64, including SafeSEH, SecurityCookie, GuardCF,
// and CHPE/ARM64EC metadata.
type LoadConfigDirectory struct {
	Size                           uint32
	TimeDateStamp                  uint32
	MajorVersion                   uint16
	MinorVersion                   uint16
	GlobalFlagsClear               uint32
	GlobalFlagsSet                 uint32
	CriticalSectionDefaultTimeout  uint32
	SecurityCookie                 uint64
	SEHandlerTable                 uint64
	SEHandlerCount                 uint64
	GuardCFCheckFunctionPointer    uint64
	GuardCFDispatchFunctionPointer uint64
	GuardCFFunctionTable           uint64
	GuardCFFunctionCount           uint64
	GuardFlags                     uint32
	CHPEMetadataPointer            uint64
}

// HasGuardCF reports whether Control Flow Guard function table metadata is populated.
func (l *LoadConfigDirectory) HasGuardCF() bool {
	return l != nil && l.GuardCFFunctionTable != 0 && l.GuardCFFunctionCount > 0
}

// HasSafeSEH reports whether SafeSEH handler table metadata is populated (PE32).
func (l *LoadConfigDirectory) HasSafeSEH() bool {
	return l != nil && l.SEHandlerTable != 0 && l.SEHandlerCount > 0
}

// HasCHPE reports whether CHPE/ARM64EC hybrid metadata pointer is populated.
func (l *LoadConfigDirectory) HasCHPE() bool {
	return l != nil && l.CHPEMetadataPointer != 0
}

// LoadConfig reads the load configuration directory ([DataDirectoryLoadConfig],
// index 10) from data. A missing directory returns nil, nil.
func (f *File) LoadConfig(data []byte) (*LoadConfigDirectory, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryLoadConfig, ErrInvalidLoadConfig)
	if err != nil || !ok {
		return nil, err
	}
	if dir.Size < 64 {
		return nil, fmt.Errorf("%w: load config directory size %d smaller than 64", ErrInvalidLoadConfig, dir.Size)
	}
	if dir.Size > MaxLoadConfigBytes {
		return nil, fmt.Errorf("%w: load config directory size %d exceeds %d", ErrLoadConfigLimit, dir.Size, MaxLoadConfigBytes)
	}

	span, err := f.rvaSpan(data, dir.VirtualAddress)
	if err != nil {
		return nil, fmt.Errorf("load config directory: %w", err)
	}
	if uint64(len(span)) < uint64(dir.Size) {
		return nil, fmt.Errorf("load config directory: %w", ErrOutOfBounds)
	}

	declaredSize := binary.LittleEndian.Uint32(span[0:4])
	if declaredSize < 64 {
		return nil, fmt.Errorf("%w: declared Size %d smaller than 64", ErrInvalidLoadConfig, declaredSize)
	}
	if declaredSize > MaxLoadConfigBytes {
		return nil, fmt.Errorf("%w: declared Size %d exceeds %d", ErrLoadConfigLimit, declaredSize, MaxLoadConfigBytes)
	}
	if uint64(len(span)) < uint64(declaredSize) {
		return nil, fmt.Errorf("load config directory: %w", ErrOutOfBounds)
	}
	// MSVC often sets DataDirectory.Size to 0x40 (64) for legacy loader
	// compatibility while storing the full struct length in the leading Size field.
	b := span[:declaredSize]
	avail := len(b)

	out := &LoadConfigDirectory{
		Size:                          declaredSize,
		TimeDateStamp:                 binary.LittleEndian.Uint32(b[4:8]),
		MajorVersion:                  binary.LittleEndian.Uint16(b[8:10]),
		MinorVersion:                  binary.LittleEndian.Uint16(b[10:12]),
		GlobalFlagsClear:              binary.LittleEndian.Uint32(b[12:16]),
		GlobalFlagsSet:                binary.LittleEndian.Uint32(b[16:20]),
		CriticalSectionDefaultTimeout: binary.LittleEndian.Uint32(b[20:24]),
	}

	if f.Is64Bit() {
		if avail >= 96 {
			out.SecurityCookie = binary.LittleEndian.Uint64(b[88:96])
		}
		if avail >= 148 {
			out.GuardCFCheckFunctionPointer = binary.LittleEndian.Uint64(b[112:120])
			out.GuardCFDispatchFunctionPointer = binary.LittleEndian.Uint64(b[120:128])
			out.GuardCFFunctionTable = binary.LittleEndian.Uint64(b[128:136])
			out.GuardCFFunctionCount = binary.LittleEndian.Uint64(b[136:144])
			out.GuardFlags = binary.LittleEndian.Uint32(b[144:148])
		}
		if avail >= 208 {
			out.CHPEMetadataPointer = binary.LittleEndian.Uint64(b[200:208])
		}
	} else {
		if avail >= 64 {
			out.SecurityCookie = uint64(binary.LittleEndian.Uint32(b[60:64]))
		}
		if avail >= 72 {
			out.SEHandlerTable = uint64(binary.LittleEndian.Uint32(b[64:68]))
			out.SEHandlerCount = uint64(binary.LittleEndian.Uint32(b[68:72]))
		}
		if avail >= 92 {
			out.GuardCFCheckFunctionPointer = uint64(binary.LittleEndian.Uint32(b[72:76]))
			out.GuardCFDispatchFunctionPointer = uint64(binary.LittleEndian.Uint32(b[76:80]))
			out.GuardCFFunctionTable = uint64(binary.LittleEndian.Uint32(b[80:84]))
			out.GuardCFFunctionCount = uint64(binary.LittleEndian.Uint32(b[84:88]))
			out.GuardFlags = binary.LittleEndian.Uint32(b[88:92])
		}
		if avail >= 128 {
			out.CHPEMetadataPointer = uint64(binary.LittleEndian.Uint32(b[124:128]))
		}
	}

	return out, nil
}
