package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Debug directory entry types defined by the Microsoft PE/COFF format
// (IMAGE_DEBUG_TYPE_*).
const (
	DebugTypeUnknown              uint32 = 0
	DebugTypeCOFF                 uint32 = 1
	DebugTypeCodeView             uint32 = 2
	DebugTypeFPO                  uint32 = 3
	DebugTypeMisc                 uint32 = 4
	DebugTypeException            uint32 = 5
	DebugTypeFixup                uint32 = 6
	DebugTypeOmapToSrc            uint32 = 7
	DebugTypeOmapFromSrc          uint32 = 8
	DebugTypeBorland              uint32 = 9
	DebugTypeReserved10           uint32 = 10
	DebugTypeCLSID                uint32 = 11
	DebugTypeVCFeature            uint32 = 12
	DebugTypePOGO                 uint32 = 13
	DebugTypeILTCG                uint32 = 14
	DebugTypeMPX                  uint32 = 15
	DebugTypeRepro                uint32 = 16
	DebugTypeSPGO                 uint32 = 18
	DebugTypeExDLLCharacteristics uint32 = 20
)

// CodeView record signatures decoded by [File.Debug].
const (
	// CodeViewSignatureRSDS identifies a PDB 7.0 CodeView record ("RSDS").
	CodeViewSignatureRSDS uint32 = 0x53445352
	// CodeViewSignatureNB10 identifies a PDB 2.0 CodeView record ("NB10").
	CodeViewSignatureNB10 uint32 = 0x3031424e
)

// Parser limits bound debug directory entry counts and CodeView payload reads.
// They are resource limits, not Windows loader requirements.
const (
	// MaxDebugEntries limits the number of IMAGE_DEBUG_DIRECTORY descriptors.
	MaxDebugEntries = 256
	// MaxDebugPayloadBytes limits any single decoded CodeView payload.
	MaxDebugPayloadBytes = 64 << 10
	// MaxCodeViewPathBytes limits each CodeView PDB path byte length,
	// including its NUL terminator when present.
	MaxCodeViewPathBytes = 4096
	// MaxDebugTotalBytes limits cumulative CodeView payload bytes read across
	// all entries in a single [File.Debug] call.
	MaxDebugTotalBytes = 1 << 20
)

const (
	debugDirectoryEntrySize = 28
	codeViewRSDSHeaderSize  = 24
	codeViewNB10HeaderSize  = 16
)

var (
	// ErrInvalidDebug indicates malformed, truncated, misaligned, or
	// conflicting debug directory or CodeView metadata.
	ErrInvalidDebug = errors.New("invalid debug directory metadata")
	// ErrDebugLimit indicates that debug directory parsing exceeded a resource
	// limit.
	ErrDebugLimit = errors.New("debug directory parser limit exceeded")
)

// CodeViewGUID holds the 16-byte Microsoft mixed-endian GUID from an RSDS
// CodeView record.
type CodeViewGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// String formats g in canonical lowercase hyphenated form
// (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
func (g CodeViewGUID) String() string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
	)
}

// Bytes encodes g in Microsoft mixed-endian wire byte order.
func (g CodeViewGUID) Bytes() [16]byte {
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], g.Data1)
	binary.LittleEndian.PutUint16(out[4:6], g.Data2)
	binary.LittleEndian.PutUint16(out[6:8], g.Data3)
	copy(out[8:16], g.Data4[:])
	return out
}

// CodeViewRecord describes a decoded RSDS ([CodeViewSignatureRSDS]) or NB10
// ([CodeViewSignatureNB10]) record stored in a [DebugTypeCodeView] debug entry.
//
// For RSDS records, GUID and Age hold the PDB 7.0 identifier and age while
// NB10Offset and NB10Signature are zero. For NB10 records, NB10Offset,
// NB10Signature, and Age hold the PDB 2.0 header fields while GUID is zero.
//
// PDBPath holds an owned copy of the raw path bytes before the NUL terminator,
// preserving non-UTF-8 bytes verbatim. A nil slice means no trailing path bytes
// were present after the fixed header; a non-nil empty slice means an explicit
// empty NUL-terminated string.
type CodeViewRecord struct {
	Signature     uint32
	GUID          CodeViewGUID
	NB10Offset    uint32
	NB10Signature uint32
	Age           uint32
	PDBPath       []byte
}

// DebugEntry describes one IMAGE_DEBUG_DIRECTORY record in file table order.
// Scalar fields preserve unmodified directory values. Non-CodeView debug types
// and unrecognized CodeView signatures are retained as metadata with CodeView
// set to nil.
type DebugEntry struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
	CodeView         *CodeViewRecord
}

// Debug reads the standard debug directory from the original bytes passed to
// [New]. Don't modify data or f during a call. Results own all returned slices;
// calls don't retain data, modify f, or cache results.
//
// A missing directory returns nil, nil. Malformed, truncated, conflicting, or
// over-limit metadata returns nil and an error, never partial results.
//
// The debug directory table is mapped by RVA using [File.RVAToOffset] and must
// fit as a contiguous 28-byte-aligned block within one header or raw section
// range and within data.
//
// For [DebugTypeCodeView] entries, PointerToRawData takes file-offset
// precedence:
//   - If PointerToRawData != 0 and AddressOfRawData == 0, the payload is read
//     directly from file offset PointerToRawData within data and [File.FileSize]
//     (allowing overlay debug data outside mapped sections).
//   - If PointerToRawData != 0 and AddressOfRawData != 0, [File.RVAToOffset]
//     must map AddressOfRawData to PointerToRawData, and the payload must fit
//     within both the file bounds and the mapped RVA span; mismatches return
//     [ErrInvalidDebug].
//   - If PointerToRawData == 0 and AddressOfRawData != 0, the payload is read
//     from the mapped RVA span.
//   - If both pointers are zero, [ErrInvalidDebug] is returned.
//
// Entries with other [DebugEntry.Type] values retain their directory metadata
// without decoding payloads. Unknown CodeView signatures in [DebugTypeCodeView]
// entries still validate pointer/size bounds and leave CodeView nil.
func (f *File) Debug(data []byte) ([]DebugEntry, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryDebug, ErrInvalidDebug)
	if err != nil || !ok {
		return nil, err
	}
	if dir.Size%debugDirectoryEntrySize != 0 {
		return nil, fmt.Errorf("%w: misaligned directory size %d", ErrInvalidDebug, dir.Size)
	}
	count := dir.Size / debugDirectoryEntrySize
	if count > MaxDebugEntries {
		return nil, ErrDebugLimit
	}

	span, err := f.rvaSpan(data, dir.VirtualAddress)
	if err != nil {
		return nil, fmt.Errorf("debug directory table: %w", err)
	}
	if uint64(len(span)) < uint64(dir.Size) {
		return nil, fmt.Errorf("debug directory table: %w", ErrOutOfBounds)
	}
	table := span[:dir.Size]

	entries := make([]DebugEntry, count)
	remainingPayload := MaxDebugTotalBytes
	for i := range count {
		raw := table[i*debugDirectoryEntrySize : (i+1)*debugDirectoryEntrySize]
		entry := DebugEntry{
			Characteristics:  binary.LittleEndian.Uint32(raw[0:4]),
			TimeDateStamp:    binary.LittleEndian.Uint32(raw[4:8]),
			MajorVersion:     binary.LittleEndian.Uint16(raw[8:10]),
			MinorVersion:     binary.LittleEndian.Uint16(raw[10:12]),
			Type:             binary.LittleEndian.Uint32(raw[12:16]),
			SizeOfData:       binary.LittleEndian.Uint32(raw[16:20]),
			AddressOfRawData: binary.LittleEndian.Uint32(raw[20:24]),
			PointerToRawData: binary.LittleEndian.Uint32(raw[24:28]),
		}
		if entry.Type == DebugTypeCodeView {
			if entry.SizeOfData < 4 {
				return nil, fmt.Errorf("debug entry %d: %w: truncated CodeView payload", i, ErrInvalidDebug)
			}
			if entry.SizeOfData > MaxDebugPayloadBytes {
				return nil, fmt.Errorf("debug entry %d: %w", i, ErrDebugLimit)
			}
			if int(entry.SizeOfData) > remainingPayload {
				return nil, fmt.Errorf("debug entry %d: %w", i, ErrDebugLimit)
			}
			remainingPayload -= int(entry.SizeOfData)

			payload, err := f.debugCodeViewPayload(data, i, entry)
			if err != nil {
				return nil, err
			}
			cv, err := decodeCodeView(payload, i)
			if err != nil {
				return nil, err
			}
			entry.CodeView = cv
		}
		entries[i] = entry
	}
	return entries, nil
}

func (f *File) debugCodeViewPayload(data []byte, index uint32, entry DebugEntry) ([]byte, error) {
	if entry.PointerToRawData == 0 && entry.AddressOfRawData == 0 {
		return nil, fmt.Errorf("debug entry %d: %w: missing CodeView payload location", index, ErrInvalidDebug)
	}
	if entry.AddressOfRawData != 0 {
		if uint64(entry.AddressOfRawData)+uint64(entry.SizeOfData) > 1<<32 {
			return nil, fmt.Errorf("debug entry %d: %w", index, ErrIntegerOverflow)
		}
	}

	if entry.PointerToRawData != 0 {
		if entry.AddressOfRawData != 0 {
			mappedOff, ok := f.RVAToOffset(entry.AddressOfRawData)
			if !ok || mappedOff != entry.PointerToRawData {
				return nil, fmt.Errorf(
					"debug entry %d: %w: conflicting file offset %#x and RVA %#x",
					index, ErrInvalidDebug, entry.PointerToRawData, entry.AddressOfRawData,
				)
			}
			span, err := f.rvaSpan(data, entry.AddressOfRawData)
			if err != nil {
				return nil, fmt.Errorf("debug entry %d: %w", index, err)
			}
			if uint64(len(span)) < uint64(entry.SizeOfData) {
				return nil, fmt.Errorf("debug entry %d: %w", index, ErrOutOfBounds)
			}
			return span[:entry.SizeOfData], nil
		}

		fileEnd := min(f.fileSize, int64(len(data)))
		if int64(entry.PointerToRawData) > math.MaxInt64-int64(entry.SizeOfData) {
			return nil, fmt.Errorf("debug entry %d: %w", index, ErrIntegerOverflow)
		}
		end := int64(entry.PointerToRawData) + int64(entry.SizeOfData)
		if end > fileEnd {
			return nil, fmt.Errorf("debug entry %d: %w", index, ErrOutOfBounds)
		}
		return data[entry.PointerToRawData:end], nil
	}

	span, err := f.rvaSpan(data, entry.AddressOfRawData)
	if err != nil {
		return nil, fmt.Errorf("debug entry %d: %w", index, err)
	}
	if uint64(len(span)) < uint64(entry.SizeOfData) {
		return nil, fmt.Errorf("debug entry %d: %w", index, ErrOutOfBounds)
	}
	return span[:entry.SizeOfData], nil
}

func decodeCodeView(payload []byte, index uint32) (*CodeViewRecord, error) {
	sig := binary.LittleEndian.Uint32(payload[:4])
	switch sig {
	case CodeViewSignatureRSDS:
		if len(payload) < codeViewRSDSHeaderSize {
			return nil, fmt.Errorf("debug entry %d: %w: truncated RSDS header", index, ErrInvalidDebug)
		}
		guid := CodeViewGUID{
			Data1: binary.LittleEndian.Uint32(payload[4:8]),
			Data2: binary.LittleEndian.Uint16(payload[8:10]),
			Data3: binary.LittleEndian.Uint16(payload[10:12]),
		}
		copy(guid.Data4[:], payload[12:20])
		pdbPath, err := extractCodeViewPath(payload[codeViewRSDSHeaderSize:])
		if err != nil {
			return nil, fmt.Errorf("debug entry %d: %w", index, err)
		}
		return &CodeViewRecord{
			Signature: sig,
			GUID:      guid,
			Age:       binary.LittleEndian.Uint32(payload[20:24]),
			PDBPath:   pdbPath,
		}, nil

	case CodeViewSignatureNB10:
		if len(payload) < codeViewNB10HeaderSize {
			return nil, fmt.Errorf("debug entry %d: %w: truncated NB10 header", index, ErrInvalidDebug)
		}
		pdbPath, err := extractCodeViewPath(payload[codeViewNB10HeaderSize:])
		if err != nil {
			return nil, fmt.Errorf("debug entry %d: %w", index, err)
		}
		return &CodeViewRecord{
			Signature:     sig,
			NB10Offset:    binary.LittleEndian.Uint32(payload[4:8]),
			NB10Signature: binary.LittleEndian.Uint32(payload[8:12]),
			Age:           binary.LittleEndian.Uint32(payload[12:16]),
			PDBPath:       pdbPath,
		}, nil

	default:
		return nil, nil
	}
}

func extractCodeViewPath(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	scanLimit := min(len(raw), MaxCodeViewPathBytes)
	nul := bytes.IndexByte(raw[:scanLimit], 0)
	if nul < 0 {
		if len(raw) > MaxCodeViewPathBytes {
			return nil, ErrDebugLimit
		}
		return nil, fmt.Errorf("%w: unterminated CodeView path", ErrUnterminatedString)
	}
	if nul == 0 {
		return []byte{}, nil
	}
	return bytes.Clone(raw[:nul]), nil
}
