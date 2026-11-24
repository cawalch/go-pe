package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// MaxTLSCallbacks limits the number of TLS callback pointers read by [File.TLS].
const MaxTLSCallbacks = 1024

var (
	// ErrInvalidTLS indicates malformed or inconsistent TLS directory metadata.
	ErrInvalidTLS = errors.New("invalid TLS directory metadata")
	// ErrTLSLimit indicates that TLS callback parsing exceeded [MaxTLSCallbacks].
	ErrTLSLimit = errors.New("TLS directory parser limit exceeded")
)

// TLSDirectory describes the IMAGE_TLS_DIRECTORY32 or IMAGE_TLS_DIRECTORY64
// structure and its decoded callback virtual addresses.
type TLSDirectory struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
	Callbacks             []uint64
}

// TLS reads the Thread Local Storage directory ([DataDirectoryTLS], index 9)
// and its null-terminated AddressOfCallBacks pointer array from data.
//
// A missing directory returns nil, nil. Malformed, truncated, or over-limit
// metadata returns nil and an error.
func (f *File) TLS(data []byte) (*TLSDirectory, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryTLS, ErrInvalidTLS)
	if err != nil || !ok {
		return nil, err
	}

	is64 := f.Is64Bit()
	minSize := uint32(24)
	ptrSize := uint32(4)
	if is64 {
		minSize = 40
		ptrSize = 8
	}
	if dir.Size < minSize {
		return nil, fmt.Errorf("%w: TLS directory size %d smaller than %d", ErrInvalidTLS, dir.Size, minSize)
	}

	span, err := f.rvaSpan(data, dir.VirtualAddress)
	if err != nil {
		return nil, fmt.Errorf("TLS directory: %w", err)
	}
	if len(span) < int(minSize) {
		return nil, fmt.Errorf("TLS directory: %w", ErrOutOfBounds)
	}

	var out TLSDirectory
	if is64 {
		out.StartAddressOfRawData = binary.LittleEndian.Uint64(span[0:8])
		out.EndAddressOfRawData = binary.LittleEndian.Uint64(span[8:16])
		out.AddressOfIndex = binary.LittleEndian.Uint64(span[16:24])
		out.AddressOfCallBacks = binary.LittleEndian.Uint64(span[24:32])
		out.SizeOfZeroFill = binary.LittleEndian.Uint32(span[32:36])
		out.Characteristics = binary.LittleEndian.Uint32(span[36:40])
	} else {
		out.StartAddressOfRawData = uint64(binary.LittleEndian.Uint32(span[0:4]))
		out.EndAddressOfRawData = uint64(binary.LittleEndian.Uint32(span[4:8]))
		out.AddressOfIndex = uint64(binary.LittleEndian.Uint32(span[8:12]))
		out.AddressOfCallBacks = uint64(binary.LittleEndian.Uint32(span[12:16]))
		out.SizeOfZeroFill = binary.LittleEndian.Uint32(span[16:20])
		out.Characteristics = binary.LittleEndian.Uint32(span[20:24])
	}

	if out.AddressOfCallBacks == 0 {
		return &out, nil
	}

	cbTableRVA, err := vaToRVA(out.AddressOfCallBacks, f.OptionalHeader.ImageBase)
	if err != nil {
		return nil, fmt.Errorf("%w: AddressOfCallBacks %#x: %w", ErrInvalidTLS, out.AddressOfCallBacks, err)
	}

	cbSpan, err := f.rvaSpan(data, cbTableRVA)
	if err != nil {
		return nil, fmt.Errorf("TLS callback table: %w", err)
	}

	for pos := 0; ; pos += int(ptrSize) {
		if pos+int(ptrSize) > len(cbSpan) {
			return nil, fmt.Errorf("TLS callback table: %w", ErrOutOfBounds)
		}
		var va uint64
		if is64 {
			va = binary.LittleEndian.Uint64(cbSpan[pos : pos+8])
		} else {
			va = uint64(binary.LittleEndian.Uint32(cbSpan[pos : pos+4]))
		}
		if va == 0 {
			break
		}
		if len(out.Callbacks) >= MaxTLSCallbacks {
			return nil, ErrTLSLimit
		}
		if _, err := vaToRVA(va, f.OptionalHeader.ImageBase); err != nil {
			return nil, fmt.Errorf("%w: callback %d VA %#x: %w", ErrInvalidTLS, len(out.Callbacks), va, err)
		}
		out.Callbacks = append(out.Callbacks, va)
	}

	return &out, nil
}

func vaToRVA(va, imageBase uint64) (uint32, error) {
	if va < imageBase {
		return 0, fmt.Errorf("VA below ImageBase %#x", imageBase)
	}
	diff := va - imageBase
	if diff > math.MaxUint32 {
		return 0, ErrIntegerOverflow
	}
	return uint32(diff), nil
}
