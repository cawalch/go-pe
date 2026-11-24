package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MaxExceptionEntries limits the number of RUNTIME_FUNCTION entries decoded
// by [File.Exceptions].
const MaxExceptionEntries = 65536

const (
	runtimeFunctionSizeX64 = 12
	runtimeFunctionSizeARM = 8
)

var (
	// ErrInvalidException indicates malformed or misaligned exception directory metadata.
	ErrInvalidException = errors.New("invalid exception directory metadata")
	// ErrExceptionLimit indicates that exception directory parsing exceeded [MaxExceptionEntries].
	ErrExceptionLimit = errors.New("exception directory parser limit exceeded")
)

// RuntimeFunction represents one IMAGE_RUNTIME_FUNCTION_ENTRY record from the
// exception directory (.pdata). For ARM, ARM64, and ARM64EC images (8-byte
// entries), EndAddress is zero.
type RuntimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

// Exceptions reads the exception directory ([DataDirectoryException], index 3)
// as RUNTIME_FUNCTION entries (8-byte entries for ARM/ARM64/ARM64EC images,
// 12-byte entries for x64 and other architectures).
//
// A missing directory returns nil, nil. Misaligned, truncated, or over-limit
// metadata returns nil and an error.
func (f *File) Exceptions(data []byte) ([]RuntimeFunction, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryException, ErrInvalidException)
	if err != nil || !ok {
		return nil, err
	}
	entrySize := uint32(runtimeFunctionSizeX64)
	switch f.FileHeader.Machine {
	case MachineARMNT, MachineARM64, MachineARM64EC:
		entrySize = runtimeFunctionSizeARM
	}
	if dir.Size%entrySize != 0 {
		return nil, fmt.Errorf("%w: misaligned exception directory size %d", ErrInvalidException, dir.Size)
	}
	count := dir.Size / entrySize
	if count > MaxExceptionEntries {
		return nil, ErrExceptionLimit
	}
	span, err := f.rvaSpan(data, dir.VirtualAddress)
	if err != nil {
		return nil, fmt.Errorf("exception directory: %w", err)
	}
	if uint64(len(span)) < uint64(dir.Size) {
		return nil, fmt.Errorf("exception directory: %w", ErrOutOfBounds)
	}

	entries := make([]RuntimeFunction, count)
	for i := range count {
		off := int(i) * int(entrySize)
		if entrySize == runtimeFunctionSizeARM {
			entries[i] = RuntimeFunction{
				BeginAddress: binary.LittleEndian.Uint32(span[off : off+4]),
				UnwindData:   binary.LittleEndian.Uint32(span[off+4 : off+8]),
			}
		} else {
			entries[i] = RuntimeFunction{
				BeginAddress: binary.LittleEndian.Uint32(span[off : off+4]),
				EndAddress:   binary.LittleEndian.Uint32(span[off+4 : off+8]),
				UnwindData:   binary.LittleEndian.Uint32(span[off+8 : off+12]),
			}
		}
	}
	return entries, nil
}
