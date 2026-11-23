package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MaxExceptionEntries limits the number of RUNTIME_FUNCTION entries decoded
// by [File.Exceptions].
const MaxExceptionEntries = 65536

const runtimeFunctionSize = 12

var (
	// ErrInvalidException indicates malformed or misaligned exception directory metadata.
	ErrInvalidException = errors.New("invalid exception directory metadata")
	// ErrExceptionLimit indicates that exception directory parsing exceeded [MaxExceptionEntries].
	ErrExceptionLimit = errors.New("exception directory parser limit exceeded")
)

// RuntimeFunction represents one 12-byte IMAGE_RUNTIME_FUNCTION_ENTRY record
// from the exception directory (.pdata).
type RuntimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

// Exceptions reads the exception directory ([DataDirectoryException], index 3)
// as 12-byte RUNTIME_FUNCTION entries.
//
// A missing directory returns nil, nil. Misaligned, truncated, or over-limit
// metadata returns nil and an error.
func (f *File) Exceptions(data []byte) ([]RuntimeFunction, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryException, ErrInvalidException)
	if err != nil || !ok {
		return nil, err
	}
	if dir.Size%runtimeFunctionSize != 0 {
		return nil, fmt.Errorf("%w: misaligned exception directory size %d", ErrInvalidException, dir.Size)
	}
	count := dir.Size / runtimeFunctionSize
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
		off := int(i) * runtimeFunctionSize
		entries[i] = RuntimeFunction{
			BeginAddress: binary.LittleEndian.Uint32(span[off : off+4]),
			EndAddress:   binary.LittleEndian.Uint32(span[off+4 : off+8]),
			UnwindData:   binary.LittleEndian.Uint32(span[off+8 : off+12]),
		}
	}
	return entries, nil
}

// MissingPE32PlusExceptionTable reports whether f is a PE32+ image lacking a
// declared [DataDirectoryException] (.pdata) table. Standard Windows/Go PE32+
// executables emit .pdata for stack unwinding; its absence is a common signal
// for packed, shellcode-wrapped, or hand-crafted PE32+ binaries.
func (f *File) MissingPE32PlusExceptionTable() bool {
	if !f.Is64Bit() {
		return false
	}
	if f.OptionalHeader.NumberOfRvaAndSizes <= DataDirectoryException {
		return true
	}
	dir := f.OptionalHeader.DataDirectories[DataDirectoryException]
	return dir.VirtualAddress == 0 || dir.Size == 0
}
