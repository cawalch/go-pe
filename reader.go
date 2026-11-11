package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var (
	// ErrOutOfBounds indicates an attempt to read past the end of the buffer.
	ErrOutOfBounds = errors.New("read out of bounds")
	// ErrIntegerOverflow indicates an invalid offset or length causing arithmetic overflow.
	ErrIntegerOverflow = errors.New("integer overflow in offset arithmetic")
	// ErrUnterminatedString indicates no NUL within the bounded string read.
	ErrUnterminatedString = errors.New("unterminated string")
)

// SafeReader reads integers and strings from a byte slice with bounds checks.
// It retains a reference to the slice. The zero value reads an empty buffer.
type SafeReader struct {
	data []byte
	size int64
}

// NewSafeReader wraps data without copying it. Don't modify data concurrently
// with reads through the returned [SafeReader].
func NewSafeReader(data []byte) *SafeReader {
	return &SafeReader{
		data: data,
		size: int64(len(data)),
	}
}

// Size returns the input size in bytes.
func (r *SafeReader) Size() int64 {
	return r.size
}

// Slice returns the bytes in the range [offset, offset+length).
// It checks for invalid bounds and integer overflow. The returned slice shares
// its underlying array with the input.
func (r *SafeReader) Slice(offset int64, length int64) ([]byte, error) {
	if offset < 0 || length < 0 {
		return nil, ErrOutOfBounds
	}
	end := offset + length
	if end < offset {
		return nil, ErrIntegerOverflow
	}
	if end > r.size {
		return nil, ErrOutOfBounds
	}
	return r.data[offset:end], nil
}

// ReadUint8 reads a uint8 at the specified offset.
func (r *SafeReader) ReadUint8(offset int64) (uint8, error) {
	if offset < 0 || offset >= r.size {
		return 0, ErrOutOfBounds
	}
	return r.data[offset], nil
}

// ReadUint16 reads a little-endian uint16 at the specified offset.
func (r *SafeReader) ReadUint16(offset int64) (uint16, error) {
	b, err := r.Slice(offset, 2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

// ReadUint32 reads a little-endian uint32 at the specified offset.
func (r *SafeReader) ReadUint32(offset int64) (uint32, error) {
	b, err := r.Slice(offset, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// ReadUint64 reads a little-endian uint64 at the specified offset.
func (r *SafeReader) ReadUint64(offset int64) (uint64, error) {
	b, err := r.Slice(offset, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// ReadASCIIZ reads a NUL-terminated string starting at offset. It reads at most
// maxLen bytes, including the terminator, and returns a copy without the NUL.
// It preserves the input bytes without validating their encoding.
//
// If offset is outside the input or maxLen is nonpositive, ReadASCIIZ returns
// [ErrOutOfBounds]. If no NUL occurs within maxLen bytes and the input,
// it returns [ErrUnterminatedString].
func (r *SafeReader) ReadASCIIZ(offset int64, maxLen int64) (string, error) {
	if offset < 0 || offset >= r.size || maxLen <= 0 {
		return "", ErrOutOfBounds
	}
	available := r.size - offset
	if maxLen > available {
		maxLen = available
	}
	b := r.data[offset : offset+maxLen]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i]), nil
	}
	return "", ErrUnterminatedString
}

// CheckBounds reports whether the range [offset, offset+length) is within the input.
func (r *SafeReader) CheckBounds(offset int64, length int64) bool {
	if offset < 0 || length < 0 {
		return false
	}
	end := offset + length
	return end >= offset && end <= r.size
}
