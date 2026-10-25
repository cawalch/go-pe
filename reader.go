package pe

import (
	"encoding/binary"
	"errors"
)

var (
	// ErrOutOfBounds indicates an attempt to read past the end of the buffer.
	ErrOutOfBounds = errors.New("read out of bounds")
	// ErrIntegerOverflow indicates an invalid offset or length causing arithmetic overflow.
	ErrIntegerOverflow = errors.New("integer overflow in offset arithmetic")
)

// SafeReader provides bounds-checked, zero-panic primitive reading operations
// over an in-memory byte slice or io.ReaderAt source.
type SafeReader struct {
	data []byte
	size int64
}

// NewSafeReader wraps a byte slice in a SafeReader.
func NewSafeReader(data []byte) *SafeReader {
	return &SafeReader{
		data: data,
		size: int64(len(data)),
	}
}

// Size returns the total byte size available.
func (r *SafeReader) Size() int64 {
	return r.size
}

// Slice returns a sub-slice at [offset : offset+length] with bounds and overflow checks.
func (r *SafeReader) Slice(offset int64, length int64) ([]byte, error) {
	if offset < 0 || length < 0 {
		return nil, ErrOutOfBounds
	}
	end := offset + length
	if end < offset || end > r.size {
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

// ReadASCIIZ reads a null-terminated ASCII string up to maxLen bytes.
func (r *SafeReader) ReadASCIIZ(offset int64, maxLen int64) (string, error) {
	if offset < 0 || offset >= r.size {
		return "", ErrOutOfBounds
	}
	available := r.size - offset
	if maxLen <= 0 || maxLen > available {
		maxLen = available
	}
	b := r.data[offset : offset+maxLen]
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), nil
		}
	}
	return string(b), nil
}

// CheckBounds verifies that [offset : offset+length] resides entirely within bounds.
func (r *SafeReader) CheckBounds(offset int64, length int64) bool {
	if offset < 0 || length < 0 {
		return false
	}
	end := offset + length
	return end >= offset && end <= r.size
}
