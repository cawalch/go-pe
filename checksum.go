package pe

import (
	"encoding/binary"
	"fmt"
)

// MaxCheckSumBytes limits the maximum PE image size accepted by
// [File.ComputeCheckSum] and [File.VerifyCheckSum].
const MaxCheckSumBytes = MaxAuthenticodeDigestBytes

// ComputeCheckSum computes the standard 16-bit carry-folded PE header checksum
// (equivalent to Windows CheckSumMappedFile) over data, excluding the 4-byte
// OptionalHeader.CheckSum field.
//
// Pass the complete byte slice used with [New]. The returned value can be
// compared against OptionalHeader.CheckSum via [File.VerifyCheckSum].
func (f *File) ComputeCheckSum(data []byte) (uint32, error) {
	if f == nil || (!f.Is32Bit() && !f.Is64Bit()) {
		return 0, fmt.Errorf("%w: file headers not parsed", ErrInvalidHeader)
	}
	if f.fileSize < 0 || int64(len(data)) != f.fileSize {
		return 0, fmt.Errorf("%w: input size %d does not match parsed file size %d", ErrOutOfBounds, len(data), f.fileSize)
	}
	if len(data) > MaxCheckSumBytes {
		return 0, fmt.Errorf("%w: image size %d exceeds %d", ErrOutOfBounds, len(data), MaxCheckSumBytes)
	}

	checksumStart := int(f.DOSHeader.AddressOfNewEXEHeader) + 24 + 64
	checksumEnd := checksumStart + 4
	if checksumStart < 0 || checksumEnd > len(data) {
		return 0, fmt.Errorf("%w: OptionalHeader.CheckSum [%#x, %#x) exceeds input size %d", ErrOutOfBounds, checksumStart, checksumEnd, len(data))
	}

	sum := sumCheckSumWords(data, checksumStart, checksumEnd)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint32(sum) + uint32(len(data)), nil
}

// VerifyCheckSum reports whether [File.ComputeCheckSum](data) matches
// f.OptionalHeader.CheckSum. Note that Windows PE linkers often leave
// OptionalHeader.CheckSum as 0 for unsigned user-mode binaries; VerifyCheckSum
// checks exact equality against the header field.
func (f *File) VerifyCheckSum(data []byte) (bool, error) {
	got, err := f.ComputeCheckSum(data)
	if err != nil {
		return false, err
	}
	return got == f.OptionalHeader.CheckSum, nil
}

func sumCheckSumWords(data []byte, zeroStart, zeroEnd int) uint64 {
	var sum uint64
	overlapStart := zeroStart &^ 1
	overlapEnd := min(len(data), (zeroEnd+1)&^1)

	// Fast path before OptionalHeader.CheckSum.
	for i := 0; i < overlapStart; i += 2 {
		sum += uint64(binary.LittleEndian.Uint16(data[i:]))
	}

	// Masked words overlapping OptionalHeader.CheckSum.
	for i := overlapStart; i < overlapEnd; i += 2 {
		lo := data[i]
		if i >= zeroStart && i < zeroEnd {
			lo = 0
		}
		var hi byte
		if i+1 < len(data) {
			hi = data[i+1]
			if i+1 >= zeroStart && i+1 < zeroEnd {
				hi = 0
			}
		}
		sum += uint64(lo) | (uint64(hi) << 8)
	}

	// Fast path after OptionalHeader.CheckSum.
	i := overlapEnd
	for ; i+1 < len(data); i += 2 {
		sum += uint64(binary.LittleEndian.Uint16(data[i:]))
	}
	if i < len(data) {
		sum += uint64(data[i])
	}
	return sum
}
