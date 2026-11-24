package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Parser limits bounding base relocation decoding.
const (
	MaxBaseRelocBlocks  = 65536
	MaxBaseRelocEntries = 1 << 20
	MaxBaseRelocBytes   = 16 << 20
)

// Base relocation types (IMAGE_REL_BASED_*).
const (
	RelocBasedAbsolute uint16 = 0
	RelocBasedHigh     uint16 = 1
	RelocBasedLow      uint16 = 2
	RelocBasedHighLow  uint16 = 3
	RelocBasedHighAdj  uint16 = 4
	RelocBasedDir64    uint16 = 10
)

var (
	// ErrInvalidBaseReloc indicates malformed or misaligned base relocation metadata.
	ErrInvalidBaseReloc = errors.New("invalid base relocation metadata")
	// ErrBaseRelocLimit indicates that base relocation parsing exceeded a limit.
	ErrBaseRelocLimit = errors.New("base relocation parser limit exceeded")
)

// BaseRelocBlock summarizes one IMAGE_BASE_RELOCATION block.
type BaseRelocBlock struct {
	PageRVA     uint32
	BlockSize   uint32
	EntryCount  int
	ActiveCount int
}

// BaseRelocDirectory summarizes all base relocation blocks in a PE image.
type BaseRelocDirectory struct {
	Blocks        []BaseRelocBlock
	TotalEntries  int
	ActiveEntries int
}

// BaseRelocs reads the base relocation directory ([DataDirectoryBaseReloc],
// index 5) from data. A missing directory returns nil, nil.
func (f *File) BaseRelocs(data []byte) (*BaseRelocDirectory, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryBaseReloc, ErrInvalidBaseReloc)
	if err != nil || !ok {
		return nil, err
	}
	if dir.Size > MaxBaseRelocBytes {
		return nil, fmt.Errorf("%w: base reloc size %d exceeds %d", ErrBaseRelocLimit, dir.Size, MaxBaseRelocBytes)
	}

	span, err := f.rvaSpan(data, dir.VirtualAddress)
	if err != nil {
		return nil, fmt.Errorf("base relocation directory: %w", err)
	}
	if uint64(len(span)) < uint64(dir.Size) {
		return nil, fmt.Errorf("base relocation directory: %w", ErrOutOfBounds)
	}
	table := span[:dir.Size]

	var out BaseRelocDirectory
	pos := 0
	for pos < len(table) {
		if len(out.Blocks) >= MaxBaseRelocBlocks {
			return nil, ErrBaseRelocLimit
		}
		if len(table)-pos < 8 {
			return nil, fmt.Errorf("%w: truncated relocation block header at %#x", ErrInvalidBaseReloc, pos)
		}
		pageRVA := binary.LittleEndian.Uint32(table[pos : pos+4])
		blockSize := binary.LittleEndian.Uint32(table[pos+4 : pos+8])
		if blockSize < 8 || blockSize%2 != 0 {
			return nil, fmt.Errorf("%w: invalid relocation block size %d at %#x", ErrInvalidBaseReloc, blockSize, pos)
		}
		if uint64(pos)+uint64(blockSize) > uint64(len(table)) {
			return nil, fmt.Errorf("%w: relocation block at %#x exceeds directory", ErrInvalidBaseReloc, pos)
		}

		entryCount := int((blockSize - 8) / 2)
		if out.TotalEntries+entryCount > MaxBaseRelocEntries {
			return nil, ErrBaseRelocLimit
		}

		active := 0
		for i := range entryCount {
			raw := binary.LittleEndian.Uint16(table[pos+8+i*2 : pos+10+i*2])
			relType := raw >> 12
			if relType != RelocBasedAbsolute {
				active++
			}
		}

		out.Blocks = append(out.Blocks, BaseRelocBlock{
			PageRVA:     pageRVA,
			BlockSize:   blockSize,
			EntryCount:  entryCount,
			ActiveCount: active,
		})
		out.TotalEntries += entryCount
		out.ActiveEntries += active
		pos += int(blockSize)
	}

	return &out, nil
}
