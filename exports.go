package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	// MaxExportSymbols limits export address table entries, including unused slots.
	MaxExportSymbols = 65536
	// MaxExportNames limits entries in the export name pointer and ordinal tables.
	MaxExportNames = 65536
	// MaxExportNameBytes limits each DLL name, symbol name, or forwarder, including its NUL.
	MaxExportNameBytes = 4096
	// MaxExportStringBytes limits total string bytes, including NULs and repeated references.
	MaxExportStringBytes = 1 << 20
)

var (
	// ErrInvalidExport indicates inconsistent export metadata.
	ErrInvalidExport = errors.New("invalid export metadata")
	// ErrExportLimit indicates that export parsing exceeded a resource limit.
	ErrExportLimit = errors.New("export parser limit exceeded")
)

// ExportDirectory contains export metadata and address table entries in file order.
// Symbols includes unused slots (RVA zero). Names preserve spelling, duplicates,
// and name pointer table order within each symbol. No names are synthesized.
type ExportDirectory struct {
	DLL             string
	Characteristics uint32
	TimeDateStamp   uint32
	MajorVersion    uint16
	MinorVersion    uint16
	OrdinalBase     uint32
	Symbols         []ExportSymbol
}

// ExportSymbol describes one export address table slot. Ordinal includes the
// directory's ordinal base. RVA is the unmodified table value; ordinary targets
// need not map to file bytes (for example, exported data in virtual zero-fill).
// A nil Names slice means ordinal-only; an empty string in Names is a named entry.
// When Forwarded is true, Forwarder contains the raw string at RVA, which can be
// empty. The parser doesn't validate its syntax or resolve another DLL.
type ExportSymbol struct {
	Ordinal   uint32
	RVA       uint32
	Names     []string
	Forwarder string
	Forwarded bool
}

// Exports reads the standard export directory from the original bytes passed
// to [New]. Don't modify data or f during a call. Results own their strings and
// slices. Calls don't retain data, modify f, or cache results.
//
// A missing directory returns nil, nil. Malformed, truncated, or over-limit
// metadata returns nil and an error, never partial results. Tables and strings
// must fit within their selected header or raw section range, the original file,
// and data. Forwarder strings must also terminate within the directory's RVA
// range. Other tables and names may lie outside that range.
func (f *File) Exports(data []byte) (*ExportDirectory, error) {
	if f == nil || (!f.Is32Bit() && !f.Is64Bit()) {
		return nil, ErrInvalidHeader
	}
	if f.OptionalHeader.NumberOfRvaAndSizes <= DataDirectoryExport {
		return nil, nil
	}
	dir := f.OptionalHeader.DataDirectories[DataDirectoryExport]
	if dir.VirtualAddress == 0 && dir.Size == 0 {
		return nil, nil
	}
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return nil, fmt.Errorf("%w: incomplete directory", ErrInvalidExport)
	}
	end := uint64(dir.VirtualAddress) + uint64(dir.Size)
	if end > 1<<32 {
		return nil, ErrIntegerOverflow
	}
	if len(f.Sections) > MaxSections {
		return nil, ErrSectionLimit
	}
	p := exportParser{file: f, data: data, stringBytes: MaxExportStringBytes}
	header, err := p.table(dir.VirtualAddress, 40)
	if err != nil {
		return nil, err
	}
	base := binary.LittleEndian.Uint32(header[16:])
	functions := binary.LittleEndian.Uint32(header[20:])
	names := binary.LittleEndian.Uint32(header[24:])
	if functions > MaxExportSymbols || names > MaxExportNames {
		return nil, ErrExportLimit
	}
	if functions != 0 && uint64(base)+uint64(functions)-1 > math.MaxUint32 {
		return nil, ErrIntegerOverflow
	}
	addresses, err := p.table(binary.LittleEndian.Uint32(header[28:]), uint64(functions)*4)
	if err != nil {
		return nil, err
	}
	pointers, err := p.table(binary.LittleEndian.Uint32(header[32:]), uint64(names)*4)
	if err != nil {
		return nil, err
	}
	ordinals, err := p.table(binary.LittleEndian.Uint32(header[36:]), uint64(names)*2)
	if err != nil {
		return nil, err
	}
	// Count aliases before allocating the output. Each index must address a slot.
	counts := make([]uint32, functions)
	for i := uint32(0); i < names; i++ {
		index := binary.LittleEndian.Uint16(ordinals[i*2:])
		if uint32(index) >= functions {
			return nil, fmt.Errorf("%w: name ordinal outside address table", ErrInvalidExport)
		}
		counts[index]++
	}
	result := &ExportDirectory{
		Characteristics: binary.LittleEndian.Uint32(header),
		TimeDateStamp:   binary.LittleEndian.Uint32(header[4:]),
		MajorVersion:    binary.LittleEndian.Uint16(header[8:]),
		MinorVersion:    binary.LittleEndian.Uint16(header[10:]),
		OrdinalBase:     base,
	}
	if rva := binary.LittleEndian.Uint32(header[12:]); rva != 0 {
		result.DLL, err = p.name(rva, 1<<32)
		if err != nil {
			return nil, err
		}
	}
	result.Symbols = make([]ExportSymbol, functions)
	// One backing array holds all aliases, avoiding a slice allocation per symbol.
	pool := make([]string, names)
	for i := range result.Symbols {
		symbol := &result.Symbols[i]
		symbol.Ordinal = base + uint32(i)
		symbol.RVA = binary.LittleEndian.Uint32(addresses[i*4:])
		if n := counts[i]; n != 0 {
			symbol.Names, pool = pool[:n:n], pool[n:]
			counts[i] = 0
		}
		if uint64(symbol.RVA) >= uint64(dir.VirtualAddress) && uint64(symbol.RVA) < end {
			symbol.Forwarded = true
			symbol.Forwarder, err = p.name(symbol.RVA, end)
			if err != nil {
				return nil, err
			}
		}
	}
	for i := uint32(0); i < names; i++ {
		index := binary.LittleEndian.Uint16(ordinals[i*2:])
		name, err := p.name(binary.LittleEndian.Uint32(pointers[i*4:]), 1<<32)
		if err != nil {
			return nil, err
		}
		result.Symbols[index].Names[counts[index]] = name
		counts[index]++
	}
	return result, nil
}

type exportParser struct {
	file        *File
	data        []byte
	stringBytes int
}

func (p *exportParser) table(rva uint32, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if rva == 0 {
		return nil, fmt.Errorf("%w: missing table RVA", ErrInvalidExport)
	}
	b, err := p.file.rvaSpan(p.data, rva)
	if err != nil {
		return nil, err
	}
	if size > uint64(len(b)) {
		return nil, ErrOutOfBounds
	}
	return b[:size], nil
}

func (p *exportParser) name(rva uint32, end uint64) (string, error) {
	if rva == 0 || uint64(rva) >= end {
		return "", fmt.Errorf("%w: invalid string RVA", ErrInvalidExport)
	}
	b, err := p.file.rvaSpan(p.data, rva)
	if err != nil {
		return "", err
	}
	b = b[:min(uint64(len(b)), end-uint64(rva))]
	limit := min(MaxExportNameBytes, p.stringBytes)
	if limit == 0 {
		return "", ErrExportLimit
	}
	name, err := NewSafeReader(b).ReadASCIIZ(0, int64(limit))
	if err != nil {
		if errors.Is(err, ErrUnterminatedString) && p.stringBytes < MaxExportNameBytes && len(b) >= p.stringBytes {
			return "", ErrExportLimit
		}
		return "", err
	}
	p.stringBytes -= len(name) + 1
	return name, nil
}
