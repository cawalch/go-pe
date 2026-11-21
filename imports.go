package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Parser limits bound work and output even when many entries refer to the same
// bytes. They are resource limits, not Windows loader requirements.
const (
	// MaxImportLibraries limits the number of import descriptors.
	MaxImportLibraries = 1024
	// MaxImportSymbols limits the total symbol count across all libraries.
	MaxImportSymbols = 65536
	// MaxImportNameBytes limits each name, including its NUL terminator.
	MaxImportNameBytes = 4096
	// MaxImportStringBytes limits total name bytes, including terminators.
	MaxImportStringBytes = 1 << 20
)

var (
	// ErrInvalidImport indicates inconsistent or unsupported import metadata.
	ErrInvalidImport = errors.New("invalid import metadata")
	// ErrImportLimit indicates that import parsing exceeded a resource limit.
	ErrImportLimit = errors.New("import parser limit exceeded")
)

// ImportLibrary describes one standard import descriptor. DLL and Symbols
// preserve their file order and spelling, including duplicate entries.
type ImportLibrary struct {
	DLL     string
	Symbols []ImportSymbol
}

// ImportSymbol identifies an import by name and hint, or by ordinal.
// When ByOrdinal is true, Name and Hint are empty and zero. Otherwise, Ordinal
// is zero. ByOrdinal distinguishes ordinal zero from a named import.
//
// When HasIATSlot is true, IATSlotRVA holds the RVA of the symbol's import
// address table (FirstThunk) slot, derived as FirstThunk + index*pointerWidth
// without dereferencing resolved IAT pointer values. When FirstThunk is zero
// or FirstThunk + index*pointerWidth overflows uint32, HasIATSlot is false and
// IATSlotRVA is zero; valid lookup-table imports still succeed.
type ImportSymbol struct {
	Name       string
	Hint       uint16
	Ordinal    uint16
	ByOrdinal  bool
	IATSlotRVA uint32
	HasIATSlot bool
}

// Imports reads the standard import directory from data using f's headers.
// Pass the original file bytes used by [New]. Don't modify data or f during
// the call. Results own their strings and slices; neither f nor the results
// retain data. Calls don't cache results or modify f.
//
// A missing directory returns nil, nil. Malformed, truncated, unsupported, or
// over-limit import data returns nil and an error, never partial results.
// Reads use [File.RVAToOffset]'s mapping policy and stay within the selected
// header or raw section range. Lookup tables and strings must fit in that range.
//
// Imports uses the lookup table when present. If its RVA is zero, it uses the
// import address table only when the descriptor's timestamp is zero (unbound).
// It doesn't decode bound addresses, delayed imports, or loaded-memory images.
func (f *File) Imports(data []byte) ([]ImportLibrary, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryImport, ErrInvalidImport)
	if err != nil || !ok {
		return nil, err
	}
	p := importParser{
		file:        f,
		data:        data,
		stringBytes: MaxImportStringBytes,
		maxName:     MaxImportNameBytes,
		maxSymbols:  MaxImportSymbols,
		invalidErr:  ErrInvalidImport,
		limitErr:    ErrImportLimit,
	}
	var libraries []ImportLibrary
	for pos := uint64(0); pos+20 <= uint64(dir.Size); pos += 20 {
		// The directory extent was checked before the loop, so this RVA fits.
		b, err := p.file.rvaSpan(p.data, dir.VirtualAddress+uint32(pos))
		if err != nil {
			return nil, fmt.Errorf("import descriptor %d: %w", len(libraries), err)
		}
		if len(b) < 20 {
			return nil, fmt.Errorf("import descriptor %d: %w", len(libraries), ErrOutOfBounds)
		}
		lookup := binary.LittleEndian.Uint32(b)
		timestamp := binary.LittleEndian.Uint32(b[4:])
		forwarder := binary.LittleEndian.Uint32(b[8:])
		name := binary.LittleEndian.Uint32(b[12:])
		address := binary.LittleEndian.Uint32(b[16:])
		if lookup|timestamp|forwarder|name|address == 0 {
			return libraries, nil
		}
		if len(libraries) == MaxImportLibraries {
			return nil, ErrImportLimit
		}
		if lookup == 0 {
			if timestamp != 0 {
				return nil, fmt.Errorf("%w: bound import has no lookup table", ErrInvalidImport)
			}
			lookup = address
		}
		if name == 0 || lookup == 0 {
			return nil, fmt.Errorf("%w: missing DLL name or lookup table", ErrInvalidImport)
		}
		b, err = p.file.rvaSpan(p.data, name)
		if err != nil {
			return nil, fmt.Errorf("import DLL name: %w", err)
		}
		dll, err := p.name(b)
		if err != nil {
			return nil, fmt.Errorf("import DLL name: %w", err)
		}
		symbols, err := p.symbols(lookup, address, false, 0)
		if err != nil {
			return nil, fmt.Errorf("imports from %q: %w", dll, err)
		}
		libraries = append(libraries, ImportLibrary{DLL: dll, Symbols: symbols})
	}
	return nil, fmt.Errorf("%w: missing directory terminator", ErrInvalidImport)
}

type importParser struct {
	file        *File
	data        []byte
	symbolCount int
	stringBytes int
	maxName     int
	maxSymbols  int
	invalidErr  error
	limitErr    error
}

func (p *importParser) name(data []byte) (string, error) {
	limit := min(p.maxName, p.stringBytes)
	if limit == 0 {
		return "", p.limitErr
	}
	name, err := NewSafeReader(data).ReadASCIIZ(0, int64(limit))
	if err != nil {
		if errors.Is(err, ErrUnterminatedString) && p.stringBytes < p.maxName && len(data) >= p.stringBytes {
			return "", p.limitErr
		}
		return "", err
	}
	if name == "" {
		return "", fmt.Errorf("%w: empty name", p.invalidErr)
	}
	p.stringBytes -= len(name) + 1
	return name, nil
}

func (p *importParser) symbols(rva, firstThunk uint32, subtractVA bool, vaBase uint64) ([]ImportSymbol, error) {
	table, err := p.file.rvaSpan(p.data, rva)
	if err != nil {
		return nil, err
	}
	width, ordinalFlag := 4, uint64(1)<<31
	if p.file.Is64Bit() {
		width, ordinalFlag = 8, uint64(1)<<63
	}
	var symbols []ImportSymbol
	for len(table) >= width {
		var value uint64
		if width == 8 {
			value = binary.LittleEndian.Uint64(table)
		} else {
			value = uint64(binary.LittleEndian.Uint32(table))
		}
		table = table[width:]
		if value == 0 {
			return symbols, nil
		}
		if p.symbolCount == p.maxSymbols {
			return nil, p.limitErr
		}
		var symbol ImportSymbol
		if firstThunk != 0 {
			slot := uint64(firstThunk) + uint64(len(symbols))*uint64(width)
			if slot <= math.MaxUint32 {
				symbol.IATSlotRVA, symbol.HasIATSlot = uint32(slot), true
			}
		}
		if value&ordinalFlag != 0 {
			if value & ^(ordinalFlag|0xffff) != 0 {
				return nil, fmt.Errorf("%w: reserved ordinal bits", p.invalidErr)
			}
			symbol.ByOrdinal, symbol.Ordinal = true, uint16(value)
		} else {
			if subtractVA {
				if value < vaBase {
					return nil, fmt.Errorf("%w: virtual address %#x below image base %#x", p.invalidErr, value, vaBase)
				}
				value -= vaBase
			}
			if value > math.MaxInt32 {
				return nil, fmt.Errorf("%w: reserved name RVA bits", p.invalidErr)
			}
			b, err := p.file.rvaSpan(p.data, uint32(value))
			if err != nil {
				return nil, err
			}
			if len(b) < 2 {
				return nil, ErrOutOfBounds
			}
			symbol.Hint = binary.LittleEndian.Uint16(b)
			symbol.Name, err = p.name(b[2:])
			if err != nil {
				return nil, err
			}
		}
		if len(symbols) == 16 {
			// Delay lookahead until this symbol is valid, so small tables and
			// early errors keep their allocation behavior. Bound the hint by
			// both the remaining symbol budget and 256 symbols per library.
			// Longer or unterminated tables keep the normal growth policy.
			limit := min(256-len(symbols)-1, p.maxSymbols-p.symbolCount-1)
			if count, terminated := countImportThunks(table, width, limit); terminated {
				grown := make([]ImportSymbol, len(symbols), len(symbols)+1+count)
				copy(grown, symbols)
				symbols = grown
			}
		}
		symbols = append(symbols, symbol)
		p.symbolCount++
	}
	return nil, fmt.Errorf("%w: missing lookup-table terminator", p.invalidErr)
}

// countImportThunks supplies a capacity hint, not validation. The main loop
// still checks each entry in order and owns all returned names and records.
func countImportThunks(table []byte, width, limit int) (int, bool) {
	// Include the slot after limit symbols so a terminator at the budget
	// boundary is accepted. Discard any trailing partial slot before scanning.
	slots := min(len(table)/width, limit+1)
	table = table[:slots*width]
	if width == 8 {
		for count := 0; len(table) >= 8; count++ {
			if binary.LittleEndian.Uint64(table) == 0 {
				return count, true
			}
			table = table[8:]
		}
	} else {
		for count := 0; len(table) >= 4; count++ {
			if binary.LittleEndian.Uint32(table) == 0 {
				return count, true
			}
			table = table[4:]
		}
	}
	return min(slots, limit), false
}
