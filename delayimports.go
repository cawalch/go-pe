package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// DelayImportAttrRVA is the documented IMAGE_DELAYLOAD_DESCRIPTOR
// AllAttributes bit indicating that descriptor fields hold RVAs rather than
// legacy 32-bit virtual addresses.
const DelayImportAttrRVA uint32 = 1

// Parser limits bound delayed import descriptors, symbols, and strings.
// They are resource limits, not Windows loader requirements.
const (
	// MaxDelayImportLibraries limits the number of delayed import descriptors.
	MaxDelayImportLibraries = 1024
	// MaxDelayImportSymbols limits the total symbol count across all delayed
	// import libraries.
	MaxDelayImportSymbols = 65536
	// MaxDelayImportNameBytes limits each delayed DLL or symbol name, including
	// its NUL terminator.
	MaxDelayImportNameBytes = 4096
	// MaxDelayImportStringBytes limits total delayed name bytes, including
	// terminators and repeated references.
	MaxDelayImportStringBytes = 1 << 20
)

const delayImportDescriptorSize = 32

var (
	// ErrInvalidDelayImport indicates malformed, truncated, or unsupported
	// delayed import metadata.
	ErrInvalidDelayImport = errors.New("invalid delayed import metadata")
	// ErrDelayImportLimit indicates that delayed import parsing exceeded a
	// resource limit.
	ErrDelayImportLimit = errors.New("delayed import parser limit exceeded")
)

// DelayImportLibrary describes one IMAGE_DELAYLOAD_DESCRIPTOR record in file
// order, preserving spelling and duplicates.
//
// Attributes preserves the unmodified descriptor AllAttributes field. Address
// fields hold normalized RVAs: when Attributes has [DelayImportAttrRVA] set,
// values come directly from the descriptor; when Attributes is 0 on PE32 images,
// nonzero 32-bit virtual addresses have [OptionalHeader.ImageBase] subtracted.
// Symbols preserves descriptor order and derives each symbol's [ImportSymbol.IATSlotRVA]
// from ImportAddressTableRVA without dereferencing resolved pointers.
type DelayImportLibrary struct {
	Attributes                 uint32
	DLL                        string
	DLLNameRVA                 uint32
	ModuleHandleRVA            uint32
	ImportAddressTableRVA      uint32
	ImportNameTableRVA         uint32
	BoundImportAddressTableRVA uint32
	UnloadInformationTableRVA  uint32
	TimeDateStamp              uint32
	Symbols                    []ImportSymbol
}

// DelayImports reads the delayed import directory ([DataDirectoryDelayImport],
// directory index 13) from data using f's headers. Pass the original bytes used
// with [New]. Don't modify data or f during a call. Results own their strings
// and slices; neither f nor the results retain data. Calls don't cache results
// or modify f.
//
// A missing directory returns nil, nil. Malformed, truncated, unsupported, or
// over-limit delayed import metadata returns nil and an error, never partial
// results. Reads use [File.RVAToOffset]'s mapping policy and must fit within one
// selected header or raw section range and within data.
//
// Descriptors with unsupported AllAttributes bits (anything other than 0 or
// [DelayImportAttrRVA]) return [ErrInvalidDelayImport]. Legacy VA-based
// descriptors (AllAttributes == 0) are supported on PE32 images by subtracting
// [OptionalHeader.ImageBase] from nonzero descriptor addresses and non-ordinal
// thunk values, and rejected on PE32+ images with [ErrInvalidDelayImport].
//
// DelayImports uses ImportNameTableRVA when nonzero; if zero, it falls back to
// ImportAddressTableRVA only when TimeDateStamp is zero (unbound).
func (f *File) DelayImports(data []byte) ([]DelayImportLibrary, error) {
	if f == nil || (!f.Is32Bit() && !f.Is64Bit()) {
		return nil, ErrInvalidHeader
	}
	if f.OptionalHeader.NumberOfRvaAndSizes <= DataDirectoryDelayImport {
		return nil, nil
	}
	dir := f.OptionalHeader.DataDirectories[DataDirectoryDelayImport]
	if dir.VirtualAddress == 0 && dir.Size == 0 {
		return nil, nil
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil, fmt.Errorf("%w: incomplete directory descriptor", ErrInvalidDelayImport)
	}
	if uint64(dir.VirtualAddress)+uint64(dir.Size) > 1<<32 {
		return nil, ErrIntegerOverflow
	}
	if len(f.Sections) > MaxSections {
		return nil, ErrSectionLimit
	}

	p := importParser{
		file:        f,
		data:        data,
		stringBytes: MaxDelayImportStringBytes,
		maxName:     MaxDelayImportNameBytes,
		maxSymbols:  MaxDelayImportSymbols,
		invalidErr:  ErrInvalidDelayImport,
		limitErr:    ErrDelayImportLimit,
	}

	var libraries []DelayImportLibrary
	for pos := uint64(0); pos+delayImportDescriptorSize <= uint64(dir.Size); pos += delayImportDescriptorSize {
		b, err := f.rvaSpan(data, dir.VirtualAddress+uint32(pos))
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}
		if len(b) < delayImportDescriptorSize {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), ErrOutOfBounds)
		}
		attrs := binary.LittleEndian.Uint32(b[0:4])
		rawName := binary.LittleEndian.Uint32(b[4:8])
		rawModHandle := binary.LittleEndian.Uint32(b[8:12])
		rawIAT := binary.LittleEndian.Uint32(b[12:16])
		rawINT := binary.LittleEndian.Uint32(b[16:20])
		rawBoundIAT := binary.LittleEndian.Uint32(b[20:24])
		rawUnloadIAT := binary.LittleEndian.Uint32(b[24:28])
		timestamp := binary.LittleEndian.Uint32(b[28:32])

		if attrs|rawName|rawModHandle|rawIAT|rawINT|rawBoundIAT|rawUnloadIAT|timestamp == 0 {
			return libraries, nil
		}
		if len(libraries) == MaxDelayImportLibraries {
			return nil, ErrDelayImportLimit
		}
		if attrs&^DelayImportAttrRVA != 0 {
			return nil, fmt.Errorf("delay import descriptor %d: %w: unsupported attributes %#x", len(libraries), ErrInvalidDelayImport, attrs)
		}

		subtractVA := attrs&DelayImportAttrRVA == 0
		if subtractVA && f.Is64Bit() {
			return nil, fmt.Errorf("delay import descriptor %d: %w: VA-based descriptors unsupported on PE32+", len(libraries), ErrInvalidDelayImport)
		}
		imageBase := f.OptionalHeader.ImageBase
		if subtractVA && imageBase > math.MaxUint32 {
			return nil, fmt.Errorf("delay import descriptor %d: %w: invalid PE32 image base %#x", len(libraries), ErrInvalidDelayImport, imageBase)
		}

		nameRVA, err := resolveDelayAddr(rawName, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}
		modHandleRVA, err := resolveDelayAddr(rawModHandle, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}
		iatRVA, err := resolveDelayAddr(rawIAT, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}
		intRVA, err := resolveDelayAddr(rawINT, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}
		boundIATRVA, err := resolveDelayAddr(rawBoundIAT, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}
		unloadIATRVA, err := resolveDelayAddr(rawUnloadIAT, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay import descriptor %d: %w", len(libraries), err)
		}

		lookup := intRVA
		if lookup == 0 {
			if timestamp != 0 {
				return nil, fmt.Errorf("delay import descriptor %d: %w: bound import has no name table", len(libraries), ErrInvalidDelayImport)
			}
			lookup = iatRVA
		}
		if nameRVA == 0 || lookup == 0 {
			return nil, fmt.Errorf("delay import descriptor %d: %w: missing DLL name or lookup table", len(libraries), ErrInvalidDelayImport)
		}

		dllSpan, err := f.rvaSpan(data, nameRVA)
		if err != nil {
			return nil, fmt.Errorf("delay import DLL name: %w", err)
		}
		dll, err := p.name(dllSpan)
		if err != nil {
			return nil, fmt.Errorf("delay import DLL name: %w", err)
		}
		symbols, err := p.symbols(lookup, iatRVA, subtractVA, imageBase)
		if err != nil {
			return nil, fmt.Errorf("delay imports from %q: %w", dll, err)
		}
		libraries = append(libraries, DelayImportLibrary{
			Attributes:                 attrs,
			DLL:                        dll,
			DLLNameRVA:                 nameRVA,
			ModuleHandleRVA:            modHandleRVA,
			ImportAddressTableRVA:      iatRVA,
			ImportNameTableRVA:         intRVA,
			BoundImportAddressTableRVA: boundIATRVA,
			UnloadInformationTableRVA:  unloadIATRVA,
			TimeDateStamp:              timestamp,
			Symbols:                    symbols,
		})
	}
	return nil, fmt.Errorf("%w: missing directory terminator", ErrInvalidDelayImport)
}

func resolveDelayAddr(raw uint32, subtractVA bool, imageBase uint64) (uint32, error) {
	if !subtractVA || raw == 0 {
		return raw, nil
	}
	if uint64(raw) < imageBase {
		return 0, fmt.Errorf("%w: virtual address %#x below image base %#x", ErrInvalidDelayImport, raw, imageBase)
	}
	return uint32(uint64(raw) - imageBase), nil
}
