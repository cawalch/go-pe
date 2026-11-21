package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Parser limits bounding [NewFromReaderAt] I/O operations and allocations.
// They are resource limits, not Windows loader requirements.
const (
	// MaxReaderAtHeaderBytes limits the combined optional header and section
	// table bytes read by [NewFromReaderAt].
	MaxReaderAtHeaderBytes = 1 << 20
	// MaxReaderAtReads limits total ReadAt calls per [NewFromReaderAt] call,
	// bounding short-read and sparse COFF string-table amplification.
	MaxReaderAtReads = 1024
	// MaxReaderAtBytes limits total bytes read per [NewFromReaderAt] call.
	MaxReaderAtBytes = 2 << 20
)

// ErrReaderAtLimit indicates that [NewFromReaderAt] exceeded a read-count or
// byte budget.
var ErrReaderAtLimit = errors.New("reader-at budget exceeded")

type readerAtBudget struct {
	r        io.ReaderAt
	size     int64
	maxReads int
	maxBytes int64
	reads    int
	bytes    int64
}

func (b *readerAtBudget) readExact(p []byte, off int64) error {
	if off < 0 || int64(len(p)) > b.size-off {
		return ErrOutOfBounds
	}
	done := 0
	for done < len(p) {
		b.reads++
		if b.reads > b.maxReads {
			return fmt.Errorf("%w: read count exceeds %d", ErrReaderAtLimit, b.maxReads)
		}
		n, err := b.r.ReadAt(p[done:], off+int64(done))
		if n < 0 || n > len(p)-done {
			return fmt.Errorf("%w: invalid ReadAt byte count %d", ErrInvalidHeader, n)
		}
		b.bytes += int64(n)
		if b.bytes > b.maxBytes {
			return fmt.Errorf("%w: read bytes exceed %d", ErrReaderAtLimit, b.maxBytes)
		}
		done += n
		if done == len(p) {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if n == 0 {
					return io.ErrUnexpectedEOF
				}
				continue
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// NewFromReaderAt parses PE32 or PE32+ headers and the declared section table
// from r with total byte length size, without reading the full file into memory.
//
// Like [New], the returned [File] owns its metadata and section names and
// retains no reference to r; callers may close r immediately after
// NewFromReaderAt returns. Reads are bounded by [MaxReaderAtReads],
// [MaxReaderAtBytes], and [MaxReaderAtHeaderBytes].
func NewFromReaderAt(r io.ReaderAt, size int64) (*File, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil ReaderAt", ErrInvalidHeader)
	}
	if size < dosHeaderSize {
		return nil, ErrShortDOS
	}

	b := readerAtBudget{
		r:        r,
		size:     size,
		maxReads: MaxReaderAtReads,
		maxBytes: MaxReaderAtBytes,
	}

	var dosBuf [dosHeaderSize]byte
	if err := b.readExact(dosBuf[:], 0); err != nil {
		return nil, err
	}
	dos, err := parseDOSHeader(NewSafeReader(dosBuf[:]))
	if err != nil {
		return nil, err
	}

	peOffset := int64(dos.AddressOfNewEXEHeader)
	if peOffset < dosHeaderSize {
		return nil, fmt.Errorf("%w: PE header overlaps DOS header", ErrInvalidHeader)
	}
	if peOffset > size-24 {
		return nil, ErrOutOfBounds
	}

	var ntHdr [24]byte
	if err := b.readExact(ntHdr[:], peOffset); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(ntHdr[0:4]) != PEMagic {
		return nil, fmt.Errorf("%w: %w", ErrNotPE, ErrInvalidMagic)
	}
	coff, err := parseFileHeader(NewSafeReader(ntHdr[4:24]), 0)
	if err != nil {
		return nil, err
	}
	if coff.NumberOfSections > MaxSections {
		return nil, fmt.Errorf("parsing sections: %w: %d", ErrSectionLimit, coff.NumberOfSections)
	}

	optAndSecLen := int64(coff.SizeOfOptionalHeader) + int64(coff.NumberOfSections)*40
	if optAndSecLen > MaxReaderAtHeaderBytes {
		return nil, fmt.Errorf("%w: header table size %d exceeds %d", ErrReaderAtLimit, optAndSecLen, MaxReaderAtHeaderBytes)
	}
	optOffset := peOffset + 24
	if optAndSecLen > size-optOffset {
		return nil, ErrOutOfBounds
	}

	buf := make([]byte, optAndSecLen)
	if err := b.readExact(buf, optOffset); err != nil {
		return nil, err
	}

	opt, err := parseOptionalHeader(NewSafeReader(buf), 0, coff.SizeOfOptionalHeader)
	if err != nil {
		return nil, err
	}

	var stringTableOffset int64
	if coff.PointerToSymbolTable > 0 {
		stringTableOffset = int64(coff.PointerToSymbolTable) + int64(coff.NumberOfSymbols)*18
	}

	secTable := buf[coff.SizeOfOptionalHeader:]
	sections, err := parseSectionsFromReaderAt(secTable, coff.NumberOfSections, stringTableOffset, &b)
	if err != nil {
		return nil, fmt.Errorf("parsing sections: %w", err)
	}

	return &File{
		DOSHeader:      dos,
		FileHeader:     coff,
		OptionalHeader: opt,
		Sections:       sections,
		fileSize:       size,
	}, nil
}

func parseSectionsFromReaderAt(table []byte, count uint16, stringTableOffset int64, b *readerAtBudget) ([]Section, error) {
	sections := make([]Section, count)
	var strTabSize uint32
	hasStrTabSize := false
	var strBuf [MaxSectionNameBytes]byte

	for i := range int(count) {
		raw := table[i*40 : (i+1)*40]
		var name string
		if raw[0] == '/' && stringTableOffset > 0 {
			if !hasStrTabSize {
				var szBuf [4]byte
				if err := b.readExact(szBuf[:], stringTableOffset); err != nil {
					return nil, fmt.Errorf("section %d name: %w", i, err)
				}
				strTabSize = binary.LittleEndian.Uint32(szBuf[:])
				if int64(strTabSize) > b.size-stringTableOffset {
					return nil, fmt.Errorf("section %d name: %w", i, ErrOutOfBounds)
				}
				hasStrTabSize = true
			}
			end := bytes.IndexByte(raw[1:8], 0)
			if end < 0 {
				end = 7
			}
			offset, err := strconv.ParseUint(string(raw[1:1+end]), 10, 32)
			if err != nil || offset < 4 {
				return nil, fmt.Errorf("section %d name: %w: invalid COFF string offset", i, ErrInvalidHeader)
			}
			if offset >= uint64(strTabSize) {
				return nil, fmt.Errorf("section %d name: %w: COFF string offset exceeds table", i, ErrInvalidHeader)
			}
			limit := min(int64(strTabSize)-int64(offset), MaxSectionNameBytes)
			if err := b.readExact(strBuf[:limit], stringTableOffset+int64(offset)); err != nil {
				return nil, fmt.Errorf("section %d name: %w", i, err)
			}
			nul := bytes.IndexByte(strBuf[:limit], 0)
			if nul < 0 {
				return nil, fmt.Errorf("section %d name: %w", i, ErrUnterminatedString)
			}
			name = string(strBuf[:nul])
		} else {
			idx := bytes.IndexByte(raw[:8], 0)
			if idx >= 0 {
				name = string(raw[:idx])
			} else {
				name = string(raw[:8])
			}
		}

		sections[i] = Section{
			Index: i,
			SectionHeader: SectionHeader{
				Name:                 name,
				VirtualSize:          binary.LittleEndian.Uint32(raw[8:12]),
				VirtualAddress:       binary.LittleEndian.Uint32(raw[12:16]),
				SizeOfRawData:        binary.LittleEndian.Uint32(raw[16:20]),
				PointerToRawData:     binary.LittleEndian.Uint32(raw[20:24]),
				PointerToRelocations: binary.LittleEndian.Uint32(raw[24:28]),
				PointerToLinenumbers: binary.LittleEndian.Uint32(raw[28:32]),
				NumberOfRelocations:  binary.LittleEndian.Uint16(raw[32:34]),
				NumberOfLinenumbers:  binary.LittleEndian.Uint16(raw[34:36]),
				Characteristics:      binary.LittleEndian.Uint32(raw[36:40]),
			},
		}
	}
	return sections, nil
}
