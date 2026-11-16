package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func TestImportSymbolsLookaheadBounds(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		for _, count := range []int{0, 1, 16, 17, 22, 255, 256, 257} {
			t.Run(fmt.Sprintf("PE64=%t/Symbols%d", is64, count), func(t *testing.T) {
				data := buildImportsPE(is64, 1, count)
				f, err := New(data)
				if err != nil {
					t.Fatal(err)
				}
				rva := binary.LittleEndian.Uint32(data[512:])
				newParser := func(remaining int) importParser {
					return importParser{file: f, data: data, symbolCount: MaxImportSymbols - remaining,
						maxSymbols: MaxImportSymbols, maxName: MaxImportNameBytes, stringBytes: MaxImportStringBytes,
						invalidErr: ErrInvalidImport, limitErr: ErrImportLimit}
				}
				p := newParser(count)
				got, err := p.symbols(rva, rva, false, 0)
				if err != nil || len(got) != count || p.symbolCount != MaxImportSymbols {
					t.Fatalf("symbols = %d, %v; count=%d", len(got), err, p.symbolCount)
				}
				if count == 0 && got != nil {
					t.Fatal("empty table must return a nil symbol slice")
				}
				if count > 16 && count <= 256 && cap(got) > count {
					t.Fatal("lookahead allocated beyond the remaining symbol budget")
				}
				if count > 0 {
					p = newParser(count - 1)
					if partial, err := p.symbols(rva, rva, false, 0); partial != nil || !errors.Is(err, ErrImportLimit) {
						t.Fatalf("exhausted budget = %v, %v", partial, err)
					}
				}
				clear(data)
				for i, sym := range got {
					if sym.Name != fmt.Sprintf("Function%d", i) || sym.Hint != uint16(i) {
						t.Fatalf("symbol %d changed after clearing input: %+v", i, sym)
					}
				}
			})
		}
	}
}

func TestImportSymbolsLookaheadErrorOrder(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := buildImportsPE(is64, 1, 256)
		f, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		rva := binary.LittleEndian.Uint32(data[512:])
		offset := importOffset(rva)
		width, flag := 4, uint64(1)<<31
		if is64 {
			width, flag = 8, uint64(1)<<63
		}
		// The seventeenth entry triggers lookahead. Its bad name must still be
		// reported before the later invalid ordinal and the missing terminator.
		putImportThunk(data[offset+16*width:], is64, 0x7fffffff)
		putImportThunk(data[offset+17*width:], is64, flag|1<<16)
		putImportThunk(data[offset+256*width:], is64, flag)
		if got, err := f.Imports(data); got != nil || !errors.Is(err, ErrOutOfBounds) {
			t.Fatalf("PE64=%t: got %v, %v", is64, got, err)
		}
	}
}
