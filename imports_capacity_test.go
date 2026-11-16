package pe

import (
	"bytes"
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
		for _, badIndex := range []int{16, 17, 255} {
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
			// Cover errors before lookahead, inside the reserved range, and at
			// its end. The bad name must precede the later invalid ordinal.
			putImportThunk(data[offset+badIndex*width:], is64, 0x7fffffff)
			putImportThunk(data[offset+(badIndex+1)*width:], is64, flag|1<<16)
			if got, err := f.Imports(data); got != nil || !errors.Is(err, ErrOutOfBounds) {
				t.Fatalf("PE64=%t: got %v, %v", is64, got, err)
			}
		}
	}
}

func TestCountImportThunksBounds(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, count := range []int{0, 1, 2, 238, 239, 240} {
			for _, limit := range []int{0, 1, 238, 239} {
				for _, tail := range []int{0, width - 1, width} {
					t.Run(fmt.Sprintf("Width%d/Count%d/Limit%d/Tail%d", width, count, limit, tail), func(t *testing.T) {
						table := make([]byte, count*width+tail)
						for i := range count {
							table[i*width] = 1
						}
						before := bytes.Clone(table)
						got, terminated := countImportThunks(table, width, limit)
						wantTerminated := count <= limit && tail == width
						if got != min(count, limit) || terminated != wantTerminated {
							t.Fatalf("countImportThunks = %d, %t; want %d, %t", got, terminated, min(count, limit), wantTerminated)
						}
						if !bytes.Equal(table, before) {
							t.Fatal("lookahead modified input")
						}
					})
				}
			}
		}
	}
}

func TestCountImportThunksPE64HighBits(t *testing.T) {
	// Include nonzero high words, ordinal zero, and runs of eight zero bytes
	// that straddle adjacent nonzero thunks. Only an aligned zero is a terminator.
	values := []uint64{1 << 8, 1 << 16, 1 << 32, 1 << 63, 0}
	table := make([]byte, len(values)*8)
	for i, v := range values {
		binary.LittleEndian.PutUint64(table[i*8:], v)
	}
	if count, ok := countImportThunks(table, 8, 4); count != 4 || !ok {
		t.Fatalf("countImportThunks = %d, %t; want 4, true", count, ok)
	}
}

func TestImportSymbolsLookaheadIndependentResults(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := buildImportsPE(is64, 2, 256)
		f, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		first, err := f.Imports(data)
		if err != nil {
			t.Fatal(err)
		}
		second, err := f.Imports(data)
		if err != nil {
			t.Fatal(err)
		}
		clear(data)
		first[0].Symbols[0].Name = "changed"
		first[0].Symbols = append(first[0].Symbols, ImportSymbol{Name: "appended"})
		if first[1].Symbols[0].Name != "Function0" || second[0].Symbols[0].Name != "Function0" || second[1].Symbols[0].Name != "Function0" {
			t.Fatal("libraries or calls share mutable results")
		}
		if second[0].Symbols[255].Name != "Function255" {
			t.Fatal("names retain input")
		}
	}
}

func TestImportSymbolsLookaheadMappingEnds(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		width, flag := 4, uint64(1)<<31
		if is64 {
			width, flag = 8, uint64(1)<<63
		}
		for _, tail := range []int{0, width - 1, width} {
			for _, bound := range []string{"section", "file", "input", "overlap"} {
				t.Run(fmt.Sprintf("PE64=%t/Tail%d/%s", is64, tail, bound), func(t *testing.T) {
					data := buildImportsPE(is64, 1, 17)
					rva := binary.LittleEndian.Uint32(data[512:])
					offset := importOffset(rva)
					for i := range 17 {
						putImportThunk(data[offset+i*width:], is64, flag|uint64(i))
					}
					// Keep the DLL readable when the mapped table is truncated.
					copy(data[480:], "lookahead.dll\x00")
					binary.LittleEndian.PutUint32(data[524:], 480)
					f, err := New(data)
					if err != nil {
						t.Fatal(err)
					}
					end := offset + 17*width + tail
					switch bound {
					case "section":
						f.Sections[0].SizeOfRawData = uint32(end - 512)
					case "file":
						f.fileSize = int64(end)
					case "input":
						data = data[:end]
					case "overlap":
						f.Sections = append([]Section{{SectionHeader: SectionHeader{VirtualAddress: rva + uint32(17*width+tail), VirtualSize: 1}}}, f.Sections...)
					}
					got, err := f.Imports(data)
					if tail == width {
						if err != nil || len(got) != 1 || len(got[0].Symbols) != 17 {
							t.Fatalf("complete terminator: %v, %v", got, err)
						}
					} else if got != nil || !errors.Is(err, ErrInvalidImport) {
						t.Fatalf("partial terminator: %v, %v", got, err)
					}
				})
			}
		}
	}
}
