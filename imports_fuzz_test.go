package pe

import (
	"encoding/binary"
	"testing"
)

func FuzzImports(f *testing.F) {
	for _, is64 := range []bool{false, true} {
		for _, count := range []int{16, 17, 18, 255, 256, 257} {
			seed := buildImportsPE(is64, 2, count)
			f.Add(is64, false, seed)
			f.Add(is64, true, seed[512:])
		}
		data := buildImportsPE(is64, 2, 3)
		f.Add(is64, false, data)
		f.Add(is64, true, data[512:])
		fallback := buildImportsPE(is64, 1, 2)
		binary.LittleEndian.PutUint32(fallback[512:], 0)
		f.Add(is64, false, fallback)
		ordinal := buildImportsPE(is64, 1, 1)
		flag, width := uint64(1)<<31, 4
		if is64 {
			flag, width = 1<<63, 8
		}
		putImportThunk(ordinal[importOffset(binary.LittleEndian.Uint32(ordinal[512:])):], is64, flag|123)
		f.Add(is64, true, ordinal[512:])
		f.Add(is64, false, buildImportsRVAEnd(is64, width))
		f.Add(is64, false, buildImportsRVAEnd(is64, width-1))
	}
	f.Add(false, false, []byte("MZ"))
	f.Add(false, false, buildImportsPE(false, 1, 1)[:531])
	f.Add(true, false, buildImportsPE(true, MaxImportLibraries, 0))
	f.Add(true, false, buildMinimalPE(1))
	f.Add(true, true, []byte{})
	f.Fuzz(func(t *testing.T, is64, payloadOnly bool, data []byte) {
		if payloadOnly {
			// Keep headers valid in this mode so mutations reach directory parsing.
			// The other mode also mutates headers, section mappings, and directory size.
			if uint64(len(data)) > 1<<32-1 {
				return
			}
			header := buildImportsPE(is64, 1, 1)[:512]
			section, directory := 392, 272
			if !is64 {
				section, directory = 376, 256
			}
			binary.LittleEndian.PutUint32(header[section+8:], uint32(len(data)))
			binary.LittleEndian.PutUint32(header[section+16:], uint32(len(data)))
			binary.LittleEndian.PutUint32(header[directory+4:], uint32(len(data)))
			data = append(header[:512:512], data...)
		}
		file, err := New(data)
		if err != nil {
			return
		}
		libraries, err := file.Imports(data)
		if err != nil {
			if libraries != nil {
				t.Fatal("partial imports returned with error")
			}
			return
		}
		if len(libraries) > MaxImportLibraries {
			t.Fatal("unbounded library count")
		}
		symbols, nameBytes := 0, 0
		checkName := func(name string) {
			if len(name) == 0 || len(name) >= MaxImportNameBytes {
				t.Fatal("invalid name length")
			}
			nameBytes += len(name) + 1
		}
		for _, library := range libraries {
			checkName(library.DLL)
			symbols += len(library.Symbols)
			for i, symbol := range library.Symbols {
				if !symbol.HasIATSlot && symbol.IATSlotRVA != 0 {
					t.Fatal("absent IAT slot has nonzero RVA")
				}
				if symbol.HasIATSlot && i > 0 && library.Symbols[i-1].HasIATSlot && symbol.IATSlotRVA <= library.Symbols[i-1].IATSlotRVA {
					t.Fatal("non-monotonic IAT slot RVA")
				}
				if symbol.ByOrdinal {
					if symbol.Name != "" || symbol.Hint != 0 {
						t.Fatal("ordinal import has name metadata")
					}
				} else {
					checkName(symbol.Name)
					if symbol.Ordinal != 0 {
						t.Fatal("named import has ordinal metadata")
					}
				}
			}
		}
		if symbols > MaxImportSymbols || nameBytes > MaxImportStringBytes {
			t.Fatal("unbounded import output")
		}
	})
}

func FuzzCountImportThunks(f *testing.F) {
	for _, is64 := range []bool{false, true} {
		width := 4
		if is64 {
			width = 8
		}
		for _, limit := range []uint8{0, 1, 238, 239} {
			f.Add(is64, limit, []byte{})
			f.Add(is64, limit, make([]byte, width-1))
			f.Add(is64, limit, make([]byte, width))
			data := make([]byte, 241*width)
			for i := range 240 {
				data[(i+1)*width-1] = 0x80
			}
			f.Add(is64, limit, data)
		}
	}
	f.Fuzz(func(t *testing.T, is64 bool, rawLimit uint8, data []byte) {
		width := 4
		if is64 {
			width = 8
		}
		limit := int(rawLimit) % 240
		want := min(len(data)/width, limit)
		wantTerminated := false
		// Use byte-wise checks as an independent oracle for aligned words.
		for i := 0; i <= want; i++ {
			if (i+1)*width > len(data) {
				break
			}
			zero := true
			for _, value := range data[i*width : (i+1)*width] {
				zero = zero && value == 0
			}
			if zero {
				want, wantTerminated = i, true
				break
			}
		}
		if got, terminated := countImportThunks(data, width, limit); got != want || terminated != wantTerminated {
			t.Fatalf("countImportThunks = %d, %t; want %d, %t", got, terminated, want, wantTerminated)
		}
	})
}
