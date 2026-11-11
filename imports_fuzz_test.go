package pe

import (
	"encoding/binary"
	"testing"
)

func FuzzImports(f *testing.F) {
	for _, is64 := range []bool{false, true} {
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
			for _, symbol := range library.Symbols {
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
