package pe_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkImportSymbols(b *testing.B) {
	for _, delayed := range []bool{false, true} {
		for _, is64 := range []bool{false, true} {
			for _, tc := range []struct {
				name               string
				libraries, symbols int
				ordinal, bad       bool
			}{
				{"Empty", 1, 0, false, false},
				{"One", 1, 1, false, false},
				{"Small", 1, 16, false, false},
				{"Medium", 1, 256, false, false},
				{"BeyondHint", 1, 257, false, false},
				{"Large", 1, 4096, false, false},
				{"Ordinal", 1, 256, true, false},
				{"ManyDLLs", 128, 1, false, false},
				{"BadSecond", 1, 256, false, true},
			} {
				data := testfixture.Imports(is64, tc.libraries, tc.symbols)
				if delayed {
					data = testfixture.DelayImports(is64, tc.libraries, tc.symbols)
				}
				rva := binary.LittleEndian.Uint32(data[512:])
				if delayed {
					rva = binary.LittleEndian.Uint32(data[528:])
				}
				off := int(rva-0x1000) + 512
				width, flag := 4, uint64(1)<<31
				if is64 {
					width, flag = 8, uint64(1)<<63
				}
				if tc.ordinal {
					for i := range tc.symbols {
						testfixture.PutImportThunk(data[off+i*width:], is64, flag|uint64(i))
					}
				}
				if tc.bad {
					testfixture.PutImportThunk(data[off+width:], is64, flag|1<<16)
				}
				f, err := pe.New(data)
				if err != nil {
					b.Fatal(err)
				}
				b.Run(fmt.Sprintf("Delay=%t/PE64=%t/%s", delayed, is64, tc.name), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						var n int
						var err error
						if delayed {
							var libs []pe.DelayImportLibrary
							libs, err = f.DelayImports(data)
							if len(libs) > 0 {
								n = len(libs[0].Symbols)
							}
						} else {
							var libs []pe.ImportLibrary
							libs, err = f.Imports(data)
							if len(libs) > 0 {
								n = len(libs[0].Symbols)
							}
						}
						if tc.bad {
							if err == nil {
								b.Fatal("accepted invalid symbol")
							}
						} else if err != nil || n != tc.symbols {
							b.Fatalf("n=%d err=%v", n, err)
						}
					}
				})
			}
		}
	}
}
