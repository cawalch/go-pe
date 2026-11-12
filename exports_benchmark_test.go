package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkExports(b *testing.B) {
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			count       int
			ordinalOnly bool
		}{{16, false}, {256, false}, {256, true}, {MaxExportSymbols, true}} {
			count := tc.count
			data := testfixture.Exports(is64, count)
			name := fmt.Sprintf("PE64=%t/Symbols%d", is64, count)
			if tc.ordinalOnly {
				binary.LittleEndian.PutUint32(data[536:], 0)
				name += "/OrdinalOnly"
			}
			f, err := New(data)
			if err != nil {
				b.Fatal(err)
			}
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := f.Exports(data)
					if err != nil || len(out.Symbols) != count {
						b.Fatalf("%v", err)
					}
				}
			})
		}
	}
	for _, bad := range []bool{false, true} {
		data := testfixture.Exports(true, 1)
		if bad {
			binary.LittleEndian.PutUint32(data[532:], MaxExportSymbols+1)
		} else {
			clear(data[0x108:0x110])
		}
		f, err := New(data)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("OverLimit=%t", bad), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				out, err := f.Exports(data)
				if out != nil || bad && !errors.Is(err, ErrExportLimit) || !bad && err != nil {
					b.Fatalf("%+v %v", out, err)
				}
			}
		})
	}
}
