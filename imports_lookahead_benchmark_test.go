package pe

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func BenchmarkCountImportThunks(b *testing.B) {
	for _, width := range []int{4, 8} {
		for _, tc := range []struct {
			name        string
			count, tail int
			terminated  bool
		}{
			{"Empty", 0, width, true},
			{"TerminatorAtLimit", 239, width, true},
			{"NoTerminator", 240, 0, false},
			{"PartialTerminator", 239, width - 1, false},
		} {
			table := make([]byte, tc.count*width+tc.tail)
			for i := range tc.count {
				if width == 8 {
					binary.LittleEndian.PutUint64(table[i*width:], 1<<63|uint64(i))
				} else {
					binary.LittleEndian.PutUint32(table[i*width:], 1<<31|uint32(i))
				}
			}
			b.Run(fmt.Sprintf("Width%d/%s", width, tc.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					count, terminated := countImportThunks(table, width, 239)
					if count != min(tc.count, 239) || terminated != tc.terminated {
						b.Fatalf("countImportThunks = %d, %t", count, terminated)
					}
				}
			})
		}
	}
}
