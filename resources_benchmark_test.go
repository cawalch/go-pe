package pe_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkResources(b *testing.B) {
	for _, is64 := range []bool{false, true} {
		for _, count := range []int{16, 256, 1024} {
			data := testfixture.ResourcesSimple(is64, count)
			f, err := pe.New(data)
			if err != nil {
				b.Fatal(err)
			}
			name := fmt.Sprintf("PE64=%t/Leaves%d", is64, count)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					dir, err := f.Resources(data)
					if err != nil || len(dir.Records) != count {
						b.Fatalf("Resources() = (%+v, %v)", dir, err)
					}
				}
			})
		}
	}

	for _, bad := range []bool{false, true} {
		data := testfixture.ResourcesSimple(true, 1)
		if bad {
			binary.LittleEndian.PutUint16(data[512+14:], pe.MaxResourceEntries+1)
		} else {
			dirOff := testfixture.ResourceDirOffset(true)
			clear(data[dirOff : dirOff+8])
		}
		f, err := pe.New(data)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("OverLimit=%t", bad), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				dir, err := f.Resources(data)
				if dir != nil || bad && !errors.Is(err, pe.ErrResourceLimit) || !bad && err != nil {
					b.Fatalf("%+v %v", dir, err)
				}
			}
		})
	}
}
