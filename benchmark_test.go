package pe

import (
	"bytes"
	stdpe "debug/pe"
	"fmt"
	"testing"
)

func BenchmarkNew(b *testing.B) {
	for _, count := range []int{1, 8, 96, 256} {
		data := buildMinimalPE(count)
		b.Run(fmt.Sprintf("Sections%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := New(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	b.Run("NonPE", func(b *testing.B) {
		data := bytes.Repeat([]byte("x"), 4096)
		b.ReportAllocs()
		for b.Loop() {
			if _, err := New(data); err == nil {
				b.Fatal("accepted non-PE")
			}
		}
	})
}

// This is a header-only workload. It does not compare the libraries' complete
// feature sets or establish equivalent malformed-input handling.
func BenchmarkStandardLibraryHeaders(b *testing.B) {
	data := buildMinimalPE(8)
	b.ReportAllocs()
	for b.Loop() {
		f, err := stdpe.NewFile(bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}
		f.Close()
	}
}

func BenchmarkRVAToOffset(b *testing.B) {
	f, err := New(buildMinimalPE(8))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := f.RVAToOffset(0x8050); !ok {
			b.Fatal("unmapped RVA")
		}
	}
}
