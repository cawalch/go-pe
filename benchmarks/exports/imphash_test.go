package exports_test

import (
	"fmt"
	"testing"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func TestCommonImphash(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("PE64=%t", is64), func(t *testing.T) {
			data := testfixture.Imports(is64, 4, 8)
			f, err := gope.New(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.Imphash(data)
			if err != nil {
				t.Fatal(err)
			}

			safe, err := saferwall.NewBytes(data, importOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = safe.Close() }()
			if err := safe.Parse(); err != nil {
				t.Fatal(err)
			}
			want, err := safe.ImpHash()
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("Imphash mismatch: go-pe=%q saferwall=%q", got, want)
			}
		})
	}
}

func BenchmarkImphashComparison(b *testing.B) {
	data := testfixture.Imports(true, 8, 32)

	b.Run("go-pe", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := gope.New(data)
			if err != nil {
				b.Fatal(err)
			}
			sum, err := f.Imphash(data)
			if err != nil || sum == "" {
				b.Fatalf("Imphash = (%q, %v)", sum, err)
			}
		}
	})

	b.Run("saferwall", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			safe, err := saferwall.NewBytes(data, importOptions())
			if err != nil {
				b.Fatal(err)
			}
			if err := safe.Parse(); err != nil {
				_ = safe.Close()
				b.Fatal(err)
			}
			sum, err := safe.ImpHash()
			_ = safe.Close()
			if err != nil || sum == "" {
				b.Fatalf("saferwall ImpHash = (%q, %v)", sum, err)
			}
		}
	})
}
