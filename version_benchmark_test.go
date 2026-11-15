package pe_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkVersionInfo(b *testing.B) {
	for _, entries := range []int{0, 16, 64, 256} {
		payload := testfixture.StandardVersionPayload(entries)
		b.Run(fmt.Sprintf("Entries%d", entries), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				vi, err := pe.ParseVersionInfo(payload)
				if err != nil || len(vi.StringTables) != 1 || len(vi.StringTables[0].Entries) != entries {
					b.Fatalf("ParseVersionInfo() = (%+v, %v)", vi, err)
				}
			}
		})
	}

	b.Run("OverLimit", func(b *testing.B) {
		p := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
			Key: "VS_VERSION_INFO",
			Children: []testfixture.VersionNodeSpec{
				{
					Key: "StringFileInfo",
					Children: []testfixture.VersionNodeSpec{
						{
							Key: "040904B0",
							Children: []testfixture.VersionNodeSpec{
								{Key: "Big", Type: 1, HasCustomValLn: true, CustomValLn: pe.MaxVersionValueUnits + 1},
							},
						},
					},
				},
			},
		})
		b.ReportAllocs()
		for b.Loop() {
			vi, err := pe.ParseVersionInfo(p)
			if vi != nil || !errors.Is(err, pe.ErrVersionInfoLimit) {
				b.Fatalf("got (%+v, %v)", vi, err)
			}
		}
	})
}
