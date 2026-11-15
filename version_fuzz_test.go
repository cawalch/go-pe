package pe_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzVersionInfo(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("short"))
	f.Add(testfixture.StandardVersionPayload(0))
	f.Add(testfixture.StandardVersionPayload(8))
	f.Add(testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
		Key: "VS_VERSION_INFO",
		Children: []testfixture.VersionNodeSpec{
			{Key: "Custom", Type: 0, ValueBytes: []byte{1, 2, 3, 4}},
		},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		vi, err := pe.ParseVersionInfo(data)
		if err != nil {
			if vi != nil {
				t.Fatalf("ParseVersionInfo returned non-nil result on error %v", err)
			}
			return
		}
		if vi == nil || vi.Key != "VS_VERSION_INFO" {
			t.Fatalf("unexpected VersionInfo on success: %+v", vi)
		}
	})
}
