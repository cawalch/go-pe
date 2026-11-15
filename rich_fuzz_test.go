package pe_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzRichHeader(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(testfixture.Minimal(false, 1))
	rich32, _ := testfixture.RichPE(false, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{
			{ToolID: 0x00ff, Version: 0x766f, Count: 4},
		},
	})
	rich64, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{
			{ToolID: 0x0104, Version: 0x725d, Count: 12},
		},
	})
	f.Add(rich32)
	f.Add(rich64)

	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := pe.New(data)
		if err != nil {
			return
		}
		rh, err := file.RichHeader(data)
		if err != nil {
			if rh != nil {
				t.Fatalf("RichHeader returned non-nil header with error %v", err)
			}
			return
		}
		if rh == nil {
			return
		}
		if len(rh.RawData) != int(rh.Length) || len(rh.ClearData) != int(rh.Length) {
			t.Fatalf("length mismatch: Length=%d Raw=%d Clear=%d", rh.Length, len(rh.RawData), len(rh.ClearData))
		}
		if len(rh.Entries) > pe.MaxRichEntries || rh.Length > pe.MaxRichHeaderBytes {
			t.Fatalf("limit exceeded without error: entries=%d len=%d", len(rh.Entries), rh.Length)
		}
	})
}
