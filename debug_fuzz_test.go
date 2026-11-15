package pe_test

import (
	"bytes"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzDebug(f *testing.F) {
	f.Add(testfixture.Minimal(false, 1))
	f.Add(testfixture.Minimal(true, 1))
	f.Add(testfixture.DebugPE(false, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1, 2, 3, 4}, 1, []byte("app.pdb"), true)},
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewNB10(0, 0x11223344, 2, []byte("legacy.pdb"), true)},
		{Type: pe.DebugTypeRepro},
	}))
	f.Add(testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Overlay: true, RawOnly: true, Payload: testfixture.EncodeCodeViewRSDS([16]byte{9}, 3, []byte{0xff, '.', 'p', 'd', 'b'}, true)},
		{Type: pe.DebugTypeCodeView, RVAOnly: true, Payload: testfixture.EncodeCodeViewRSDS([16]byte{8}, 4, nil, true)},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := pe.New(data)
		if err != nil {
			return
		}
		entries, err := parsed.Debug(data)
		if err != nil {
			if entries != nil {
				t.Fatalf("Debug() returned partial entries with err=%v", err)
			}
			return
		}
		if len(entries) > pe.MaxDebugEntries {
			t.Fatalf("entry count %d exceeds MaxDebugEntries %d", len(entries), pe.MaxDebugEntries)
		}
		var totalPayload uint64
		for i, e := range entries {
			if e.CodeView == nil {
				continue
			}
			totalPayload += uint64(e.SizeOfData)
			if len(e.CodeView.PDBPath) >= pe.MaxCodeViewPathBytes {
				t.Fatalf("entry %d PDBPath length %d >= MaxCodeViewPathBytes", i, len(e.CodeView.PDBPath))
			}
			if bytes.IndexByte(e.CodeView.PDBPath, 0) >= 0 {
				t.Fatalf("entry %d PDBPath contains embedded NUL byte", i)
			}
		}
		if totalPayload > pe.MaxDebugTotalBytes {
			t.Fatalf("total CodeView payload %d exceeds MaxDebugTotalBytes", totalPayload)
		}
	})
}
