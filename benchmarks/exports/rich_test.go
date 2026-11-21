package exports_test

import (
	"fmt"
	"testing"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func richOptions() *saferwall.Options {
	return &saferwall.Options{
		OmitExportDirectory:        true,
		OmitImportDirectory:        true,
		OmitResourceDirectory:      true,
		OmitExceptionDirectory:     true,
		OmitSecurityDirectory:      true,
		OmitRelocDirectory:         true,
		OmitDebugDirectory:         true,
		OmitArchitectureDirectory:  true,
		OmitGlobalPtrDirectory:     true,
		OmitTLSDirectory:           true,
		OmitLoadConfigDirectory:    true,
		OmitBoundImportDirectory:   true,
		OmitIATDirectory:           true,
		OmitDelayImportDirectory:   true,
		OmitCLRHeaderDirectory:     true,
		DisableCertValidation:      true,
		DisableSignatureValidation: true,
		Logger:                     discardLogger{},
	}
}

func TestCommonRichHeader(t *testing.T) {
	// Scope excludes invalid padding, key=0, and multi-marker DOS stubs:
	// saferwall/pe searches forward from byte 0 (recording anomalies instead of
	// errors) whereas go-pe scans backward from e_lfanew with strict validation.
	entries := []testfixture.RichEntrySpec{
		{ToolID: 0x00ff, Version: 0x766f, Count: 2},
		{ToolID: 0x0104, Version: 0x725d, Count: 19},
		{ToolID: 0x0105, Version: 0x725d, Count: 1},
	}

	for _, is64 := range []bool{false, true} {
		for _, customKey := range []bool{false, true} {
			name := fmt.Sprintf("PE64=%t/CustomKey=%t", is64, customKey)
			t.Run(name, func(t *testing.T) {
				data, wantChecksum := testfixture.RichPE(is64, testfixture.RichOptions{
					Entries:      entries,
					UseCustomKey: customKey,
					CustomKey:    0x13572468,
				})
				f, err := gope.New(data)
				if err != nil {
					t.Fatal(err)
				}
				rh, err := f.RichHeader(data)
				if err != nil || rh == nil {
					t.Fatalf("go-pe RichHeader = (%+v, %v)", rh, err)
				}

				safe, err := saferwall.NewBytes(data, richOptions())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = safe.Close() }()
				if err := safe.Parse(); err != nil {
					t.Fatal(err)
				}
				if !safe.HasRichHdr {
					t.Fatal("saferwall reported HasRichHdr=false")
				}
				if int64(safe.RichHeader.DansOffset) != rh.Offset ||
					safe.RichHeader.XORKey != rh.Key ||
					safe.RichHeaderChecksum() != rh.ComputedChecksum ||
					rh.ComputedChecksum != wantChecksum ||
					rh.ChecksumValid != !customKey ||
					len(safe.RichHeader.CompIDs) != len(rh.Entries) {
					t.Fatalf("mismatch: go-pe=%+v saferwall=%+v computed=%#x", rh, safe.RichHeader, safe.RichHeaderChecksum())
				}
				for i, cid := range safe.RichHeader.CompIDs {
					got := rh.Entries[i]
					if cid.ProdID != got.ToolID || cid.MinorCV != got.Version || cid.Count != got.Count {
						t.Fatalf("entry[%d] mismatch: go-pe=%+v saferwall=%+v", i, got, cid)
					}
				}
			})
		}
	}
}

func BenchmarkParseRichHeader(b *testing.B) {
	entries := make([]testfixture.RichEntrySpec, 32)
	for i := range entries {
		entries[i] = testfixture.RichEntrySpec{ToolID: uint16(i + 1), Version: 0x766f, Count: uint32(i + 1)}
	}
	data, _ := testfixture.RichPE(true, testfixture.RichOptions{Entries: entries})

	b.Run("go-pe", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := gope.New(data)
			if err != nil {
				b.Fatal(err)
			}
			rh, err := f.RichHeader(data)
			if err != nil || rh == nil || len(rh.Entries) != len(entries) {
				b.Fatalf("RichHeader = (%+v, %v)", rh, err)
			}
		}
	})

	b.Run("saferwall", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			safe, err := saferwall.NewBytes(data, richOptions())
			if err != nil {
				b.Fatal(err)
			}
			err = safe.Parse()
			_ = safe.Close()
			if err != nil || !safe.HasRichHdr || len(safe.RichHeader.CompIDs) != len(entries) {
				b.Fatalf("saferwall RichHeader = (%+v, %v)", safe.RichHeader, err)
			}
		}
	})
}
