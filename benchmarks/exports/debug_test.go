package exports_test

import (
	"bytes"
	"fmt"
	"testing"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func debugOptions() *saferwall.Options {
	return &saferwall.Options{
		OmitExportDirectory:        true,
		OmitImportDirectory:        true,
		OmitResourceDirectory:      true,
		OmitExceptionDirectory:     true,
		OmitSecurityDirectory:      true,
		OmitRelocDirectory:         true,
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

func TestCommonDebugDirectory(t *testing.T) {
	// Scope uses well-formed RSDS CodeView entries plus a metadata-only Repro
	// entry with PointerToRawData matching RVAToOffset(AddressOfRawData).
	// saferwall/pe ignores AddressOfRawData-only entries and underflows
	// SizeOfData-24-1 on RSDS records without a trailing path.
	guid := [16]byte{
		0x78, 0x56, 0x34, 0x12,
		0xbc, 0x9a,
		0xf0, 0xde,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	}

	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("PE64=%t", is64), func(t *testing.T) {
			data := testfixture.DebugPE(is64, []testfixture.DebugEntrySpec{
				{
					TimeDateStamp: 1700000100,
					Type:          gope.DebugTypeCodeView,
					Payload:       testfixture.EncodeCodeViewRSDS(guid, 5, []byte(`C:\build\sample.pdb`), true),
				},
				{
					TimeDateStamp: 1700000200,
					Type:          0x9999,
				},
			})

			f, err := gope.New(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.Debug(data)
			if err != nil {
				t.Fatal(err)
			}

			safe, err := saferwall.NewBytes(data, debugOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = safe.Close() }()
			if err := safe.Parse(); err != nil {
				t.Fatal(err)
			}

			if len(got) != len(safe.Debugs) {
				t.Fatalf("entry count mismatch: go-pe=%d saferwall=%d", len(got), len(safe.Debugs))
			}
			for i, se := range safe.Debugs {
				ge := got[i]
				if ge.Type != uint32(se.Struct.Type) ||
					ge.TimeDateStamp != se.Struct.TimeDateStamp ||
					ge.SizeOfData != se.Struct.SizeOfData ||
					ge.AddressOfRawData != se.Struct.AddressOfRawData ||
					ge.PointerToRawData != se.Struct.PointerToRawData {
					t.Fatalf("entry[%d] header mismatch: go-pe=%+v saferwall=%+v", i, ge, se.Struct)
				}
				if ge.Type == gope.DebugTypeCodeView {
					rsds, ok := se.Info.(saferwall.CVInfoPDB70)
					if !ok || ge.CodeView == nil {
						t.Fatalf("entry[%d] CodeView mismatch: ok=%t got=%+v", i, ok, ge.CodeView)
					}
					if ge.CodeView.Signature != uint32(rsds.CVSignature) ||
						ge.CodeView.GUID.Data1 != rsds.Signature.Data1 ||
						ge.CodeView.GUID.Data2 != rsds.Signature.Data2 ||
						ge.CodeView.GUID.Data3 != rsds.Signature.Data3 ||
						ge.CodeView.GUID.Data4 != rsds.Signature.Data4 ||
						ge.CodeView.Age != rsds.Age ||
						!bytes.Equal(ge.CodeView.PDBPath, []byte(rsds.PDBFileName)) {
						t.Fatalf("entry[%d] RSDS mismatch: go-pe=%+v saferwall=%+v", i, ge.CodeView, rsds)
					}
				}
			}
		})
	}
}

func BenchmarkParseDebug(b *testing.B) {
	guid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	data := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:    gope.DebugTypeCodeView,
			Payload: testfixture.EncodeCodeViewRSDS(guid, 2, []byte(`C:\src\app\out\app.pdb`), true),
		},
		{
			Type: 0x9999,
		},
	})

	b.Run("go-pe", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := gope.New(data)
			if err != nil {
				b.Fatal(err)
			}
			entries, err := f.Debug(data)
			if err != nil || len(entries) != 2 || entries[0].CodeView == nil {
				b.Fatalf("Debug = (%+v, %v)", entries, err)
			}
		}
	})

	b.Run("saferwall", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			safe, err := saferwall.NewBytes(data, debugOptions())
			if err != nil {
				b.Fatal(err)
			}
			err = safe.Parse()
			_ = safe.Close()
			if err != nil || len(safe.Debugs) != 2 {
				b.Fatalf("saferwall Debugs = (%+v, %v)", safe.Debugs, err)
			}
		}
	})
}
