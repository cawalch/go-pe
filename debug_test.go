package pe_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestDebugAbsent(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Minimal(is64, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := f.Debug(data)
		if err != nil || entries != nil {
			t.Fatalf("Debug() PE64=%t = (%+v, %v), want (nil, nil)", is64, entries, err)
		}
	}

	// Fewer than 7 data directories -> absent debug directory.
	data := testfixture.Minimal(false, 1)
	binary.LittleEndian.PutUint32(data[244:], 6)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Debug(data)
	if err != nil || entries != nil {
		t.Fatalf("Debug() short directory table = (%+v, %v), want (nil, nil)", entries, err)
	}
}

func TestDebugRSDSAndNB10Formats(t *testing.T) {
	guid := [16]byte{
		0x78, 0x56, 0x34, 0x12, // Data1 LE = 0x12345678
		0xbc, 0x9a, // Data2 LE = 0x9abc
		0xf0, 0xde, // Data3 LE = 0xdef0
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Data4
	}
	nonUTF8Path := []byte{'C', ':', '\\', 'b', 'u', 'i', 'l', 'd', '\\', 0xff, 0xfe, '.', 'p', 'd', 'b'}

	for _, is64 := range []bool{false, true} {
		data := testfixture.DebugPE(is64, []testfixture.DebugEntrySpec{
			{
				Type:    pe.DebugTypePOGO,
				Payload: []byte{0, 0, 0, 0},
			},
			{
				Characteristics: 1,
				TimeDateStamp:   1700000100,
				MajorVersion:    1,
				MinorVersion:    2,
				Type:            pe.DebugTypeCodeView,
				Payload:         testfixture.EncodeCodeViewRSDS(guid, 7, []byte(`C:\src\app.pdb`), true),
			},
			{
				TimeDateStamp: 1700000200,
				Type:          pe.DebugTypeCodeView,
				Payload:       testfixture.EncodeCodeViewNB10(0x40, 0x55667788, 3, nonUTF8Path, true),
			},
			{
				Type: 0x9999,
			},
		})

		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := f.Debug(data)
		if err != nil {
			t.Fatalf("PE64=%t Debug() failed: %v", is64, err)
		}
		if len(entries) != 4 {
			t.Fatalf("PE64=%t got %d entries, want 4", is64, len(entries))
		}

		// Entry 0: known non-CodeView retained as metadata.
		if entries[0].Type != pe.DebugTypePOGO || entries[0].CodeView != nil {
			t.Fatalf("entry[0] = %+v, want POGO with nil CodeView", entries[0])
		}

		// Entry 1: RSDS.
		cv1 := entries[1].CodeView
		if cv1 == nil || cv1.Signature != pe.CodeViewSignatureRSDS {
			t.Fatalf("entry[1].CodeView = %+v, want RSDS", cv1)
		}
		if entries[1].Characteristics != 1 || entries[1].MajorVersion != 1 || entries[1].MinorVersion != 2 {
			t.Fatalf("entry[1] header mismatch: %+v", entries[1])
		}
		if cv1.GUID.Data1 != 0x12345678 || cv1.GUID.Data2 != 0x9abc || cv1.GUID.Data3 != 0xdef0 {
			t.Fatalf("GUID = %+v", cv1.GUID)
		}
		if got := cv1.GUID.String(); got != "12345678-9abc-def0-1122-334455667788" {
			t.Fatalf("GUID.String() = %q", got)
		}
		if got := cv1.GUID.Bytes(); got != guid {
			t.Fatalf("GUID.Bytes() = %x, want %x", got, guid)
		}
		if cv1.Age != 7 || cv1.NB10Offset != 0 || cv1.NB10Signature != 0 {
			t.Fatalf("entry[1].CodeView numeric fields = %+v", cv1)
		}
		if !bytes.Equal(cv1.PDBPath, []byte(`C:\src\app.pdb`)) {
			t.Fatalf("entry[1].PDBPath = %q", cv1.PDBPath)
		}

		// Entry 2: NB10 with raw non-UTF8 path preserved verbatim.
		cv2 := entries[2].CodeView
		if cv2 == nil || cv2.Signature != pe.CodeViewSignatureNB10 {
			t.Fatalf("entry[2].CodeView = %+v, want NB10", cv2)
		}
		if cv2.NB10Offset != 0x40 || cv2.NB10Signature != 0x55667788 || cv2.Age != 3 || cv2.GUID != (pe.CodeViewGUID{}) {
			t.Fatalf("entry[2].CodeView numeric fields = %+v", cv2)
		}
		if !bytes.Equal(cv2.PDBPath, nonUTF8Path) {
			t.Fatalf("entry[2].PDBPath = %x, want %x", cv2.PDBPath, nonUTF8Path)
		}

		// Entry 3: unknown debug type retained as metadata.
		if entries[3].Type != 0x9999 || entries[3].CodeView != nil {
			t.Fatalf("entry[3] = %+v, want unknown metadata", entries[3])
		}
	}
}

func TestDebugPointerModesAndPaths(t *testing.T) {
	guid := [16]byte{1, 2, 3, 4}
	data := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			// Overlay / file-offset-only RSDS with absent path (24-byte header only).
			Type:    pe.DebugTypeCodeView,
			Overlay: true,
			RawOnly: true,
			Payload: testfixture.EncodeCodeViewRSDS(guid, 1, nil, false),
		},
		{
			// RVA-only RSDS with explicit empty NUL-terminated path.
			Type:    pe.DebugTypeCodeView,
			RVAOnly: true,
			Payload: testfixture.EncodeCodeViewRSDS(guid, 2, nil, true),
		},
		{
			// NB10 header only (absent path, 16 bytes).
			Type:    pe.DebugTypeCodeView,
			Payload: testfixture.EncodeCodeViewNB10(0, 0xdeadbeef, 4, nil, false),
		},
		{
			// Unknown CodeView signature ("NB09") retained with CodeView nil.
			Type:    pe.DebugTypeCodeView,
			Payload: []byte{'N', 'B', '0', '9', 1, 2, 3, 4},
		},
	})

	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Debug(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
	if entries[0].CodeView == nil || entries[0].CodeView.PDBPath != nil || entries[0].CodeView.Age != 1 {
		t.Fatalf("entry[0] (absent path overlay) = %+v", entries[0].CodeView)
	}
	if entries[1].CodeView == nil || entries[1].CodeView.PDBPath == nil || len(entries[1].CodeView.PDBPath) != 0 || entries[1].CodeView.Age != 2 {
		t.Fatalf("entry[1] (empty path RVA-only) = %+v", entries[1].CodeView)
	}
	if entries[2].CodeView == nil || entries[2].CodeView.PDBPath != nil || entries[2].CodeView.NB10Signature != 0xdeadbeef {
		t.Fatalf("entry[2] (NB10 absent path) = %+v", entries[2].CodeView)
	}
	if entries[3].Type != pe.DebugTypeCodeView || entries[3].CodeView != nil {
		t.Fatalf("entry[3] (unknown CV signature) = %+v, want nil CodeView", entries[3])
	}
}

func TestDebugOwnershipAndNonCaching(t *testing.T) {
	path := []byte("owned.pdb")
	orig := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:    pe.DebugTypeCodeView,
			Payload: testfixture.EncodeCodeViewRSDS([16]byte{9}, 5, path, true),
		},
	})
	work := bytes.Clone(orig)

	f, err := pe.New(work)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Debug(work)
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite source buffer and verify returned PDBPath is owned.
	clear(work)
	if !bytes.Equal(entries[0].CodeView.PDBPath, path) {
		t.Fatalf("PDBPath aliased caller buffer: got %q, want %q", entries[0].CodeView.PDBPath, path)
	}

	// Repeated calls reflect current input slice rather than caching stale state.
	entries2, err := f.Debug(orig)
	if err != nil || !bytes.Equal(entries2[0].CodeView.PDBPath, path) {
		t.Fatalf("second Debug(orig) = (%+v, %v)", entries2, err)
	}
}
