package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func debugDirOffsets(is64 bool) int {
	if is64 {
		return 264 + 6*8
	}
	return 248 + 6*8
}

func TestDebugReceiverAndDirectoryValidation(t *testing.T) {
	var nilFile *pe.File
	if entries, err := nilFile.Debug(nil); entries != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil.Debug() = (%+v, %v), want ErrInvalidHeader", entries, err)
	}
	zero := &pe.File{}
	if entries, err := zero.Debug(nil); entries != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("zero.Debug() = (%+v, %v), want ErrInvalidHeader", entries, err)
	}

	cases := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{
			name: "ZeroRVAWithNonZeroSize",
			mutate: func(b []byte) {
				off := debugDirOffsets(true)
				binary.LittleEndian.PutUint32(b[off:], 0)
				binary.LittleEndian.PutUint32(b[off+4:], 28)
			},
			want: pe.ErrInvalidDebug,
		},
		{
			name: "NonZeroRVAWithZeroSize",
			mutate: func(b []byte) {
				off := debugDirOffsets(true)
				binary.LittleEndian.PutUint32(b[off:], 0x1000)
				binary.LittleEndian.PutUint32(b[off+4:], 0)
			},
			want: pe.ErrInvalidDebug,
		},
		{
			name: "MisalignedDirectorySize",
			mutate: func(b []byte) {
				off := debugDirOffsets(true)
				binary.LittleEndian.PutUint32(b[off:], 0x1000)
				binary.LittleEndian.PutUint32(b[off+4:], 29)
			},
			want: pe.ErrInvalidDebug,
		},
		{
			name: "DirectoryArithmeticOverflow",
			mutate: func(b []byte) {
				off := debugDirOffsets(true)
				binary.LittleEndian.PutUint32(b[off:], 0xfffffff0)
				binary.LittleEndian.PutUint32(b[off+4:], 28)
			},
			want: pe.ErrIntegerOverflow,
		},
		{
			name: "OverMaxDebugEntries",
			mutate: func(b []byte) {
				off := debugDirOffsets(true)
				binary.LittleEndian.PutUint32(b[off:], 0x1000)
				binary.LittleEndian.PutUint32(b[off+4:], (pe.MaxDebugEntries+1)*28)
			},
			want: pe.ErrDebugLimit,
		},
		{
			name: "DirectoryTableOutOfBounds",
			mutate: func(b []byte) {
				off := debugDirOffsets(true)
				binary.LittleEndian.PutUint32(b[off:], 0x11f0)
				binary.LittleEndian.PutUint32(b[off+4:], 28*2)
			},
			want: pe.ErrOutOfBounds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
				{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, []byte("a.pdb"), true)},
			})
			tc.mutate(data)
			f, err := pe.New(data)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := f.Debug(data)
			if entries != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Debug() = (%+v, %v), want error %v", entries, err, tc.want)
			}
		})
	}
}

func TestDebugPointerConflictsAndCodeViewBounds(t *testing.T) {
	// Missing both pointers on CodeView entry.
	missingPtrs := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, SizeOfData: 25, KeepSize: true},
	})
	// Conflicting PointerToRawData vs AddressOfRawData (both valid section locations, pointing differently).
	conflicting := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:             pe.DebugTypeCodeView,
			Payload:          testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, []byte("a.pdb"), true),
			PointerToRawData: 512 + 28 + 1, // shifted by 1 from AddressOfRawData mapping
		},
	})
	// Non-zero unmapped RVA alongside valid file offset conflicts cleanly.
	unmappedRVAConflict := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:             pe.DebugTypeCodeView,
			Payload:          testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, []byte("a.pdb"), true),
			AddressOfRawData: 0x9000,
			PointerToRawData: 512 + 28,
		},
	})
	// Truncated < 4 signature bytes.
	shortSig := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, SizeOfData: 3, AddressOfRawData: 0x1000, PointerToRawData: 512, KeepSize: true},
	})
	// Truncated RSDS (< 24 bytes).
	shortRSDS := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, []byte("a.pdb"), true)[:20]},
	})
	// Truncated NB10 (< 16 bytes).
	shortNB10 := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewNB10(0, 1, 1, []byte("a.pdb"), true)[:12]},
	})
	// Unterminated RSDS path (trailing non-NUL bytes within limit).
	unterminated := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, []byte("unterminated"), false)},
	})
	// Single payload over MaxDebugPayloadBytes.
	overPayload := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:             pe.DebugTypeCodeView,
			SizeOfData:       pe.MaxDebugPayloadBytes + 1,
			PointerToRawData: 512,
			KeepSize:         true,
		},
	})
	// Path exceeding MaxCodeViewPathBytes (4096 non-NUL bytes followed by NUL).
	longPath := bytes.Repeat([]byte{'a'}, pe.MaxCodeViewPathBytes)
	overPath := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, longPath, true)},
	})
	// Path at exact MaxCodeViewPathBytes boundary (4095 chars + NUL = 4096) succeeds.
	exactPath := bytes.Repeat([]byte{'b'}, pe.MaxCodeViewPathBytes-1)
	okPath := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{Type: pe.DebugTypeCodeView, Payload: testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, exactPath, true)},
	})

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"MissingPointers", missingPtrs, pe.ErrInvalidDebug},
		{"ConflictingPointers", conflicting, pe.ErrInvalidDebug},
		{"UnmappedRVAConflict", unmappedRVAConflict, pe.ErrInvalidDebug},
		{"TruncatedSignature", shortSig, pe.ErrInvalidDebug},
		{"TruncatedRSDS", shortRSDS, pe.ErrInvalidDebug},
		{"TruncatedNB10", shortNB10, pe.ErrInvalidDebug},
		{"UnterminatedPath", unterminated, pe.ErrUnterminatedString},
		{"OverPayloadLimit", overPayload, pe.ErrDebugLimit},
		{"OverPathLimit", overPath, pe.ErrDebugLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := pe.New(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := f.Debug(tc.data)
			if entries != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Debug() = (%+v, %v), want %v", entries, err, tc.want)
			}
		})
	}

	f, err := pe.New(okPath)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Debug(okPath)
	if err != nil || len(entries) != 1 || !bytes.Equal(entries[0].CodeView.PDBPath, exactPath) {
		t.Fatalf("exact MaxCodeViewPathBytes Debug() = (%+v, %v)", entries, err)
	}
}

func TestDebugCumulativeLimitAndTruncation(t *testing.T) {
	// 17 entries each pointing to the same 64 KiB RSDS payload exceed MaxDebugTotalBytes (1 MiB)
	// before hitting MaxDebugEntries (256).
	bigPath := append(bytes.Repeat([]byte{'x'}, 100), 0)
	bigRSDS := make([]byte, pe.MaxDebugPayloadBytes)
	copy(bigRSDS, testfixture.EncodeCodeViewRSDS([16]byte{7}, 1, bigPath, false))

	specs := make([]testfixture.DebugEntrySpec, (pe.MaxDebugTotalBytes/pe.MaxDebugPayloadBytes)+1)
	sharedRaw := uint32(512 + len(specs)*28)
	sharedRVA := uint32(0x1000 + len(specs)*28)
	specs[0] = testfixture.DebugEntrySpec{
		Type:    pe.DebugTypeCodeView,
		Payload: bigRSDS,
	}
	for i := 1; i < len(specs); i++ {
		specs[i] = testfixture.DebugEntrySpec{
			Type:             pe.DebugTypeCodeView,
			SizeOfData:       pe.MaxDebugPayloadBytes,
			AddressOfRawData: sharedRVA,
			PointerToRawData: sharedRaw,
			KeepSize:         true,
		}
	}
	data := testfixture.DebugPE(true, specs)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := f.Debug(data); entries != nil || !errors.Is(err, pe.ErrDebugLimit) {
		t.Fatalf("cumulative repeated CodeView = (%+v, %v), want ErrDebugLimit", entries, err)
	}

	// Exact MaxDebugEntries non-CodeView entries succeed, while +1 fails with ErrDebugLimit.
	maxSpecs := make([]testfixture.DebugEntrySpec, pe.MaxDebugEntries)
	for i := range maxSpecs {
		maxSpecs[i] = testfixture.DebugEntrySpec{Type: pe.DebugTypeRepro}
	}
	maxData := testfixture.DebugPE(false, maxSpecs)
	mf, err := pe.New(maxData)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mf.Debug(maxData)
	if err != nil || len(got) != pe.MaxDebugEntries {
		t.Fatalf("exact MaxDebugEntries = (%d, %v), want (%d, nil)", len(got), err, pe.MaxDebugEntries)
	}

	// Overlay truncated before end of declared NewWithLength fileSize returns ErrOutOfBounds.
	overlayPE := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:    pe.DebugTypeCodeView,
			Overlay: true,
			RawOnly: true,
			Payload: testfixture.EncodeCodeViewRSDS([16]byte{1}, 1, []byte("overlay.pdb"), true),
		},
	})
	trunc := overlayPE[:len(overlayPE)-2]
	tf, err := pe.NewWithLength(trunc, int64(len(overlayPE)))
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := tf.Debug(trunc); entries != nil || !errors.Is(err, pe.ErrOutOfBounds) {
		t.Fatalf("truncated overlay Debug() = (%+v, %v), want ErrOutOfBounds", entries, err)
	}

	// CodeView payload offset arithmetic overflow (PointerToRawData near MaxUint32, overlay raw-only).
	overflowPE := testfixture.DebugPE(true, []testfixture.DebugEntrySpec{
		{
			Type:             pe.DebugTypeCodeView,
			SizeOfData:       32,
			PointerToRawData: 0xfffffffe,
			KeepSize:         true,
		},
	})
	of, err := pe.New(overflowPE)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := of.Debug(overflowPE); entries != nil || !errors.Is(err, pe.ErrOutOfBounds) {
		t.Fatalf("overflow raw offset Debug() = (%+v, %v), want ErrOutOfBounds", entries, err)
	}
}
