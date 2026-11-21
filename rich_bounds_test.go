package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRichHeaderValidationErrors(t *testing.T) {
	var nilFile *pe.File
	if rh, err := nilFile.RichHeader(make([]byte, 128)); rh != nil || !errors.Is(err, pe.ErrInvalidRichHeader) {
		t.Fatalf("nil file: got (%+v, %v), want ErrInvalidRichHeader", rh, err)
	}
	var unparsed pe.File
	if rh, err := unparsed.RichHeader(make([]byte, 128)); rh != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("unparsed file: got (%+v, %v), want ErrInvalidHeader", rh, err)
	}

	validPE, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{{ToolID: 1, Version: 2, Count: 3}},
	})
	f, err := pe.New(validPE)
	if err != nil {
		t.Fatal(err)
	}

	if rh, err := f.RichHeader(validPE[:63]); rh != nil || !errors.Is(err, pe.ErrInvalidRichHeader) {
		t.Fatalf("short data: got (%+v, %v)", rh, err)
	}
	if rh, err := f.RichHeader(validPE[:int(f.DOSHeader.AddressOfNewEXEHeader)-1]); rh != nil || !errors.Is(err, pe.ErrInvalidRichHeader) {
		t.Fatalf("truncated before e_lfanew: got (%+v, %v)", rh, err)
	}

	badLfanew := *f
	badLfanew.DOSHeader.AddressOfNewEXEHeader = 32
	if rh, err := badLfanew.RichHeader(validPE); rh != nil || !errors.Is(err, pe.ErrInvalidRichHeader) {
		t.Fatalf("overlapping e_lfanew: got (%+v, %v)", rh, err)
	}

	// Build stub-based malformed cases.
	key := uint32(0x11223344)
	cases := []struct {
		name    string
		dos     []byte
		stub    []byte
		wantErr error
	}{
		{
			name:    "truncated_key_after_rich",
			stub:    []byte{'R', 'i', 'c', 'h', 1, 2},
			wantErr: pe.ErrInvalidRichHeader,
		},
		{
			name: "zero_xor_key",
			stub: func() []byte {
				var b []byte
				b = binary.LittleEndian.AppendUint32(b, pe.DanSMarker)
				b = append(b, make([]byte, 12)...)
				b = append(b, 'R', 'i', 'c', 'h', 0, 0, 0, 0)
				return b
			}(),
			wantErr: pe.ErrInvalidRichHeader,
		},
		{
			name:    "missing_dans_marker",
			stub:    binary.LittleEndian.AppendUint32([]byte{0, 1, 2, 3, 4, 5, 6, 7, 'R', 'i', 'c', 'h'}, key),
			wantErr: pe.ErrInvalidRichHeader,
		},
		{
			name: "dans_inside_dos_header_ignored",
			dos: func() []byte {
				d := make([]byte, 64)
				binary.LittleEndian.PutUint32(d[0x20:], pe.DanSMarker^key)
				return d
			}(),
			stub:    binary.LittleEndian.AppendUint32([]byte{'R', 'i', 'c', 'h'}, key),
			wantErr: pe.ErrInvalidRichHeader,
		},
		{
			name: "unaligned_dans_before_rich",
			stub: func() []byte {
				var b []byte
				b = binary.LittleEndian.AppendUint32(b, pe.DanSMarker^key)
				b = append(b, make([]byte, 13)...)
				b = append(b, 'R', 'i', 'c', 'h')
				b = binary.LittleEndian.AppendUint32(b, key)
				return b
			}(),
			wantErr: pe.ErrInvalidRichHeader,
		},
		{
			name: "body_shorter_than_16_bytes",
			stub: func() []byte {
				var b []byte
				b = binary.LittleEndian.AppendUint32(b, pe.DanSMarker^key)
				b = binary.LittleEndian.AppendUint32(b, key)
				b = binary.LittleEndian.AppendUint32(b, key)
				b = append(b, 'R', 'i', 'c', 'h')
				b = binary.LittleEndian.AppendUint32(b, key)
				return b
			}(),
			wantErr: pe.ErrInvalidRichHeader,
		},
		{
			name: "odd_dword_entry_count",
			stub: func() []byte {
				var b []byte
				b = binary.LittleEndian.AppendUint32(b, pe.DanSMarker^key)
				b = binary.LittleEndian.AppendUint32(b, key)
				b = binary.LittleEndian.AppendUint32(b, key)
				b = binary.LittleEndian.AppendUint32(b, key)
				b = binary.LittleEndian.AppendUint32(b, 1^key)
				b = append(b, 'R', 'i', 'c', 'h')
				b = binary.LittleEndian.AppendUint32(b, key)
				return b
			}(),
			wantErr: pe.ErrInvalidRichHeader,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := testfixture.WithDOSStub(false, tc.dos, tc.stub)
			pf, err := pe.New(img)
			if err != nil {
				t.Fatal(err)
			}
			rh, err := pf.RichHeader(img)
			if rh != nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("got (%+v, %v), want %v", rh, err, tc.wantErr)
			}
		})
	}
}

func TestRichHeaderLimits(t *testing.T) {
	// Exactly MaxRichEntries entries must succeed.
	atLimitEntries := make([]testfixture.RichEntrySpec, pe.MaxRichEntries)
	for i := range atLimitEntries {
		atLimitEntries[i] = testfixture.RichEntrySpec{ToolID: uint16(i), Version: 1, Count: 1}
	}
	atLimitPE, _ := testfixture.RichPE(true, testfixture.RichOptions{Entries: atLimitEntries})
	f, err := pe.New(atLimitPE)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := f.RichHeader(atLimitPE)
	if err != nil || rh == nil || len(rh.Entries) != pe.MaxRichEntries || !rh.ChecksumValid {
		t.Fatalf("at MaxRichEntries failed: (%+v, %v)", rh, err)
	}

	// MaxRichEntries + 1 must fail with ErrRichHeaderLimit.
	overEntryPE, _ := testfixture.RichPE(false, testfixture.RichOptions{
		Entries: make([]testfixture.RichEntrySpec, pe.MaxRichEntries+1),
	})
	of, err := pe.New(overEntryPE)
	if err != nil {
		t.Fatal(err)
	}
	if rh, err := of.RichHeader(overEntryPE); rh != nil || !errors.Is(err, pe.ErrRichHeaderLimit) {
		t.Fatalf("over MaxRichEntries: got (%+v, %v), want ErrRichHeaderLimit", rh, err)
	}

	// Backward search exceeding MaxRichHeaderBytes without DanS hits ErrRichHeaderLimit.
	farStub := make([]byte, pe.MaxRichHeaderBytes+12)
	copy(farStub[len(farStub)-8:], []byte{'R', 'i', 'c', 'h', 1, 0, 0, 0})
	farPE := testfixture.WithDOSStub(false, nil, farStub)
	ff, err := pe.New(farPE)
	if err != nil {
		t.Fatal(err)
	}
	if rh, err := ff.RichHeader(farPE); rh != nil || !errors.Is(err, pe.ErrRichHeaderLimit) {
		t.Fatalf("over MaxRichHeaderBytes search: got (%+v, %v), want ErrRichHeaderLimit", rh, err)
	}

	// DOS stub at MaxRichStubBytes without Rich returns (nil, nil); +1 exceeds limit.
	atStubLimit := testfixture.WithDOSStub(false, nil, make([]byte, pe.MaxRichStubBytes))
	af, err := pe.New(atStubLimit)
	if err != nil {
		t.Fatal(err)
	}
	if rh, err := af.RichHeader(atStubLimit); rh != nil || err != nil {
		t.Fatalf("at MaxRichStubBytes: got (%+v, %v), want (nil, nil)", rh, err)
	}

	overStubLimit := testfixture.WithDOSStub(false, nil, make([]byte, pe.MaxRichStubBytes+1))
	sf, err := pe.New(overStubLimit)
	if err != nil {
		t.Fatal(err)
	}
	if rh, err := sf.RichHeader(overStubLimit); rh != nil || !errors.Is(err, pe.ErrRichHeaderLimit) {
		t.Fatalf("over MaxRichStubBytes: got (%+v, %v), want ErrRichHeaderLimit", rh, err)
	}
}
