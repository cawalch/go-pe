package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestExceptionDirectory(t *testing.T) {
	data64 := testfixture.Minimal(true, 1)
	f64, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := f64.Exceptions(data64); err != nil || entries != nil {
		t.Fatalf("missing Exceptions = (%+v, %v), want (nil, nil)", entries, err)
	}

	secOff := int(f64.Sections[0].PointerToRawData)
	secRVA := f64.Sections[0].VirtualAddress
	dirOff := 152 + 112 + pe.DataDirectoryException*8
	binary.LittleEndian.PutUint32(data64[dirOff:], secRVA)
	binary.LittleEndian.PutUint32(data64[dirOff+4:], 24)
	binary.LittleEndian.PutUint32(data64[secOff:], 0x1000)
	binary.LittleEndian.PutUint32(data64[secOff+4:], 0x1080)
	binary.LittleEndian.PutUint32(data64[secOff+8:], 0x2000)
	binary.LittleEndian.PutUint32(data64[secOff+12:], 0x1100)
	binary.LittleEndian.PutUint32(data64[secOff+16:], 0x1150)
	binary.LittleEndian.PutUint32(data64[secOff+20:], 0x2020)

	fPop, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fPop.Exceptions(data64)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].BeginAddress != 0x1000 || entries[1].UnwindData != 0x2020 {
		t.Fatalf("unexpected Exceptions: %+v", entries)
	}

	binary.LittleEndian.PutUint32(data64[dirOff+4:], 10)
	fBad, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fBad.Exceptions(data64); !errors.Is(err, pe.ErrInvalidException) {
		t.Fatalf("misaligned Exceptions err = %v, want ErrInvalidException", err)
	}
}
