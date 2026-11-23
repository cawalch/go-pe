package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestExceptionDirectory(t *testing.T) {
	// Minimal PE32+ has no .pdata.
	data64 := testfixture.Minimal(true, 1)
	f64, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	if !f64.MissingPE32PlusExceptionTable() {
		t.Fatal("expected MissingPE32PlusExceptionTable() = true")
	}
	if entries, err := f64.Exceptions(data64); err != nil || entries != nil {
		t.Fatalf("missing Exceptions = (%+v, %v), want (nil, nil)", entries, err)
	}

	// Minimal PE32 should report MissingPE32PlusExceptionTable() = false.
	data32 := testfixture.Minimal(false, 1)
	f32, err := pe.New(data32)
	if err != nil {
		t.Fatal(err)
	}
	if f32.MissingPE32PlusExceptionTable() {
		t.Fatal("PE32 should return MissingPE32PlusExceptionTable() = false")
	}

	// Populate 2 RUNTIME_FUNCTION entries in PE32+.
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
	if fPop.MissingPE32PlusExceptionTable() {
		t.Fatal("expected MissingPE32PlusExceptionTable() = false when populated")
	}
	entries, err := fPop.Exceptions(data64)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].BeginAddress != 0x1000 || entries[1].UnwindData != 0x2020 {
		t.Fatalf("unexpected Exceptions: %+v", entries)
	}

	// Misaligned size returns ErrInvalidException.
	binary.LittleEndian.PutUint32(data64[dirOff+4:], 10)
	fBad, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fBad.Exceptions(data64); !errors.Is(err, pe.ErrInvalidException) {
		t.Fatalf("misaligned Exceptions err = %v, want ErrInvalidException", err)
	}
}
