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

	// ARM64 uses 8-byte RUNTIME_FUNCTION entries (BeginAddress + UnwindData).
	armData := testfixture.Minimal(true, 1)
	binary.LittleEndian.PutUint16(armData[132:], pe.MachineARM64)
	fArmInit, err := pe.New(armData)
	if err != nil {
		t.Fatal(err)
	}
	armSecOff := int(fArmInit.Sections[0].PointerToRawData)
	armSecRVA := fArmInit.Sections[0].VirtualAddress
	binary.LittleEndian.PutUint32(armData[dirOff:], armSecRVA)
	binary.LittleEndian.PutUint32(armData[dirOff+4:], 16) // 2 x 8-byte entries
	binary.LittleEndian.PutUint32(armData[armSecOff:], 0x1000)
	binary.LittleEndian.PutUint32(armData[armSecOff+4:], 0x2001)
	binary.LittleEndian.PutUint32(armData[armSecOff+8:], 0x1100)
	binary.LittleEndian.PutUint32(armData[armSecOff+12:], 0x2021)

	fArm, err := pe.New(armData)
	if err != nil {
		t.Fatal(err)
	}
	armEntries, err := fArm.Exceptions(armData)
	if err != nil {
		t.Fatalf("ARM64 Exceptions err = %v", err)
	}
	if len(armEntries) != 2 || armEntries[0].BeginAddress != 0x1000 || armEntries[0].EndAddress != 0 || armEntries[1].UnwindData != 0x2021 {
		t.Fatalf("unexpected ARM64 Exceptions: %+v", armEntries)
	}
}
