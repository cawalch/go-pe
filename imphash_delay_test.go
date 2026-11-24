package pe_test

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestDelayAwareImphash(t *testing.T) {
	impData := testfixture.Imports(true, 1, 4)
	fImp, err := pe.New(impData)
	if err != nil {
		t.Fatal(err)
	}
	ih, err := fImp.Imphash(impData)
	if err != nil {
		t.Fatal(err)
	}
	dih, err := fImp.DelayAwareImphash(impData)
	if err != nil {
		t.Fatal(err)
	}
	if ih != dih {
		t.Fatalf("DelayAwareImphash = %q, want %q when no delay imports", dih, ih)
	}

	delayData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(delayData)
	if err != nil {
		t.Fatal(err)
	}
	secOff := int(fMin.Sections[0].PointerToRawData)
	secRVA := fMin.Sections[0].VirtualAddress
	dirOff := 152 + 112 + pe.DataDirectoryDelayImport*8
	binary.LittleEndian.PutUint32(delayData[dirOff:], secRVA)
	binary.LittleEndian.PutUint32(delayData[dirOff+4:], 64)
	binary.LittleEndian.PutUint32(delayData[secOff+0:], pe.DelayImportAttrRVA)
	binary.LittleEndian.PutUint32(delayData[secOff+4:], secRVA+128)
	binary.LittleEndian.PutUint32(delayData[secOff+8:], secRVA+224)
	binary.LittleEndian.PutUint32(delayData[secOff+12:], secRVA+96)
	binary.LittleEndian.PutUint32(delayData[secOff+16:], secRVA+64)
	binary.LittleEndian.PutUint64(delayData[secOff+64:], uint64(secRVA+160))
	copy(delayData[secOff+128:], "kernel32.dll\x00")
	copy(delayData[secOff+162:], "VirtualAllocEx\x00")

	fDelay, err := pe.New(delayData)
	if err != nil {
		t.Fatal(err)
	}
	dih2, err := fDelay.DelayAwareImphash(delayData)
	if err != nil || dih2 == "" {
		t.Fatalf("DelayAwareImphash = (%q, %v), want non-empty", dih2, err)
	}
}
