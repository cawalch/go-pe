package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestLoadConfig(t *testing.T) {
	minData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(minData)
	if err != nil {
		t.Fatal(err)
	}
	if lc, err := fMin.LoadConfig(minData); err != nil || lc != nil {
		t.Fatalf("missing LoadConfig = (%+v, %v), want (nil, nil)", lc, err)
	}

	data64 := testfixture.Minimal(true, 1)
	f64, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	secOff := int(f64.Sections[0].PointerToRawData)
	secRVA := f64.Sections[0].VirtualAddress
	dirOff := 152 + 112 + pe.DataDirectoryLoadConfig*8
	binary.LittleEndian.PutUint32(data64[dirOff:], secRVA)
	binary.LittleEndian.PutUint32(data64[dirOff+4:], 256)
	binary.LittleEndian.PutUint32(data64[secOff:], 256)
	binary.LittleEndian.PutUint64(data64[secOff+88:], 0x140005000)
	binary.LittleEndian.PutUint64(data64[secOff+128:], 0x140006000)
	binary.LittleEndian.PutUint64(data64[secOff+136:], 12)
	binary.LittleEndian.PutUint32(data64[secOff+144:], 0x100)
	binary.LittleEndian.PutUint64(data64[secOff+200:], 0x140007000)

	fLC, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	lc, err := fLC.LoadConfig(data64)
	if err != nil {
		t.Fatal(err)
	}
	if !lc.HasGuardCF() || !lc.HasCHPE() || lc.HasSafeSEH() || lc.SecurityCookie != 0x140005000 {
		t.Fatalf("unexpected PE32+ LoadConfig: %+v", lc)
	}

	data32 := testfixture.Minimal(false, 1)
	f32, err := pe.New(data32)
	if err != nil {
		t.Fatal(err)
	}
	secOff32 := int(f32.Sections[0].PointerToRawData)
	secRVA32 := f32.Sections[0].VirtualAddress
	dirOff32 := 152 + 96 + pe.DataDirectoryLoadConfig*8
	binary.LittleEndian.PutUint32(data32[dirOff32:], secRVA32)
	binary.LittleEndian.PutUint32(data32[dirOff32+4:], 160)
	binary.LittleEndian.PutUint32(data32[secOff32:], 160)
	binary.LittleEndian.PutUint32(data32[secOff32+64:], 0x402000)
	binary.LittleEndian.PutUint32(data32[secOff32+68:], 5)
	binary.LittleEndian.PutUint32(data32[secOff32+124:], 0x403000) // CHPEMetadataPointer at 0x7C
	f32LC, err := pe.New(data32)
	if err != nil {
		t.Fatal(err)
	}
	lc32, err := f32LC.LoadConfig(data32)
	if err != nil || !lc32.HasSafeSEH() || !lc32.HasCHPE() || lc32.CHPEMetadataPointer != 0x403000 {
		t.Fatalf("unexpected PE32 LoadConfig: (%+v, %v)", lc32, err)
	}

	// MSVC-style legacy DataDirectory.Size=64 with full struct declaredSize=256.
	binary.LittleEndian.PutUint32(data64[dirOff+4:], 64)
	fLegacy, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	lcLegacy, err := fLegacy.LoadConfig(data64)
	if err != nil {
		t.Fatalf("legacy dir.Size=64 LoadConfig err = %v", err)
	}
	if !lcLegacy.HasGuardCF() || !lcLegacy.HasCHPE() || lcLegacy.SecurityCookie != 0x140005000 {
		t.Fatalf("legacy dir.Size=64 truncated fields: %+v", lcLegacy)
	}

	binary.LittleEndian.PutUint32(data64[dirOff+4:], 16)
	fBad, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fBad.LoadConfig(data64); !errors.Is(err, pe.ErrInvalidLoadConfig) {
		t.Fatalf("short LoadConfig err = %v, want ErrInvalidLoadConfig", err)
	}
}
