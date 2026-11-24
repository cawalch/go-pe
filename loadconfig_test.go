package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestLoadConfigAndMitigationAnomalies(t *testing.T) {
	// Missing LoadConfig returns nil, nil.
	minData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(minData)
	if err != nil {
		t.Fatal(err)
	}
	if lc, err := fMin.LoadConfig(minData); err != nil || lc != nil {
		t.Fatalf("missing LoadConfig = (%+v, %v), want (nil, nil)", lc, err)
	}

	// PE32+ LoadConfig with GuardCF + CHPE.
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
	binary.LittleEndian.PutUint32(data64[secOff:], 256) // Size
	binary.LittleEndian.PutUint64(data64[secOff+88:], 0x140005000)
	binary.LittleEndian.PutUint64(data64[secOff+128:], 0x140006000) // GuardCFFunctionTable
	binary.LittleEndian.PutUint64(data64[secOff+136:], 12)          // GuardCFFunctionCount
	binary.LittleEndian.PutUint32(data64[secOff+144:], 0x100)
	binary.LittleEndian.PutUint64(data64[secOff+200:], 0x140007000) // CHPEMetadataPointer

	// Also set DllCharacteristicsGuardCF (without DynamicBase).
	binary.LittleEndian.PutUint16(data64[152+70:], pe.DllCharacteristicsGuardCF)

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
	mit, err := fLC.MitigationAnomalies(data64)
	if err != nil || mit.Any() {
		t.Fatalf("expected clean MitigationAnomalies, got (%+v, %v)", mit, err)
	}

	// PE32 LoadConfig with SafeSEH.
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
	binary.LittleEndian.PutUint32(data32[secOff32+64:], 0x402000) // SEHandlerTable
	binary.LittleEndian.PutUint32(data32[secOff32+68:], 5)        // SEHandlerCount
	f32LC, err := pe.New(data32)
	if err != nil {
		t.Fatal(err)
	}
	lc32, err := f32LC.LoadConfig(data32)
	if err != nil || !lc32.HasSafeSEH() {
		t.Fatalf("unexpected PE32 LoadConfig: (%+v, %v)", lc32, err)
	}

	// Mitigation anomalies: GuardCF without table + DynamicBase with RelocsStripped & empty relocs.
	anomData := testfixture.Minimal(true, 1)
	binary.LittleEndian.PutUint16(anomData[132+18:], pe.CharacteristicsExecutableImage|pe.CharacteristicsRelocsStripped)
	binary.LittleEndian.PutUint16(anomData[152+70:], pe.DllCharacteristicsGuardCF|pe.DllCharacteristicsDynamicBase)
	fAnom, err := pe.New(anomData)
	if err != nil {
		t.Fatal(err)
	}
	mitAnom, err := fAnom.MitigationAnomalies(anomData)
	if err != nil {
		t.Fatal(err)
	}
	if !mitAnom.GuardCFMissingTable || !mitAnom.DynamicBaseRelocsStripped || !mitAnom.DynamicBaseEmptyRelocs {
		t.Fatalf("expected all mitigation anomalies, got %+v", mitAnom)
	}

	// Short LoadConfig directory returns ErrInvalidLoadConfig.
	binary.LittleEndian.PutUint32(data64[dirOff+4:], 16)
	fBad, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fBad.LoadConfig(data64); !errors.Is(err, pe.ErrInvalidLoadConfig) {
		t.Fatalf("short LoadConfig err = %v, want ErrInvalidLoadConfig", err)
	}
}
