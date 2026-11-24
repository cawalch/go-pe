package detect_test

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/detect"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestMitigations(t *testing.T) {
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
	binary.LittleEndian.PutUint64(data64[secOff+128:], 0x140006000)
	binary.LittleEndian.PutUint64(data64[secOff+136:], 12)
	binary.LittleEndian.PutUint16(data64[152+70:], pe.DllCharacteristicsGuardCF)

	fLC, err := pe.New(data64)
	if err != nil {
		t.Fatal(err)
	}
	mit, err := detect.Mitigations(fLC, data64)
	if err != nil || mit.Any() {
		t.Fatalf("expected clean Mitigations, got (%+v, %v)", mit, err)
	}

	anomData := testfixture.Minimal(true, 1)
	binary.LittleEndian.PutUint16(anomData[132+18:], pe.CharacteristicsExecutableImage|pe.CharacteristicsRelocsStripped)
	binary.LittleEndian.PutUint16(anomData[152+70:], pe.DllCharacteristicsGuardCF|pe.DllCharacteristicsDynamicBase)
	fAnom, err := pe.New(anomData)
	if err != nil {
		t.Fatal(err)
	}
	mitAnom, err := detect.Mitigations(fAnom, anomData)
	if err != nil {
		t.Fatal(err)
	}
	if !mitAnom.GuardCFMissingTable || !mitAnom.DynamicBaseRelocsStripped || !mitAnom.DynamicBaseEmptyRelocs {
		t.Fatalf("expected all mitigation anomalies, got %+v", mitAnom)
	}
}
