package detect_test

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/detect"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestImportsAndExports(t *testing.T) {
	impData := testfixture.Imports(true, 1, 4)
	fImp, err := pe.New(impData)
	if err != nil {
		t.Fatal(err)
	}
	anom, err := detect.ImportsAndExports(fImp, impData)
	if err != nil || anom.Any() {
		t.Fatalf("clean Imports fixture reported anomalies: (%+v, %v)", anom, err)
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
	binary.LittleEndian.PutUint64(delayData[secOff+72:], uint64(secRVA+192))
	copy(delayData[secOff+128:], "kernel32.dll\x00")
	copy(delayData[secOff+162:], "VirtualAllocEx\x00")
	copy(delayData[secOff+194:], "CreateRemoteThread\x00")

	fDelay, err := pe.New(delayData)
	if err != nil {
		t.Fatal(err)
	}
	dAnom, err := detect.ImportsAndExports(fDelay, delayData)
	if err != nil {
		t.Fatal(err)
	}
	if len(dAnom.DelayLoadSensitiveAPIs) != 2 || len(dAnom.SuspiciousAPIClusters) == 0 {
		t.Fatalf("expected DelayLoadSensitiveAPIs + process_injection cluster, got %+v", dAnom)
	}

	hiEnt := testfixture.Minimal(true, 1)
	for i := range 512 {
		hiEnt[secOff+i] = byte(i)
	}
	fHi, err := pe.New(hiEnt)
	if err != nil {
		t.Fatal(err)
	}
	hiAnom, err := detect.ImportsAndExports(fHi, hiEnt)
	if err != nil || !hiAnom.MinimalIATWithHighEntropy {
		t.Fatalf("expected MinimalIATWithHighEntropy, got (%+v, %v)", hiAnom, err)
	}

	expData := testfixture.Minimal(true, 1)
	expDirOff := 152 + 112 + pe.DataDirectoryExport*8
	binary.LittleEndian.PutUint32(expData[expDirOff:], secRVA)
	binary.LittleEndian.PutUint32(expData[expDirOff+4:], 128)
	binary.LittleEndian.PutUint32(expData[secOff+12:], secRVA+80)
	binary.LittleEndian.PutUint32(expData[secOff+16:], 42)
	binary.LittleEndian.PutUint32(expData[secOff+20:], 1)
	binary.LittleEndian.PutUint32(expData[secOff+24:], 1)
	binary.LittleEndian.PutUint32(expData[secOff+28:], secRVA+40)
	binary.LittleEndian.PutUint32(expData[secOff+32:], secRVA+44)
	binary.LittleEndian.PutUint32(expData[secOff+36:], secRVA+48)
	binary.LittleEndian.PutUint32(expData[secOff+40:], secRVA+100)
	binary.LittleEndian.PutUint32(expData[secOff+44:], secRVA+60)
	binary.LittleEndian.PutUint16(expData[secOff+48:], 0)
	copy(expData[secOff+60:], "ReflectiveLoader\x00")
	copy(expData[secOff+80:], "evil.dll\x00")

	fExp, err := pe.New(expData)
	if err != nil {
		t.Fatal(err)
	}
	eAnom, err := detect.ImportsAndExports(fExp, expData)
	if err != nil {
		t.Fatal(err)
	}
	if !eAnom.UnusualOrdinalBase || !eAnom.ExportsWithoutDLLFlag || len(eAnom.ReflectiveDLLExports) != 1 {
		t.Fatalf("expected export/reflective anomalies, got %+v", eAnom)
	}
}
