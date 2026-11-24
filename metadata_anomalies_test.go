package pe_test

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRichAndPDBAnomalies(t *testing.T) {
	// Valid Rich header -> no anomalies.
	richData, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{{ToolID: 0x0104, Version: 0x725d, Count: 2}},
	})
	fRich, err := pe.New(richData)
	if err != nil {
		t.Fatal(err)
	}
	rAnom, err := fRich.RichAnomalies(richData)
	if err != nil || rAnom.Any() {
		t.Fatalf("valid RichPE reported anomalies: (%+v, %v)", rAnom, err)
	}

	// Tampered Rich header (checksum mismatch) + non-zero padding + zero linker version + Go runtime.
	badRich, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries:      []testfixture.RichEntrySpec{{ToolID: 0x0104, Version: 0x725d, Count: 2}},
		Padding:      [3]uint32{1, 0, 0},
		UseCustomKey: true,
		CustomKey:    0x12345678,
	})
	// Set MajorLinkerVersion = 0, MinorLinkerVersion = 0 (offset e_lfanew+24+2).
	eLfanew := binary.LittleEndian.Uint32(badRich[0x3c:])
	badRich[eLfanew+24+2] = 0
	badRich[eLfanew+24+3] = 0
	fBadRich, err := pe.New(badRich)
	if err != nil {
		t.Fatal(err)
	}
	secOff := int(fBadRich.Sections[0].PointerToRawData)
	copy(badRich[secOff:], "\xff Go buildinf:")

	rBadAnom, err := fBadRich.RichAnomalies(badRich)
	if err != nil {
		t.Fatal(err)
	}
	if !rBadAnom.InvalidChecksum || !rBadAnom.NonZeroPadding || !rBadAnom.LinkerVersionMismatch || !rBadAnom.SpoofedOnNonMSVC {
		t.Fatalf("expected all RichAnomalies, got %+v", rBadAnom)
	}

	// CodeView PDB anomalies: all-zero GUID, age 0, developer path leak, non-UTF8/control chars.
	pdbData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(pdbData)
	if err != nil {
		t.Fatal(err)
	}
	secOff2 := int(fMin.Sections[0].PointerToRawData)
	secRVA2 := fMin.Sections[0].VirtualAddress
	dbgDirOff := 152 + 112 + pe.DataDirectoryDebug*8
	pdbPath := "C:\\Users\\alice\\Desktop\\implant.pdb\x01\xff\x00"
	cvSize := 24 + len(pdbPath)
	binary.LittleEndian.PutUint32(pdbData[dbgDirOff:], secRVA2)
	binary.LittleEndian.PutUint32(pdbData[dbgDirOff+4:], 28)
	binary.LittleEndian.PutUint32(pdbData[secOff2+12:], pe.DebugTypeCodeView)
	binary.LittleEndian.PutUint32(pdbData[secOff2+16:], uint32(cvSize))
	binary.LittleEndian.PutUint32(pdbData[secOff2+20:], secRVA2+32)
	binary.LittleEndian.PutUint32(pdbData[secOff2+24:], uint32(secOff2+32))

	binary.LittleEndian.PutUint32(pdbData[secOff2+32:], pe.CodeViewSignatureRSDS)
	// GUID bytes [4:20] left all zero, Age [20:24] left 0.
	copy(pdbData[secOff2+32+24:], pdbPath)

	fPDB, err := pe.New(pdbData)
	if err != nil {
		t.Fatal(err)
	}
	pAnom, err := fPDB.PDBAnomalies(pdbData)
	if err != nil {
		t.Fatal(err)
	}
	if !pAnom.AllZeroGUID || !pAnom.ZeroAge || !pAnom.NonUTF8Path || !pAnom.ControlCharsInPath || !pAnom.DeveloperPathLeak {
		t.Fatalf("expected all PDBAnomalies, got %+v", pAnom)
	}
}
