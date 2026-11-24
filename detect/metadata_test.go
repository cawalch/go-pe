package detect_test

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/detect"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRichAndPDB(t *testing.T) {
	richData, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{{ToolID: 0x0104, Version: 0x725d, Count: 2}},
	})
	fRich, err := pe.New(richData)
	if err != nil {
		t.Fatal(err)
	}
	rAnom, err := detect.Rich(fRich, richData)
	if err != nil || rAnom.Any() {
		t.Fatalf("valid RichPE reported anomalies: (%+v, %v)", rAnom, err)
	}

	// MSVC-linked Windows Rust binaries legitimately have a Rich header.
	rustRich, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{{ToolID: 0x0104, Version: 0x725d, Count: 2}},
	})
	fRustRich, err := pe.New(rustRich)
	if err != nil {
		t.Fatal(err)
	}
	copy(rustRich[fRustRich.Sections[0].PointerToRawData:], `panicked at library\core\src\panicking.rs`)
	rRustAnom, err := detect.Rich(fRustRich, rustRich)
	if err != nil || rRustAnom.SpoofedOnNonMSVC {
		t.Fatalf("MSVC Rust binary should not trigger SpoofedOnNonMSVC: (%+v, %v)", rRustAnom, err)
	}

	badRich, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries:      []testfixture.RichEntrySpec{{ToolID: 0x0104, Version: 0x725d, Count: 2}},
		Padding:      [3]uint32{1, 0, 0},
		UseCustomKey: true,
		CustomKey:    0x12345678,
	})
	eLfanew := binary.LittleEndian.Uint32(badRich[0x3c:])
	badRich[eLfanew+24+2] = 0
	badRich[eLfanew+24+3] = 0
	fBadRich, err := pe.New(badRich)
	if err != nil {
		t.Fatal(err)
	}
	secOff := int(fBadRich.Sections[0].PointerToRawData)
	copy(badRich[secOff:], "\xff Go buildinf:")

	rBadAnom, err := detect.Rich(fBadRich, badRich)
	if err != nil {
		t.Fatal(err)
	}
	if !rBadAnom.InvalidChecksum || !rBadAnom.NonZeroPadding || !rBadAnom.LinkerVersionMismatch || !rBadAnom.SpoofedOnNonMSVC {
		t.Fatalf("expected all RichAnomalies, got %+v", rBadAnom)
	}

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
	copy(pdbData[secOff2+32+24:], pdbPath)

	fPDB, err := pe.New(pdbData)
	if err != nil {
		t.Fatal(err)
	}
	pAnom, err := detect.PDB(fPDB, pdbData)
	if err != nil {
		t.Fatal(err)
	}
	if !pAnom.AllZeroGUID || !pAnom.ZeroAge || !pAnom.NonUTF8Path || !pAnom.ControlCharsInPath || !pAnom.DeveloperPathLeak {
		t.Fatalf("expected all PDBAnomalies, got %+v", pAnom)
	}
}
