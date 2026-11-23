package pe_test

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestSectionAnomaliesAndFPGuards(t *testing.T) {
	// Baseline clean minimal PE: .text has EP, zeroed bytes -> no anomalies.
	clean := testfixture.Minimal(true, 2)
	fc, err := pe.New(clean)
	if err != nil {
		t.Fatal(err)
	}
	resClean, err := fc.SectionAnomalies(clean, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resClean.Any() {
		t.Fatalf("clean PE reported anomalies: %+v", resClean)
	}

	// FP guard 1: .data BSS (VirtualSize >> SizeOfRawData) without Execute must not trigger.
	// FP guard 2: .zdebug_* high-entropy section must be excluded by default.
	// FP guard 3: TimeDateStamp == 0 sets ZeroTimeDateStamp but not Any().
	fpData := testfixture.Minimal(true, 3)
	// Set TimeDateStamp = 0 (offset 132+4 = 136).
	binary.LittleEndian.PutUint32(fpData[136:], 0)
	secOff := 152 + 240
	// Section 1 (.data): non-exec, VirtualSize = 0x50000, SizeOfRawData = 0x200.
	binary.LittleEndian.PutUint32(fpData[secOff+40+8:], 0x50000)
	binary.LittleEndian.PutUint32(fpData[secOff+40+36:], pe.SectionCntInitializedData|pe.SectionMemRead|pe.SectionMemWrite)
	// Section 2: rename to .zdebug_i and fill with high-entropy bytes.
	copy(fpData[secOff+80:secOff+88], ".zdebug_")
	binary.LittleEndian.PutUint32(fpData[secOff+80+36:], pe.SectionCntInitializedData|pe.SectionMemRead)
	rawOff2 := binary.LittleEndian.Uint32(fpData[secOff+80+20:])
	for i := range 512 {
		fpData[int(rawOff2)+i] = byte(i)
	}

	fFP, err := pe.New(fpData)
	if err != nil {
		t.Fatal(err)
	}
	resFP, err := fFP.SectionAnomalies(fpData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resFP.ZeroTimeDateStamp {
		t.Fatal("expected ZeroTimeDateStamp = true")
	}
	if resFP.Any() {
		t.Fatalf("expected FP guards to suppress Any(), got %+v", resFP)
	}
	// With IncludeDebugSections: true, .zdebug_ should be flagged.
	resWithDbg, err := fFP.SectionAnomalies(fpData, &pe.AnomalyOptions{IncludeDebugSections: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resWithDbg.HighEntropySections) != 1 || resWithDbg.HighEntropySections[0].Index != 2 {
		t.Fatalf("expected .zdebug_ flagged with IncludeDebugSections, got %+v", resWithDbg.HighEntropySections)
	}

	// True positive: RWX, high entropy, EP in last writable section, 0xFFFFFFFF timestamp, high-entropy overlay.
	tpData := testfixture.Minimal(true, 2)
	binary.LittleEndian.PutUint32(tpData[136:], 0xffffffff)
	// Point EP to section 1 (0x2000).
	binary.LittleEndian.PutUint32(tpData[152+16:], 0x2000)
	// Make section 1 RWX and fill with high entropy.
	binary.LittleEndian.PutUint32(tpData[secOff+40+36:], pe.SectionMemRead|pe.SectionMemWrite|pe.SectionMemExecute)
	rawOff1 := binary.LittleEndian.Uint32(tpData[secOff+40+20:])
	for i := range 512 {
		tpData[int(rawOff1)+i] = byte(i)
	}
	ov := make([]byte, 512)
	for i := range ov {
		ov[i] = byte(i)
	}
	tpData = append(tpData, ov...)

	fTP, err := pe.New(tpData)
	if err != nil {
		t.Fatal(err)
	}
	resTP, err := fTP.SectionAnomalies(tpData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resTP.Any() || len(resTP.RWXSections) != 1 || len(resTP.HighEntropySections) != 1 ||
		!resTP.EntryPointInWritable || !resTP.EntryPointInLastSection ||
		!resTP.OverlayHighEntropy || !resTP.SuspiciousTimeDateStamp {
		t.Fatalf("expected all TP flags set, got %+v", resTP)
	}
}
