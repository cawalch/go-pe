package detect_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/detect"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestSectionsAndFPGuards(t *testing.T) {
	clean := testfixture.Minimal(true, 2)
	fc, err := pe.New(clean)
	if err != nil {
		t.Fatal(err)
	}
	resClean, err := detect.Sections(fc, clean, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resClean.Any() {
		t.Fatalf("clean PE reported anomalies: %+v", resClean)
	}

	fpData := testfixture.Minimal(true, 3)
	binary.LittleEndian.PutUint32(fpData[136:], 0)
	secOff := 152 + 240
	binary.LittleEndian.PutUint32(fpData[secOff+40+8:], 0x50000)
	binary.LittleEndian.PutUint32(fpData[secOff+40+36:], pe.SectionCntInitializedData|pe.SectionMemRead|pe.SectionMemWrite)
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
	resFP, err := detect.Sections(fFP, fpData, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resFP.ZeroTimeDateStamp {
		t.Fatal("expected ZeroTimeDateStamp = true")
	}
	if resFP.Any() {
		t.Fatalf("expected FP guards to suppress Any(), got %+v", resFP)
	}

	resWithDbg, err := detect.Sections(fFP, fpData, &detect.SectionOptions{IncludeDebugSections: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resWithDbg.HighEntropySections) != 1 || resWithDbg.HighEntropySections[0].Index != 2 {
		t.Fatalf("expected .zdebug_ flagged with IncludeDebugSections, got %+v", resWithDbg.HighEntropySections)
	}

	tpData := testfixture.Minimal(true, 2)
	binary.LittleEndian.PutUint32(tpData[136:], 0xffffffff)
	binary.LittleEndian.PutUint32(tpData[152+16:], 0x2000)
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
	resTP, err := detect.Sections(fTP, tpData, &detect.SectionOptions{
		VerificationTime: time.Unix(1700000000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resTP.Any() || len(resTP.RWXSections) != 1 || len(resTP.HighEntropySections) != 1 ||
		!resTP.EntryPointInWritable || !resTP.EntryPointInLastSection ||
		!resTP.OverlayHighEntropy || !resTP.SuspiciousTimeDateStamp {
		t.Fatalf("expected all TP flags set, got %+v", resTP)
	}
}
