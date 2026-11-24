package detect_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/detect"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRuntimeGoRustNim(t *testing.T) {
	clean := testfixture.Minimal(true, 1)
	fClean, err := pe.New(clean)
	if err != nil {
		t.Fatal(err)
	}
	rtClean, err := detect.Runtime(fClean, clean)
	if err != nil || rtClean.Language != detect.RuntimeUnknown {
		t.Fatalf("clean Runtime = (%+v, %v), want RuntimeUnknown", rtClean, err)
	}

	goData := testfixture.Minimal(true, 1)
	secOff := int(fClean.Sections[0].PointerToRawData)
	copy(goData[secOff:], "\xff Go buildinf:")
	goData[secOff+15] = 2
	ver := "go1.26.0"
	goData[secOff+32] = byte(len(ver))
	copy(goData[secOff+33:], ver)
	copy(goData[secOff+64:], []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00})

	fGo, err := pe.New(goData)
	if err != nil {
		t.Fatal(err)
	}
	rtGo, err := detect.Runtime(fGo, goData)
	if err != nil || rtGo.Language != detect.RuntimeGo || rtGo.Go == nil ||
		!rtGo.Go.HasBuildInfo || rtGo.Go.Version != "go1.26.0" || !rtGo.Go.HasGoPclntab || rtGo.Go.PossibleGarble {
		t.Fatalf("unexpected Go Runtime: (%+v, %v)", rtGo, err)
	}

	garbleData := testfixture.Minimal(true, 1)
	copy(garbleData[secOff:], []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00})
	copy(garbleData[secOff+16:], "runtime.main")
	fGarble, err := pe.New(garbleData)
	if err != nil {
		t.Fatal(err)
	}
	rtGarble, err := detect.Runtime(fGarble, garbleData)
	if err != nil || rtGarble.Language != detect.RuntimeGo || !rtGarble.Go.PossibleGarble {
		t.Fatalf("expected PossibleGarble=true, got (%+v, %v)", rtGarble, err)
	}

	rustData := testfixture.Minimal(true, 1)
	copy(rustData[secOff:], `panicked at library\core\src\panicking.rs`)
	fRust, err := pe.New(rustData)
	if err != nil {
		t.Fatal(err)
	}
	rtRust, err := detect.Runtime(fRust, rustData)
	if err != nil || rtRust.Language != detect.RuntimeRust || len(rtRust.RustMarkers) < 2 {
		t.Fatalf("unexpected Rust Runtime: (%+v, %v)", rtRust, err)
	}

	nimData := testfixture.Minimal(true, 1)
	copy(nimData[secOff:], "nimMain stdlib_system.nim @mmain.nim.c")
	fNim, err := pe.New(nimData)
	if err != nil {
		t.Fatal(err)
	}
	rtNim, err := detect.Runtime(fNim, nimData)
	if err != nil || rtNim.Language != detect.RuntimeNim || len(rtNim.NimMarkers) < 3 {
		t.Fatalf("unexpected Nim Runtime: (%+v, %v)", rtNim, err)
	}
}
