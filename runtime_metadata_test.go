package pe_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestDetectRuntimeGoRustNim(t *testing.T) {
	// Clean minimal PE -> RuntimeUnknown.
	clean := testfixture.Minimal(true, 1)
	fClean, err := pe.New(clean)
	if err != nil {
		t.Fatal(err)
	}
	rtClean, err := fClean.DetectRuntime(clean)
	if err != nil || rtClean.Language != pe.RuntimeUnknown {
		t.Fatalf("clean DetectRuntime = (%+v, %v), want RuntimeUnknown", rtClean, err)
	}

	// Go runtime with inline buildinfo + pclntab magic.
	goData := testfixture.Minimal(true, 1)
	secOff := int(fClean.Sections[0].PointerToRawData)
	copy(goData[secOff:], "\xff Go buildinf:")
	goData[secOff+15] = 2 // inline flag
	ver := "go1.26.0"
	goData[secOff+32] = byte(len(ver))
	copy(goData[secOff+33:], ver)
	copy(goData[secOff+64:], []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00})

	fGo, err := pe.New(goData)
	if err != nil {
		t.Fatal(err)
	}
	rtGo, err := fGo.DetectRuntime(goData)
	if err != nil || rtGo.Language != pe.RuntimeGo || rtGo.Go == nil ||
		!rtGo.Go.HasBuildInfo || rtGo.Go.Version != "go1.26.0" || !rtGo.Go.HasGoPclntab || rtGo.Go.PossibleGarble {
		t.Fatalf("unexpected Go DetectRuntime: (%+v, %v)", rtGo, err)
	}

	// Go garble-like: pclntab + runtime.main present, but buildinf stripped.
	garbleData := testfixture.Minimal(true, 1)
	copy(garbleData[secOff:], []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00})
	copy(garbleData[secOff+16:], "runtime.main")
	fGarble, err := pe.New(garbleData)
	if err != nil {
		t.Fatal(err)
	}
	rtGarble, err := fGarble.DetectRuntime(garbleData)
	if err != nil || rtGarble.Language != pe.RuntimeGo || !rtGarble.Go.PossibleGarble {
		t.Fatalf("expected PossibleGarble=true, got (%+v, %v)", rtGarble, err)
	}

	// Rust runtime markers.
	rustData := testfixture.Minimal(true, 1)
	copy(rustData[secOff:], `panicked at library\core\src\panicking.rs`)
	fRust, err := pe.New(rustData)
	if err != nil {
		t.Fatal(err)
	}
	rtRust, err := fRust.DetectRuntime(rustData)
	if err != nil || rtRust.Language != pe.RuntimeRust || len(rtRust.RustMarkers) < 2 {
		t.Fatalf("unexpected Rust DetectRuntime: (%+v, %v)", rtRust, err)
	}

	// Nim runtime markers.
	nimData := testfixture.Minimal(true, 1)
	copy(nimData[secOff:], "nimMain stdlib_system.nim @mmain.nim.c")
	fNim, err := pe.New(nimData)
	if err != nil {
		t.Fatal(err)
	}
	rtNim, err := fNim.DetectRuntime(nimData)
	if err != nil || rtNim.Language != pe.RuntimeNim || len(rtNim.NimMarkers) < 3 {
		t.Fatalf("unexpected Nim DetectRuntime: (%+v, %v)", rtNim, err)
	}
}
