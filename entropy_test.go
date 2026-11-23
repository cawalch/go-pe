package pe_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestShannonEntropy(t *testing.T) {
	if got := pe.ShannonEntropy(nil); got != 0 {
		t.Fatalf("ShannonEntropy(nil) = %v, want 0", got)
	}
	if got := pe.ShannonEntropy(make([]byte, 1024)); got != 0 {
		t.Fatalf("ShannonEntropy(zeros) = %v, want 0", got)
	}
	uniform := make([]byte, 256*4)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	if got := pe.ShannonEntropy(uniform); math.Abs(got-8.0) > 1e-9 {
		t.Fatalf("ShannonEntropy(uniform) = %v, want 8.0", got)
	}
}

func TestSectionDataAndEntropy(t *testing.T) {
	data := testfixture.Minimal(true, 2)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}

	sec0 := f.Sections[0]
	for i := range int(sec0.SizeOfRawData) {
		data[int(sec0.PointerToRawData)+i] = byte(i)
	}

	gotBytes, err := f.SectionData(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotBytes) != int(sec0.SizeOfRawData) {
		t.Fatalf("SectionData len = %d, want %d", len(gotBytes), sec0.SizeOfRawData)
	}
	// Mutating returned slice must not affect caller buffer.
	gotBytes[0] ^= 0xff
	if data[sec0.PointerToRawData] == gotBytes[0] {
		t.Fatal("SectionData aliased caller buffer")
	}

	ent, err := f.SectionEntropy(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(ent-8.0) > 1e-9 {
		t.Fatalf("SectionEntropy(0) = %v, want 8.0", ent)
	}

	ent1, err := f.SectionEntropy(data, 1)
	if err != nil || ent1 != 0 {
		t.Fatalf("SectionEntropy(1) = (%v, %v), want (0, nil)", ent1, err)
	}

	if _, err := f.SectionData(data, -1); !errors.Is(err, pe.ErrOutOfBounds) {
		t.Fatalf("SectionData(-1) err = %v, want ErrOutOfBounds", err)
	}
	if _, err := f.SectionData(data, 2); !errors.Is(err, pe.ErrOutOfBounds) {
		t.Fatalf("SectionData(2) err = %v, want ErrOutOfBounds", err)
	}

	// Overlay entropy check.
	if _, ok, err := f.OverlayEntropy(data); err != nil || ok {
		t.Fatalf("OverlayEntropy(no overlay) = (%v, %v), want (false, nil)", ok, err)
	}
	ov := make([]byte, 512)
	for i := range ov {
		ov[i] = byte(i)
	}
	withOv := append(bytes.Clone(data), ov...)
	fOv, err := pe.New(withOv)
	if err != nil {
		t.Fatal(err)
	}
	ovEnt, ok, err := fOv.OverlayEntropy(withOv)
	if err != nil || !ok || math.Abs(ovEnt-8.0) > 1e-9 {
		t.Fatalf("OverlayEntropy = (%v, %v, %v), want (8.0, true, nil)", ovEnt, ok, err)
	}
}
