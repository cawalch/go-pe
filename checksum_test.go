package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestComputeAndVerifyCheckSum(t *testing.T) {
	var nilFile *pe.File
	if _, err := nilFile.ComputeCheckSum(nil); !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil ComputeCheckSum err = %v, want ErrInvalidHeader", err)
	}
	if _, err := nilFile.VerifyCheckSum(nil); !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil VerifyCheckSum err = %v, want ErrInvalidHeader", err)
	}

	for _, is64 := range []bool{false, true} {
		// Include an odd trailing byte to exercise odd-length word padding.
		data := append(testfixture.Minimal(is64, 2), 0x7f)
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}

		sum, err := f.ComputeCheckSum(data)
		if err != nil {
			t.Fatalf("PE64=%t ComputeCheckSum: %v", is64, err)
		}
		if sum == 0 {
			t.Fatalf("PE64=%t ComputeCheckSum returned 0", is64)
		}

		// Header CheckSum is 0, so VerifyCheckSum must return false.
		ok, err := f.VerifyCheckSum(data)
		if err != nil || ok {
			t.Fatalf("PE64=%t VerifyCheckSum(zero header) = (%t, %v), want (false, nil)", is64, ok, err)
		}

		// Writing computed checksum into OptionalHeader.CheckSum must not change ComputeCheckSum
		// and must make VerifyCheckSum return true.
		checksumOff := int(f.DOSHeader.AddressOfNewEXEHeader) + 24 + 64
		binary.LittleEndian.PutUint32(data[checksumOff:], sum)
		f2, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		sum2, err := f2.ComputeCheckSum(data)
		if err != nil || sum2 != sum {
			t.Fatalf("PE64=%t ComputeCheckSum after header update = (%#x, %v), want %#x", is64, sum2, err, sum)
		}
		ok, err = f2.VerifyCheckSum(data)
		if err != nil || !ok {
			t.Fatalf("PE64=%t VerifyCheckSum = (%t, %v), want (true, nil)", is64, ok, err)
		}

		// Truncated data must fail with ErrOutOfBounds.
		if _, err := f2.ComputeCheckSum(data[:len(data)-1]); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("PE64=%t truncated ComputeCheckSum err = %v, want ErrOutOfBounds", is64, err)
		}
	}
}

func TestOverlayHelpers(t *testing.T) {
	var nilFile *pe.File
	if off, ok := nilFile.OverlayOffset(); ok || off != 0 {
		t.Fatalf("nil OverlayOffset = (%d, %t)", off, ok)
	}
	if _, _, err := nilFile.Overlay(nil); !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil Overlay err = %v, want ErrInvalidHeader", err)
	}

	full := testfixture.Minimal(true, 2)
	f, err := pe.New(full)
	if err != nil {
		t.Fatal(err)
	}
	if off, ok := f.OverlayOffset(); ok || off != 0 {
		t.Fatalf("no-overlay OverlayOffset = (%d, %t)", off, ok)
	}
	if ov, ok, err := f.Overlay(full); err != nil || ok || ov != nil {
		t.Fatalf("no-overlay Overlay = (%v, %t, %v), want (nil, false, nil)", ov, ok, err)
	}

	want := []byte("OVERLAY-PAYLOAD")
	withOverlay := append(append([]byte(nil), full...), want...)
	of, err := pe.New(withOverlay)
	if err != nil {
		t.Fatal(err)
	}
	off, ok := of.OverlayOffset()
	if !ok || off != int64(len(full)) {
		t.Fatalf("OverlayOffset = (%d, %t), want (%d, true)", off, ok, len(full))
	}
	ov, ok, err := of.Overlay(withOverlay)
	if err != nil || !ok || !bytes.Equal(ov, want) {
		t.Fatalf("Overlay = (%q, %t, %v), want (%q, true, nil)", ov, ok, err, want)
	}
	// Mutating input must not mutate returned overlay slice.
	withOverlay[len(withOverlay)-1] ^= 0xff
	if !bytes.Equal(ov, want) {
		t.Fatalf("Overlay aliased caller buffer")
	}
}
