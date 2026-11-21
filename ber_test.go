package pe

import (
	"bytes"
	"testing"
)

func TestBERToDERNestedIndefiniteAndHighTag(t *testing.T) {
	// Build 128 levels of indefinite-length SEQUENCE wrapping a 200-byte OCTET STRING
	// plus a high-tag (tag 128: 0x1f 0x81 0x00) primitive element and trailing NULs.
	payload := bytes.Repeat([]byte{0xab}, 200)
	inner := make([]byte, 0, 4+len(payload)+5)
	inner = append(inner, 0x04, 0x81, byte(len(payload)))
	inner = append(inner, payload...)
	inner = append(inner, 0x1f, 0x81, 0x00, 0x01, 0x42)

	const depth = 128
	ber := make([]byte, 0, depth*4+len(inner)+8)
	for range depth {
		ber = append(ber, 0x30, 0x80)
	}
	ber = append(ber, inner...)
	for range depth {
		ber = append(ber, 0x00, 0x00)
	}
	ber = append(ber, 0x00, 0x00, 0x00) // trailing NUL padding

	got, err := berToDER(ber)
	if err != nil {
		t.Fatalf("berToDER failed: %v", err)
	}

	// Verify canonical DER encoding from the inside out.
	want := inner
	for range depth {
		var hdr [6]byte
		hdr[0] = 0x30
		n := encodeDERLength((*[5]byte)(hdr[1:6]), len(want))
		next := make([]byte, 0, 1+n+len(want))
		next = append(next, hdr[:1+n]...)
		next = append(next, want...)
		want = next
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("berToDER output mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

func TestRVASpanSinglePassClamping(t *testing.T) {
	data := buildMinimalPE(2)
	f, err := New(data)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Header RVA clamps at SizeOfHeaders.
	hdrSpan, err := f.rvaSpan(data, 0x40)
	if err != nil {
		t.Fatalf("rvaSpan(header): %v", err)
	}
	if want := int(f.OptionalHeader.SizeOfHeaders - 0x40); len(hdrSpan) != want {
		t.Fatalf("header span len = %d, want %d", len(hdrSpan), want)
	}

	// Overlapping earlier section (.text at 0x1000..0x2000, .data at 0x1800..0x2800):
	// if .text is narrowed to 0x1000..0x1200, an RVA in 0x1800..0x2000 must clamp
	// before .data or match .data; specifically, an RVA at 0x1700 in a section
	// declared after .data (e.g. .text at 0x1900, .data at 0x1000..0x2000) clamps
	// at .text's VA.
	f.Sections[0].VirtualAddress = 0x1900
	f.Sections[0].VirtualSize = 0x200
	f.Sections[0].SizeOfRawData = 0x200
	f.Sections[1].VirtualAddress = 0x1000
	f.Sections[1].VirtualSize = 0x1000
	f.Sections[1].SizeOfRawData = 0x200

	// RVA 0x1850 is in .data (index 1), which has raw size 0x200 (to 0x1200) —
	// test raw-covered RVA 0x1100 which must clamp at .text's VA (0x1900) or raw end (0x1200).
	span, err := f.rvaSpan(data, 0x1100)
	if err != nil {
		t.Fatalf("rvaSpan(0x1100): %v", err)
	}
	if len(span) != 0x100 {
		t.Fatalf("rvaSpan(0x1100) len = %d, want 256", len(span))
	}

	// Now make .data raw size 0x1000 and expand backing buffer so .text at 0x1900 is the tighter clamp.
	bigData := make([]byte, 0x2000)
	copy(bigData, data)
	f.Sections[1].SizeOfRawData = 0x1000
	f.Sections[1].PointerToRawData = 0x200
	f.fileSize = int64(len(bigData))
	span, err = f.rvaSpan(bigData, 0x1100)
	if err != nil {
		t.Fatalf("rvaSpan(0x1100) clamped by earlier section: %v", err)
	}
	if len(span) != 0x800 {
		t.Fatalf("rvaSpan(0x1100) len = %d, want %d", len(span), 0x800)
	}
}
