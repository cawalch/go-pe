package pe_test

import (
	"crypto"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestFileSizeDeclaredExtentAndTruncation(t *testing.T) {
	var nilFile *pe.File
	if nilFile.FileSize() != 0 {
		t.Fatalf("nil FileSize = %d", nilFile.FileSize())
	}
	if ext, ok := nilFile.DeclaredExtent(); ok || ext != 0 {
		t.Fatalf("nil DeclaredExtent = (%d, %t)", ext, ok)
	}
	if nilFile.InputTruncated() {
		t.Fatal("nil InputTruncated = true")
	}

	var zeroFile pe.File
	if ext, ok := zeroFile.DeclaredExtent(); ok || ext != 0 || zeroFile.InputTruncated() {
		t.Fatalf("zero File extent = (%d, %t, %t)", ext, ok, zeroFile.InputTruncated())
	}

	for _, is64 := range []bool{false, true} {
		// Minimal PE has 2 sections of 512 bytes starting after 512-byte header (total 1536).
		full := testfixture.Minimal(is64, 2)
		f, err := pe.New(full)
		if err != nil {
			t.Fatal(err)
		}
		if f.FileSize() != int64(len(full)) {
			t.Fatalf("FileSize = %d, want %d", f.FileSize(), len(full))
		}
		ext, ok := f.DeclaredExtent()
		if !ok || ext != uint64(len(full)) || f.InputTruncated() {
			t.Fatalf("full PE64=%t extent=(%d, %t) truncated=%t want=%d", is64, ext, ok, f.InputTruncated(), len(full))
		}

		// Overlay bytes do not mark the input truncated.
		withOverlay := append(append([]byte(nil), full...), []byte("OVERLAY")...)
		of, err := pe.New(withOverlay)
		if err != nil {
			t.Fatal(err)
		}
		if ext, ok := of.DeclaredExtent(); !ok || ext != uint64(len(full)) || of.FileSize() != int64(len(withOverlay)) || of.InputTruncated() {
			t.Fatalf("overlay PE64=%t extent=(%d, %t) size=%d truncated=%t", is64, ext, ok, of.FileSize(), of.InputTruncated())
		}

		// Truncated prefix parses headers, clamps RVAToOffset, and sets InputTruncated=true.
		prefix := full[:1024]
		tf, err := pe.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if tf.FileSize() != 1024 {
			t.Fatalf("prefix FileSize = %d", tf.FileSize())
		}
		if ext, ok := tf.DeclaredExtent(); !ok || ext != 1536 || !tf.InputTruncated() {
			t.Fatalf("prefix extent=(%d, %t) truncated=%t", ext, ok, tf.InputTruncated())
		}
		if _, ok := tf.RVAToOffset(0x2010); ok {
			t.Fatal("truncated prefix unexpectedly mapped second section RVA")
		}

		// NewWithLength with truthful full length unblocks RVAToOffset / OffsetToRVA
		// while payload readers remain safely bounded by len(prefix).
		sf, err := pe.NewWithLength(prefix, int64(len(full)))
		if err != nil {
			t.Fatal(err)
		}
		if sf.FileSize() != int64(len(full)) || sf.InputTruncated() {
			t.Fatalf("stream prefix size=%d truncated=%t", sf.FileSize(), sf.InputTruncated())
		}
		if off, ok := sf.RVAToOffset(0x2010); !ok || off != 0x410 {
			t.Fatalf("stream RVAToOffset(0x2010) = (%#x, %t), want (0x410, true)", off, ok)
		}
		if rva, ok := sf.OffsetToRVA(0x410); !ok || rva != 0x2010 {
			t.Fatalf("stream OffsetToRVA(0x410) = (%#x, %t), want (0x2010, true)", rva, ok)
		}
		if _, err := sf.AuthenticodeDigest(prefix, crypto.SHA256); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("AuthenticodeDigest on shorter prefix = %v, want ErrOutOfBounds", err)
		}
	}

	// Certificate directory extent contributes to DeclaredExtent and InputTruncated.
	signed := testfixture.Certificates(false, testfixture.CertificateSpec{Revision: 0x0200, Type: 2, Payload: make([]byte, 16)})
	sf, err := pe.New(signed)
	if err != nil {
		t.Fatal(err)
	}
	wantSignedExt, ok := sf.DeclaredExtent()
	if !ok || wantSignedExt != uint64(len(signed)) || sf.InputTruncated() {
		t.Fatalf("signed extent=(%d, %t) len=%d truncated=%t", wantSignedExt, ok, len(signed), sf.InputTruncated())
	}
	cutSigned := signed[:len(signed)-4]
	csf, err := pe.New(cutSigned)
	if err != nil {
		t.Fatal(err)
	}
	if ext, ok := csf.DeclaredExtent(); !ok || ext != wantSignedExt || !csf.InputTruncated() {
		t.Fatalf("cut signed extent=(%d, %t) want=%d truncated=%t", ext, ok, wantSignedExt, csf.InputTruncated())
	}

	// Virtual-only sections (SizeOfRawData == 0) do not expand file extent,
	// while high uint32 section bounds accumulate cleanly in uint64.
	full := testfixture.Minimal(true, 2)
	secOff := 152 + 240
	// Zero out SizeOfRawData on section 1 (.data) while keeping a non-zero PointerToRawData.
	binary.LittleEndian.PutUint32(full[secOff+40+16:], 0)
	binary.LittleEndian.PutUint32(full[secOff+40+20:], 0x500000)
	bss, err := pe.New(full)
	if err != nil {
		t.Fatal(err)
	}
	if ext, ok := bss.DeclaredExtent(); !ok || ext != 1024 || bss.InputTruncated() {
		t.Fatalf("zero-raw section inflated extent: (%d, %t) truncated=%t", ext, ok, bss.InputTruncated())
	}

	// Reject negative or shorter stream lengths in NewWithLength.
	if f, err := pe.NewWithLength(full, int64(len(full)-1)); f != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("shorter NewWithLength = (%v, %v), want ErrInvalidHeader", f, err)
	}
	if f, err := pe.NewWithLength(full, -1); f != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("negative NewWithLength = (%v, %v), want ErrInvalidHeader", f, err)
	}

	// Large raw offset + size > math.MaxUint32 stays exact in uint64.
	binary.LittleEndian.PutUint32(full[secOff+40+16:], 0x2000)
	binary.LittleEndian.PutUint32(full[secOff+40+20:], math.MaxUint32)
	huge, err := pe.New(full)
	if err != nil {
		t.Fatal(err)
	}
	if ext, ok := huge.DeclaredExtent(); !ok || ext != uint64(math.MaxUint32)+0x2000 || !huge.InputTruncated() {
		t.Fatalf("64-bit declared extent = (%#x, %t) truncated=%t", ext, ok, huge.InputTruncated())
	}
}
