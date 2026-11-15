package pe_test

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestAuthenticodeDigestAlgorithmsAndRanges(t *testing.T) {
	algs := []struct {
		alg crypto.Hash
		new func() hash.Hash
	}{
		{alg: crypto.MD5, new: md5.New},
		{alg: crypto.SHA1, new: sha1.New},
		{alg: crypto.SHA256, new: sha256.New},
		{alg: crypto.SHA384, new: sha512.New384},
		{alg: crypto.SHA512, new: sha512.New},
	}

	for _, is64 := range []bool{false, true} {
		name := "PE32"
		if is64 {
			name = "PE32Plus"
		}
		t.Run(name, func(t *testing.T) {
			unsigned := testfixture.Minimal(is64, 2)
			// Fill sections and header stub with non-zero deterministic bytes.
			copy(unsigned[0x40:], []byte("DOS-STUB-DATA-FOR-AUTHENTICODE-HASHING"))
			for i := 0x400; i < len(unsigned); i++ {
				unsigned[i] = byte(i*17 + 3)
			}

			// Set CheckSum before signing: excluded from Authenticode digest.
			optOffset := 132 + 20
			binary.LittleEndian.PutUint32(unsigned[optOffset+64:], 0xdeadbeef)

			fu, err := pe.New(unsigned)
			if err != nil {
				t.Fatalf("New(unsigned) error = %v", err)
			}

			// Build signed copy by appending a WIN_CERTIFICATE table and setting DataDirectory[4].
			blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
				CommonName:         "Digest Test Signer",
				IncludeCertificate: true,
			})
			signed := appendCertificateTable(unsigned, is64, []byte("pre-cert-overlay-bytes"), pe.CertificateTypePKCS7SignedData, blob)
			fs, err := pe.New(signed)
			if err != nil {
				t.Fatalf("New(signed) error = %v", err)
			}

			// Verify unsigned + pre-cert overlay matches signed with cert table excluded.
			unsignedWithOverlay := append(bytes.Clone(unsigned), []byte("pre-cert-overlay-bytes")...)
			unsignedWithOverlay = padTo8(unsignedWithOverlay)
			binary.LittleEndian.PutUint32(unsignedWithOverlay[optOffset+64:], 0x11223344)
			fuOverlay, err := pe.New(unsignedWithOverlay)
			if err != nil {
				t.Fatalf("New(unsignedWithOverlay) error = %v", err)
			}

			ranges, err := fs.AuthenticodeDigestRanges(signed)
			if err != nil {
				t.Fatalf("AuthenticodeDigestRanges() error = %v", err)
			}
			if len(ranges) != 3 {
				t.Fatalf("len(ranges) = %d, want 3 (before CheckSum, CheckSum..CertDir, CertDir..CertTable)", len(ranges))
			}

			var hashes []crypto.Hash
			var wantList [][]byte
			for _, tc := range algs {
				hashes = append(hashes, tc.alg)

				gotSigned, err := fs.AuthenticodeDigest(signed, tc.alg)
				if err != nil {
					t.Fatalf("AuthenticodeDigest(signed, %v) error = %v", tc.alg, err)
				}
				gotUnsigned, err := fuOverlay.AuthenticodeDigest(unsignedWithOverlay, tc.alg)
				if err != nil {
					t.Fatalf("AuthenticodeDigest(unsignedOverlay, %v) error = %v", tc.alg, err)
				}
				if !bytes.Equal(gotSigned, gotUnsigned) {
					t.Fatalf("%v signed digest %x != unsigned overlay digest %x", tc.alg, gotSigned, gotUnsigned)
				}

				h := tc.new()
				for _, r := range ranges {
					h.Write(signed[r.Offset : r.Offset+r.Length])
				}
				want := h.Sum(nil)
				if !bytes.Equal(gotSigned, want) {
					t.Fatalf("%v digest = %x, want %x", tc.alg, gotSigned, want)
				}
				wantList = append(wantList, want)

				// Mutating returned digest slice must not corrupt future calls.
				clear(gotSigned)
				again, err := fs.AuthenticodeDigest(signed, tc.alg)
				if err != nil || !bytes.Equal(again, want) {
					t.Fatalf("%v digest affected by caller mutation", tc.alg)
				}
			}

			gotMulti, err := fs.AuthenticodeDigests(signed, hashes...)
			if err != nil {
				t.Fatalf("AuthenticodeDigests() error = %v", err)
			}
			if len(gotMulti) != len(wantList) {
				t.Fatalf("len(gotMulti) = %d, want %d", len(gotMulti), len(wantList))
			}
			for i := range wantList {
				if !bytes.Equal(gotMulti[i], wantList[i]) {
					t.Fatalf("AuthenticodeDigests[%d] = %x, want %x", i, gotMulti[i], wantList[i])
				}
			}

			// Unsigned without overlay sanity check.
			if _, err := fu.AuthenticodeDigest(unsigned, crypto.SHA256); err != nil {
				t.Fatalf("AuthenticodeDigest(unsigned) error = %v", err)
			}
		})
	}
}

func TestAuthenticodeDigestMutationSensitivity(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		name := "PE32"
		if is64 {
			name = "PE32Plus"
		}
		t.Run(name, func(t *testing.T) {
			base := testfixture.Minimal(is64, 2)
			data := appendCertificateTable(base, is64, []byte("overlay!"), pe.CertificateTypePKCS7SignedData, bytes.Repeat([]byte{0xab}, 61))
			// Also append trailing bytes after the certificate table to prove post-cert region sensitivity.
			data = append(data, []byte("post-cert-trailing")...)

			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			baseline, err := f.AuthenticodeDigest(data, crypto.SHA256)
			if err != nil {
				t.Fatalf("AuthenticodeDigest() error = %v", err)
			}
			ranges, err := f.AuthenticodeDigestRanges(data)
			if err != nil {
				t.Fatalf("AuthenticodeDigestRanges() error = %v", err)
			}

			included := make([]bool, len(data))
			var totalIncluded int64
			for i, r := range ranges {
				if r.Offset < 0 || r.Length <= 0 || r.Offset+r.Length > int64(len(data)) {
					t.Fatalf("range[%d] out of bounds: %+v", i, r)
				}
				if i > 0 && r.Offset <= ranges[i-1].Offset+ranges[i-1].Length {
					t.Fatalf("ranges not strictly separated: prev=%+v cur=%+v", ranges[i-1], r)
				}
				totalIncluded += r.Length
				for pos := r.Offset; pos < r.Offset+r.Length; pos++ {
					included[pos] = true
				}
			}

			certDir := f.OptionalHeader.DataDirectories[pe.DataDirectoryCertificate]
			excludedCount := int64(4 + 8 + certDir.Size)
			if totalIncluded+excludedCount != int64(len(data)) {
				t.Fatalf("included (%d) + excluded (%d) != fileSize (%d)", totalIncluded, excludedCount, len(data))
			}

			work := bytes.Clone(data)
			for off := range work {
				work[off] ^= 0xff
				got, err := f.AuthenticodeDigest(work, crypto.SHA256)
				if err != nil {
					t.Fatalf("offset %d: AuthenticodeDigest() unexpected error = %v", off, err)
				}
				same := bytes.Equal(got, baseline)
				if included[off] && same {
					t.Fatalf("offset %d (included) mutation did not change digest", off)
				}
				if !included[off] && !same {
					t.Fatalf("offset %d (excluded) mutation changed digest", off)
				}
				work[off] = data[off]
			}
		})
	}
}

func TestAuthenticodeDigestLayouts(t *testing.T) {
	t.Run("OutOfOrderSectionsAndGaps", func(t *testing.T) {
		data := testfixture.Minimal(true, 2)
		secOff := 152 + 240
		// Swap physical file ranges so section[0] points after section[1], with gaps before and between.
		data = append(data, make([]byte, 0x400)...)
		binary.LittleEndian.PutUint32(data[secOff+16:], 0x200)
		binary.LittleEndian.PutUint32(data[secOff+20:], 0x600) // sec0 at 0x600..0x800 (gap at 0x400..0x600)
		binary.LittleEndian.PutUint32(data[secOff+40+16:], 0x100)
		binary.LittleEndian.PutUint32(data[secOff+40+20:], 0x400) // sec1 at 0x400..0x500 (gap at 0x500..0x600)
		data[0x450] = 0x11
		data[0x550] = 0x22
		data[0x650] = 0x33

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		got, err := f.AuthenticodeDigest(data, crypto.SHA256)
		if err != nil {
			t.Fatalf("AuthenticodeDigest() error = %v", err)
		}

		// Verify mutating the inter-section gap byte changes the digest.
		mutated := bytes.Clone(data)
		mutated[0x550] ^= 0xff
		gotMutated, err := f.AuthenticodeDigest(mutated, crypto.SHA256)
		if err != nil {
			t.Fatalf("AuthenticodeDigest(mutated) error = %v", err)
		}
		if bytes.Equal(got, gotMutated) {
			t.Fatal("mutating inter-section gap did not change digest")
		}
	})

	t.Run("ZeroSizeSectionIgnored", func(t *testing.T) {
		data := testfixture.Minimal(false, 2)
		secOff := 152 + 224
		// Set second section SizeOfRawData=0 and PointerToRawData past EOF.
		binary.LittleEndian.PutUint32(data[secOff+40+16:], 0)
		binary.LittleEndian.PutUint32(data[secOff+40+20:], 0x99990000)

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := f.AuthenticodeDigest(data, crypto.SHA256); err != nil {
			t.Fatalf("AuthenticodeDigest() with zero-size section failed: %v", err)
		}
	})

	t.Run("ZeroSectionsWithOverlay", func(t *testing.T) {
		data := testfixture.Minimal(true, 0)
		data = append(data, []byte("overlay-no-sections")...)

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		ranges, err := f.AuthenticodeDigestRanges(data)
		if err != nil {
			t.Fatalf("AuthenticodeDigestRanges() error = %v", err)
		}
		if len(ranges) != 3 {
			t.Fatalf("len(ranges) = %d, want 3", len(ranges))
		}
	})

	t.Run("WithoutCertificateDataDirectory", func(t *testing.T) {
		data := testfixture.Minimal(false, 1)
		// Trim NumberOfRvaAndSizes down to 4 (excludes DataDirectory[4]).
		binary.LittleEndian.PutUint32(data[244:], 4)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		ranges, err := f.AuthenticodeDigestRanges(data)
		if err != nil {
			t.Fatalf("AuthenticodeDigestRanges() error = %v", err)
		}
		// Only CheckSum is excluded -> 2 included ranges.
		if len(ranges) != 2 {
			t.Fatalf("len(ranges) = %d, want 2", len(ranges))
		}
		got, err := f.AuthenticodeDigest(data, crypto.SHA256)
		if err != nil {
			t.Fatalf("AuthenticodeDigest() error = %v", err)
		}
		h := sha256.New()
		h.Write(data[:216])
		h.Write(data[220:])
		if !bytes.Equal(got, h.Sum(nil)) {
			t.Fatalf("digest = %x, want %x", got, h.Sum(nil))
		}
	})

	t.Run("EmptyMultiDigestZeroAllocs", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		allocs := testing.AllocsPerRun(100, func() {
			digests, err := f.AuthenticodeDigests(data)
			if err != nil || digests != nil {
				t.Fatalf("AuthenticodeDigests() = (%v, %v), want (nil, nil)", digests, err)
			}
		})
		if allocs != 0 {
			t.Fatalf("allocs = %v, want 0", allocs)
		}
	})
}

func TestAuthenticodeDigestRejectsMalformedAndLimits(t *testing.T) {
	t.Run("NilAndUnparsedFile", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		var nilFile *pe.File
		if _, err := nilFile.AuthenticodeDigest(data, crypto.SHA256); !errors.Is(err, pe.ErrInvalidHeader) {
			t.Fatalf("nil file err = %v, want ErrInvalidHeader", err)
		}
		if _, err := (&pe.File{}).AuthenticodeDigestRanges(data); !errors.Is(err, pe.ErrInvalidHeader) {
			t.Fatalf("zero File err = %v, want ErrInvalidHeader", err)
		}
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		for _, alg := range []crypto.Hash{0, crypto.SHA3_256, crypto.BLAKE2s_256} {
			if _, err := f.AuthenticodeDigest(data, alg); !errors.Is(err, pe.ErrUnsupportedDigestAlgorithm) {
				t.Fatalf("alg %v err = %v, want ErrUnsupportedDigestAlgorithm", alg, err)
			}
		}
		if _, err := f.AuthenticodeDigests(data, crypto.SHA256, crypto.SHA3_256); !errors.Is(err, pe.ErrUnsupportedDigestAlgorithm) {
			t.Fatalf("multi unsupported alg err = %v, want ErrUnsupportedDigestAlgorithm", err)
		}
	})

	t.Run("MismatchedOrTruncatedData", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := f.AuthenticodeDigest(data[:len(data)-1], crypto.SHA256); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("short slice err = %v, want ErrOutOfBounds", err)
		}
		longer := append(bytes.Clone(data), 0x00)
		if _, err := f.AuthenticodeDigest(longer, crypto.SHA256); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("longer slice err = %v, want ErrOutOfBounds", err)
		}
	})

	t.Run("HeaderSizeErrors", func(t *testing.T) {
		tooBig := testfixture.Minimal(true, 1)
		binary.LittleEndian.PutUint32(tooBig[152+60:], uint32(len(tooBig)+512))
		fBig, err := pe.New(tooBig)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := fBig.AuthenticodeDigest(tooBig, crypto.SHA256); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("SizeOfHeaders>file err = %v, want ErrOutOfBounds", err)
		}

		tooSmall := testfixture.Minimal(true, 1)
		binary.LittleEndian.PutUint32(tooSmall[152+60:], 64)
		fSmall, err := pe.New(tooSmall)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := fSmall.AuthenticodeDigest(tooSmall, crypto.SHA256); !errors.Is(err, pe.ErrInvalidHeader) {
			t.Fatalf("SizeOfHeaders<tableEnd err = %v, want ErrInvalidHeader", err)
		}
	})

	t.Run("SectionErrors", func(t *testing.T) {
		secOff := 152 + 240

		// Section overlapping headers.
		overlapHdr := testfixture.Minimal(true, 1)
		binary.LittleEndian.PutUint32(overlapHdr[secOff+20:], 0x100)
		fh, err := pe.New(overlapHdr)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := fh.AuthenticodeDigest(overlapHdr, crypto.SHA256); !errors.Is(err, pe.ErrInvalidHeader) {
			t.Fatalf("section overlaps header err = %v, want ErrInvalidHeader", err)
		}

		// Two sections overlapping on disk.
		overlapSec := testfixture.Minimal(true, 2)
		binary.LittleEndian.PutUint32(overlapSec[secOff+40+20:], 0x300) // overlaps section 0 [0x200, 0x400) when headers adjusted? wait headerSize is 512 (0x200), sec0=0x200..0x400
		fs, err := pe.New(overlapSec)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := fs.AuthenticodeDigest(overlapSec, crypto.SHA256); !errors.Is(err, pe.ErrInvalidHeader) {
			t.Fatalf("overlapping sections err = %v, want ErrInvalidHeader", err)
		}

		// Section truncated past EOF.
		trunc := testfixture.Minimal(true, 1)
		binary.LittleEndian.PutUint32(trunc[secOff+16:], 0x400)
		ft, err := pe.New(trunc)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := ft.AuthenticodeDigest(trunc, crypto.SHA256); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("truncated section err = %v, want ErrOutOfBounds", err)
		}

		// Section arithmetic overflow in uint32 offset+size.
		overflow := testfixture.Minimal(true, 1)
		binary.LittleEndian.PutUint32(overflow[secOff+20:], 0xfffff000)
		binary.LittleEndian.PutUint32(overflow[secOff+16:], 0x2000)
		fo, err := pe.New(overflow)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if _, err := fo.AuthenticodeDigest(overflow, crypto.SHA256); !errors.Is(err, pe.ErrIntegerOverflow) {
			t.Fatalf("overflow section err = %v, want ErrIntegerOverflow", err)
		}
	})

	t.Run("CertificateDirectoryErrors", func(t *testing.T) {
		dirOff := testfixture.CertificateDirOffset(true)

		// Unaligned security directory.
		unaligned := testfixture.Minimal(true, 1)
		unaligned = append(unaligned, make([]byte, 16)...)
		binary.LittleEndian.PutUint32(unaligned[dirOff:], 0x401)
		binary.LittleEndian.PutUint32(unaligned[dirOff+4:], 8)
		fu, _ := pe.New(unaligned)
		if _, err := fu.AuthenticodeDigest(unaligned, crypto.SHA256); !errors.Is(err, pe.ErrInvalidCertificate) {
			t.Fatalf("unaligned cert dir err = %v, want ErrInvalidCertificate", err)
		}

		// Over MaxCertificateBytes.
		overLimit := testfixture.Minimal(true, 1)
		binary.LittleEndian.PutUint32(overLimit[dirOff:], 0x400)
		binary.LittleEndian.PutUint32(overLimit[dirOff+4:], pe.MaxCertificateBytes+8)
		fl, _ := pe.New(overLimit)
		if _, err := fl.AuthenticodeDigest(overLimit, crypto.SHA256); !errors.Is(err, pe.ErrCertificateLimit) {
			t.Fatalf("over cert limit err = %v, want ErrCertificateLimit", err)
		}
	})

	t.Run("MaxAuthenticodeDigestBytesLimit", func(t *testing.T) {
		big := make([]byte, pe.MaxAuthenticodeDigestBytes+1)
		copy(big, testfixture.Minimal(true, 1))
		f, err := pe.New(big)
		if err != nil {
			t.Fatalf("New(big) error = %v", err)
		}
		if _, err := f.AuthenticodeDigest(big, crypto.SHA256); !errors.Is(err, pe.ErrAuthenticodeLimit) {
			t.Fatalf("big digest err = %v, want ErrAuthenticodeLimit", err)
		}
	})
}

func TestAuthenticodeDigestConcurrentReads(t *testing.T) {
	blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
	})
	data := appendCertificateTable(testfixture.Minimal(true, 2), true, nil, pe.CertificateTypePKCS7SignedData, blob)
	f, err := pe.New(data)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want, err := f.AuthenticodeDigest(data, crypto.SHA256)
	if err != nil {
		t.Fatalf("AuthenticodeDigest() error = %v", err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				got, err := f.AuthenticodeDigest(data, crypto.SHA256)
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("concurrent AuthenticodeDigest = (%x, %v), want %x", got, err, want)
					return
				}
			}
		})
	}
	wg.Wait()
}

func appendCertificateTable(base []byte, is64 bool, preOverlay []byte, certType uint16, payload []byte) []byte {
	out := bytes.Clone(base)
	out = append(out, preOverlay...)
	out = padTo8(out)
	tableOff := uint32(len(out))

	recLen := 8 + len(payload)
	paddedLen := (recLen + 7) &^ 7
	rec := make([]byte, paddedLen)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(recLen))
	binary.LittleEndian.PutUint16(rec[4:6], pe.CertificateRevision2_0)
	binary.LittleEndian.PutUint16(rec[6:8], certType)
	copy(rec[8:], payload)
	out = append(out, rec...)

	dirOff := testfixture.CertificateDirOffset(is64)
	binary.LittleEndian.PutUint32(out[dirOff:], tableOff)
	binary.LittleEndian.PutUint32(out[dirOff+4:], uint32(len(rec)))
	return out
}

func padTo8(b []byte) []byte {
	if rem := len(b) % 8; rem != 0 {
		b = append(b, make([]byte, 8-rem)...)
	}
	return b
}
