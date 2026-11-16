package exports_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	"github.com/foxboron/go-uefi/authenticode"
	saferwall "github.com/saferwall/pe"
)

var (
	goUEFIDirOnce sync.Once
	goUEFIDirPath string
	goUEFIDirErr  error
)

func goUEFIFixture(tb testing.TB, rel string) []byte {
	tb.Helper()
	goUEFIDirOnce.Do(func() {
		out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/foxboron/go-uefi").CombinedOutput()
		if err != nil {
			goUEFIDirErr = err
			return
		}
		goUEFIDirPath = strings.TrimSpace(string(out))
	})
	if goUEFIDirErr != nil {
		tb.Skipf("unable to locate go-uefi module cache: %v", goUEFIDirErr)
	}
	data, err := os.ReadFile(filepath.Join(goUEFIDirPath, rel))
	if err != nil {
		tb.Fatalf("ReadFile(%q): %v", rel, err)
	}
	return data
}

type countingReaderAt struct {
	r         io.ReaderAt
	bytesRead int64
	reads     int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.bytesRead += int64(n)
	c.reads++
	return n, err
}

func saferwallAuthentihash(data []byte) ([]byte, error) {
	sw, err := saferwall.NewBytes(data, fastHeaderOptions())
	if err != nil {
		return nil, err
	}
	if err := sw.Parse(); err != nil {
		return nil, err
	}
	h := sw.Authentihash()
	if h == nil {
		return nil, errors.New("saferwall Authentihash returned nil")
	}
	return h, nil
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCrossLibraryAuthenticodeDigest(t *testing.T) {
	// Redistributable signed PE fixtures from go-uefi testdata.
	t.Run("SignedReferenceVectors", func(t *testing.T) {
		cases := []struct {
			name     string
			relPath  string
			wantHex  string
			wantSigs int
		}{
			{
				name:     "test.pecoff.signed",
				relPath:  "authenticode/testdata/test.pecoff.signed",
				wantHex:  "e7d74d2bc1287c17bf056e259ad7d2ca557e848b252509ae9956df0b14f69702",
				wantSigs: 1,
			},
			{
				name:     "HelloWorld.efi.signed",
				relPath:  "tests/data/binary/HelloWorld.efi.signed",
				wantHex:  "765600a03f44d9f954376dd5f4e5b5e86b2ca1a3d6308a005f95922b0ebe7c94",
				wantSigs: 1,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				data := goUEFIFixture(t, tc.relPath)
				want := mustDecodeHex(t, tc.wantHex)

				gp, err := gope.New(data)
				if err != nil {
					t.Fatalf("go-pe New: %v", err)
				}
				gotGP, err := gp.AuthenticodeDigest(data, crypto.SHA256)
				if err != nil {
					t.Fatalf("go-pe AuthenticodeDigest: %v", err)
				}
				if !bytes.Equal(gotGP, want) {
					t.Fatalf("go-pe = %x, want %x", gotGP, want)
				}

				sigs, err := gp.AuthenticodeSignatures(data)
				if err != nil || len(sigs) != tc.wantSigs || sigs[0].IndirectData == nil {
					t.Fatalf("go-pe AuthenticodeSignatures = (%d, %v)", len(sigs), err)
				}
				if !bytes.Equal(sigs[0].IndirectData.Digest, gotGP) {
					t.Fatalf("embedded SpcIndirectDataContent.Digest %x != computed %x", sigs[0].IndirectData.Digest, gotGP)
				}

				gotSW, err := saferwallAuthentihash(data)
				if err != nil {
					t.Fatalf("saferwall Authentihash: %v", err)
				}
				if !bytes.Equal(gotSW, want) {
					t.Fatalf("saferwall = %x, want %x", gotSW, want)
				}

				cr := &countingReaderAt{r: bytes.NewReader(data)}
				uefiBin, err := authenticode.Parse(cr)
				if err != nil {
					t.Fatalf("go-uefi Parse: %v", err)
				}
				gotUEFI := uefiBin.Hash(crypto.SHA256)
				if !bytes.Equal(gotUEFI, want) {
					t.Fatalf("go-uefi = %x, want %x", gotUEFI, want)
				}
				t.Logf("size=%dB go-uefi_reads=%d go-uefi_bytes_read=%dB (%.2fx)",
					len(data), cr.reads, cr.bytesRead, float64(cr.bytesRead)/float64(len(data)))
			})
		}
	})

	// Compare redistributable unsigned binaries across go-pe, saferwall, and go-uefi.
	t.Run("UnsignedRedistributablesAndDisagreements", func(t *testing.T) {
		unpaddedCases := []struct {
			name        string
			data        []byte
			unpaddedHex string
			paddedHex   string
		}{
			{
				name:        "test.pecoff",
				data:        goUEFIFixture(t, "authenticode/testdata/test.pecoff"),
				unpaddedHex: "9f2b505ce20bc20c2ce7f7a33cb93ca97d1465735ce6821a6fc8e8c7b1e0e60a",
				paddedHex:   "e7d74d2bc1287c17bf056e259ad7d2ca557e848b252509ae9956df0b14f69702",
			},
			{
				name:        "HelloWorld.efi",
				data:        goUEFIFixture(t, "tests/data/binary/HelloWorld.efi"),
				unpaddedHex: "d2ae1f36ec9b40b55f60920a3f58ec902ebdc7c323e443412c751cdb3c42d3f3",
				paddedHex:   "765600a03f44d9f954376dd5f4e5b5e86b2ca1a3d6308a005f95922b0ebe7c94",
			},
			{
				name:        "linuxx64.efi.stub",
				data:        goUEFIFixture(t, "tests/data/binary/linuxx64.efi.stub"),
				unpaddedHex: "b9d3bcb414848ce11814ccb9fd98d95511e95fcc117c24e1517c9867761f251e",
				paddedHex:   "cc09c6b98fc5bf619ce09388399c35c21a510855f5fd308de653a8cf868e01cc",
			},
		}

		for _, tc := range unpaddedCases {
			t.Run(tc.name, func(t *testing.T) {
				gp, err := gope.New(tc.data)
				if err != nil {
					t.Fatalf("go-pe New: %v", err)
				}
				gotGP, err := gp.AuthenticodeDigest(tc.data, crypto.SHA256)
				if err != nil {
					t.Fatalf("go-pe AuthenticodeDigest: %v", err)
				}
				gotSW, err := saferwallAuthentihash(tc.data)
				if err != nil {
					t.Fatalf("saferwall Authentihash: %v", err)
				}
				uefiBin, err := authenticode.Parse(bytes.NewReader(tc.data))
				if err != nil {
					t.Fatalf("go-uefi Parse: %v", err)
				}
				gotUEFI := uefiBin.Hash(crypto.SHA256)

				if !bytes.Equal(gotGP, mustDecodeHex(t, tc.unpaddedHex)) {
					t.Fatalf("go-pe = %x, want unpadded %s", gotGP, tc.unpaddedHex)
				}
				if !bytes.Equal(gotSW, gotGP) {
					t.Fatalf("saferwall = %x, want match with go-pe %x", gotSW, gotGP)
				}
				// Documented disagreement: go-uefi appends 8-byte EOF zero-padding for unsigned unaligned binaries.
				if !bytes.Equal(gotUEFI, mustDecodeHex(t, tc.paddedHex)) {
					t.Fatalf("go-uefi = %x, want padded %s", gotUEFI, tc.paddedHex)
				}
			})
		}

		for _, name := range []string{"gcc-386-mingw-exec", "gcc-amd64-mingw-exec", "gcc-386-mingw-no-symbols-exec"} {
			t.Run(name, func(t *testing.T) {
				data := gorootFixture(t, name)
				gp, err := gope.New(data)
				if err != nil {
					t.Fatalf("go-pe New: %v", err)
				}
				gotGP, err := gp.AuthenticodeDigest(data, crypto.SHA256)
				if err != nil {
					t.Fatalf("go-pe AuthenticodeDigest: %v", err)
				}
				gotSW, err := saferwallAuthentihash(data)
				if err != nil {
					t.Fatalf("saferwall Authentihash: %v", err)
				}
				if !bytes.Equal(gotGP, gotSW) {
					t.Fatalf("go-pe %x != saferwall %x", gotGP, gotSW)
				}
				uefiBin, err := authenticode.Parse(bytes.NewReader(data))
				if err != nil {
					t.Fatalf("go-uefi Parse: %v", err)
				}
				gotUEFI := uefiBin.Hash(crypto.SHA256)
				if len(data)%8 == 0 && !bytes.Equal(gotGP, gotUEFI) {
					t.Fatalf("8-byte aligned %s: go-pe %x != go-uefi %x", name, gotGP, gotUEFI)
				}
				if len(data)%8 != 0 && bytes.Equal(gotGP, gotUEFI) {
					t.Fatalf("unaligned %s unexpectedly matched go-uefi 8-byte padded digest", name)
				}
			})
		}

		// Truncated EFI stub: go-pe and saferwall reject cleanly; go-uefi panics in bytes.Buffer.Truncate.
		t.Run("vmlinuz-4.15.0-47-generic", func(t *testing.T) {
			data := gorootFixture(t, "vmlinuz-4.15.0-47-generic")
			gp, err := gope.New(data)
			if err != nil {
				t.Fatalf("go-pe New: %v", err)
			}
			if _, err := gp.AuthenticodeDigest(data, crypto.SHA256); !errors.Is(err, gope.ErrOutOfBounds) {
				t.Fatalf("go-pe err = %v, want ErrOutOfBounds", err)
			}
			if h, err := saferwallAuthentihash(data); err == nil && h != nil {
				t.Fatalf("saferwall unexpectedly returned digest %x on truncated header", h)
			}
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				_, _ = authenticode.Parse(bytes.NewReader(data))
			}()
			if !panicked {
				t.Fatal("expected go-uefi panic on truncated vmlinuz stub")
			}
		})
	})

	// Disagreement cases: truncated section body, gap between sections, and post-certificate trailer.
	t.Run("LayoutDisagreements", func(t *testing.T) {
		t.Run("TruncatedSectionBody", func(t *testing.T) {
			data := testfixture.Minimal(true, 1)
			// Inflate SizeOfRawData past EOF while keeping SizeOfHeaders in bounds.
			binary.LittleEndian.PutUint32(data[152+240+16:], 0x1000)

			gp, err := gope.New(data)
			if err != nil {
				t.Fatalf("go-pe New: %v", err)
			}
			if _, err := gp.AuthenticodeDigest(data, crypto.SHA256); !errors.Is(err, gope.ErrOutOfBounds) {
				t.Fatalf("go-pe err = %v, want ErrOutOfBounds", err)
			}
			// Documented disagreement: saferwall does not validate section bounds in Authentihash.
			if h, err := saferwallAuthentihash(data); err != nil || len(h) != sha256.Size {
				t.Fatalf("saferwall = (%x, %v), expected silent non-nil digest on truncated section", h, err)
			}
		})

		t.Run("TrailingDataAfterCertificateTable", func(t *testing.T) {
			blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
				IncludeCertificate: true,
			})
			signed := testfixture.Certificates(true, testfixture.CertificateSpec{
				Revision: gope.CertificateRevision2_0,
				Type:     gope.CertificateTypePKCS7SignedData,
				Payload:  blob,
			})
			// Append 16 bytes after WIN_CERTIFICATE (8-byte aligned overall).
			withTrailer := append(bytes.Clone(signed), []byte("0123456789abcdef")...)

			gp, err := gope.New(withTrailer)
			if err != nil {
				t.Fatalf("go-pe New: %v", err)
			}
			gotGP, err := gp.AuthenticodeDigest(withTrailer, crypto.SHA256)
			if err != nil {
				t.Fatalf("go-pe AuthenticodeDigest: %v", err)
			}
			gotSW, err := saferwallAuthentihash(withTrailer)
			if err != nil {
				t.Fatalf("saferwall Authentihash: %v", err)
			}
			if !bytes.Equal(gotGP, gotSW) {
				t.Fatalf("go-pe %x != saferwall %x", gotGP, gotSW)
			}
			// go-uefi subtracts ddEntry.Size from the end of remaining bytes instead of [dirStart, dirEnd).
			uefiBin, err := authenticode.Parse(bytes.NewReader(withTrailer))
			if err != nil {
				t.Fatalf("go-uefi Parse: %v", err)
			}
			if bytes.Equal(uefiBin.Hash(crypto.SHA256), gotGP) {
				t.Fatal("go-uefi unexpectedly matched range-excluded digest when trailing bytes follow cert table")
			}
		})
	})
}

func BenchmarkAuthenticodeDigestComparison(b *testing.B) {
	helloSigned := goUEFIFixture(b, "tests/data/binary/HelloWorld.efi.signed")

	blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
	})
	// Update certificate table at end of 1MiB synthetic image.
	signed1MiB := func() []byte {
		base := append(testfixture.Minimal(true, 1), make([]byte, 1<<20)...)
		if rem := len(base) % 8; rem != 0 {
			base = append(base, make([]byte, 8-rem)...)
		}
		tableOff := uint32(len(base))
		recLen := 8 + len(blob)
		padded := (recLen + 7) &^ 7
		rec := make([]byte, padded)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(recLen))
		binary.LittleEndian.PutUint16(rec[4:6], gope.CertificateRevision2_0)
		binary.LittleEndian.PutUint16(rec[6:8], gope.CertificateTypePKCS7SignedData)
		copy(rec[8:], blob)
		out := append(base, rec...)
		dirOff := testfixture.CertificateDirOffset(true)
		binary.LittleEndian.PutUint32(out[dirOff:], tableOff)
		binary.LittleEndian.PutUint32(out[dirOff+4:], uint32(len(rec)))
		return out
	}()

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "HelloWorldSigned", data: helloSigned},
		{name: "SyntheticSigned1MiB", data: signed1MiB},
	} {
		b.Run(tc.name+"/go-pe", func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			for b.Loop() {
				f, err := gope.New(tc.data)
				if err != nil {
					b.Fatal(err)
				}
				d, err := f.AuthenticodeDigest(tc.data, crypto.SHA256)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkAny = d
			}
		})

		b.Run(tc.name+"/go-pe-HeaderCached", func(b *testing.B) {
			f, err := gope.New(tc.data)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				d, err := f.AuthenticodeDigest(tc.data, crypto.SHA256)
				if err != nil {
					b.Fatal(err)
				}
				benchSinkAny = d
			}
		})

		opts := fastHeaderOptions()
		b.Run(tc.name+"/saferwall", func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			for b.Loop() {
				sw, err := saferwall.NewBytes(tc.data, opts)
				if err != nil {
					b.Fatal(err)
				}
				if err := sw.Parse(); err != nil {
					b.Fatal(err)
				}
				benchSinkAny = sw.Authentihash()
			}
		})

		b.Run(tc.name+"/go-uefi", func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			for b.Loop() {
				bin, err := authenticode.Parse(bytes.NewReader(tc.data))
				if err != nil {
					b.Fatal(err)
				}
				benchSinkAny = bin.Hash(crypto.SHA256)
			}
		})
	}
}
