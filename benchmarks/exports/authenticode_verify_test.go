package exports_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	"github.com/foxboron/go-uefi/authenticode"
)

func parseFirstPEMCert(tb testing.TB, pemBytes []byte) *x509.Certificate {
	tb.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		tb.Fatalf("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tb.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestCrossLibraryAuthenticodeVerify(t *testing.T) {
	t.Run("RealSignedPECOFFAgreesWithGoUEFI", func(t *testing.T) {
		data := goUEFIFixture(t, "authenticode/testdata/test.pecoff.signed")
		dbCert := parseFirstPEMCert(t, goUEFIFixture(t, "authenticode/testdata/db.pem"))

		// go-uefi verification: binds digest + PKCS#7 signature + explicit cert.
		uefiPE, err := authenticode.Parse(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("go-uefi Parse: %v", err)
		}
		ok, err := uefiPE.Verify(dbCert)
		if err != nil || !ok {
			t.Fatalf("go-uefi Verify = (%v, %v), want (true, nil)", ok, err)
		}

		// go-pe offline verification without roots reports valid digest and CMS
		// independently from chain trust, even after the fixture cert expires.
		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		gpOffline, err := gp.VerifyAuthenticode(data, gope.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("go-pe VerifyAuthenticode(offline): %v", err)
		}
		if len(gpOffline.Signatures) != 1 {
			t.Fatalf("go-pe signatures = %d, want 1", len(gpOffline.Signatures))
		}
		sig := gpOffline.Signatures[0]
		if sig.Digest.Status != gope.AuthenticodeStatusValid {
			t.Fatalf("go-pe Digest = %+v, want valid", sig.Digest)
		}
		if sig.Signers[0].Binding.Status != gope.AuthenticodeStatusValid ||
			sig.Signers[0].CMS.Status != gope.AuthenticodeStatusValid {
			t.Fatalf("go-pe signer integrity failed: %+v", sig.Signers[0])
		}
		if sig.Signers[0].Trust.Status != gope.AuthenticodeStatusUnchecked {
			t.Fatalf("go-pe Trust = %+v, want unchecked without Roots", sig.Signers[0].Trust)
		}

		// Note: go-uefi's db.pem test fixture has zero NotBefore/NotAfter bounds
		// (0001-01-01T00:00:00Z), which go-uefi accepts because it skips X.509
		// time/chain validation, whereas go-pe reports Digest=valid, CMS=valid,
		// and Trust=invalid when evaluating chain policy at a concrete time.
		roots := x509.NewCertPool()
		roots.AddCert(dbCert)
		gpTrusted, err := gp.VerifyAuthenticode(data, gope.AuthenticodeVerifyOptions{
			Roots:            roots,
			VerificationTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			KeyUsages:        []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			t.Fatalf("go-pe VerifyAuthenticode(trusted): %v", err)
		}
		if gpTrusted.Signatures[0].Digest.Status != gope.AuthenticodeStatusValid ||
			gpTrusted.Signatures[0].Signers[0].CMS.Status != gope.AuthenticodeStatusValid {
			t.Fatalf("go-pe integrity degraded unexpectedly: %+v", gpTrusted.Signatures[0])
		}
		if gpTrusted.Signatures[0].Signers[0].Trust.Status != gope.AuthenticodeStatusInvalid {
			t.Fatalf("go-pe Trust = %+v, want invalid for expired/zero-window db.pem", gpTrusted.Signatures[0].Signers[0].Trust)
		}

		// Saferwall agrees on the underlying SHA-256 Authentihash.
		swDigest, err := saferwallAuthentihash(data)
		if err != nil {
			t.Fatalf("saferwallAuthentihash: %v", err)
		}
		if !bytes.Equal(swDigest, sig.Digest.Computed) {
			t.Fatalf("saferwall Authentihash %x != go-pe computed %x", swDigest, sig.Digest.Computed)
		}
	})

	t.Run("RealSignedEFIAgreesWithGoUEFI", func(t *testing.T) {
		data := goUEFIFixture(t, "tests/data/binary/HelloWorld.efi.signed")

		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		res, err := gp.VerifyAuthenticode(data, gope.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("go-pe VerifyAuthenticode: %v", err)
		}
		if len(res.Signatures) == 0 {
			t.Fatalf("expected signature in HelloWorld.efi.signed")
		}
		sig := res.Signatures[0]
		if sig.Digest.Status != gope.AuthenticodeStatusValid || sig.Signers[0].CMS.Status != gope.AuthenticodeStatusValid {
			t.Fatalf("go-pe failed offline verification on HelloWorld.efi.signed: digest=%+v cms=%+v", sig.Digest, sig.Signers[0].CMS)
		}

		uefiPE, err := authenticode.Parse(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("go-uefi Parse: %v", err)
		}
		// HelloWorld.efi.signed carries its signer certificate in the PKCS#7 bag.
		ok, err := uefiPE.Verify(sig.Signers[0].SignerCertificate)
		if err != nil || !ok {
			t.Fatalf("go-uefi Verify = (%v, %v), want (true, nil)", ok, err)
		}
	})

	t.Run("TamperedImageDivergence", func(t *testing.T) {
		pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{UseRSA: true})
		base := testfixture.MinimalAligned(true)
		bf, _ := gope.New(base)
		digest, _ := bf.AuthenticodeDigest(base, crypto.SHA256)
		blob := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
			SignerCert:     pki.SignerCert,
			SignerKey:      pki.SignerKey,
			ExtraCerts:     []*x509.Certificate{pki.InterCert},
			ImageDigest:    digest,
			ImageDigestAlg: crypto.SHA256,
		})
		signed := testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
			Revision: gope.CertificateRevision2_0,
			Type:     gope.CertificateTypePKCS7SignedData,
			Payload:  blob,
		})
		// Tamper one PE byte: go-pe reports Digest=Invalid while CMS remains Valid;
		// go-uefi returns a single (false, err).
		signed[len(base)-1] ^= 0xff

		gp, _ := gope.New(signed)
		res, err := gp.VerifyAuthenticode(signed, gope.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("go-pe VerifyAuthenticode: %v", err)
		}
		if res.Signatures[0].Digest.Status != gope.AuthenticodeStatusInvalid ||
			res.Signatures[0].Signers[0].CMS.Status != gope.AuthenticodeStatusValid {
			t.Fatalf("expected Digest=invalid CMS=valid, got %+v", res.Signatures[0])
		}

		uefiPE, err := authenticode.Parse(bytes.NewReader(signed))
		if err != nil {
			t.Fatalf("go-uefi Parse: %v", err)
		}
		if ok, err := uefiPE.Verify(pki.SignerCert); ok || err == nil {
			t.Fatalf("go-uefi Verify unexpectedly succeeded on tampered PE")
		}
	})
}

// Mutate a hashed section byte in each upstream signed fixture. A valid CMS
// signature alone must not conceal an invalid image digest.
func TestSignedCorpusTampering(t *testing.T) {
	for _, path := range []string{"authenticode/testdata/test.pecoff.signed", "tests/data/binary/HelloWorld.efi.signed"} {
		t.Run(path, func(t *testing.T) {
			data := bytes.Clone(goUEFIFixture(t, path))
			f, err := gope.New(data)
			if err != nil {
				t.Fatal(err)
			}
			mutated := false
			for _, section := range f.Sections {
				if section.SizeOfRawData > 0 && uint64(section.PointerToRawData) < uint64(len(data)) {
					data[section.PointerToRawData] ^= 1
					mutated = true
					break
				}
			}
			if !mutated {
				t.Fatal("fixture has no backed section to mutate")
			}
			result, err := f.VerifyAuthenticode(data, gope.AuthenticodeVerifyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Signatures) == 0 || len(result.Signatures[0].Signers) == 0 {
				t.Fatal("missing signature or signer")
			}
			sig := result.Signatures[0]
			if sig.Digest.Status != gope.AuthenticodeStatusInvalid || sig.Signers[0].CMS.Status != gope.AuthenticodeStatusValid || sig.Signers[0].Trust.Status != gope.AuthenticodeStatusUnchecked {
				t.Fatalf("unexpected tamper result: %+v", sig)
			}
			other, err := authenticode.Parse(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := other.Verify(sig.Signers[0].SignerCertificate); ok || err == nil {
				t.Fatal("go-uefi accepted modified image")
			}
		})
	}
}

func BenchmarkVerifyAuthenticodeCrossLibrary(b *testing.B) {
	data := goUEFIFixture(b, "authenticode/testdata/test.pecoff.signed")
	dbCert := parseFirstPEMCert(b, goUEFIFixture(b, "authenticode/testdata/db.pem"))

	b.Run("RealPECOFF/go-pe-OfflineIntegrity", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := gope.New(data)
			if err != nil {
				b.Fatal(err)
			}
			res, err := f.VerifyAuthenticode(data, gope.AuthenticodeVerifyOptions{})
			if err != nil || res.Signatures[0].Digest.Status != gope.AuthenticodeStatusValid {
				b.Fatalf("verify failed: %+v %v", res, err)
			}
			benchSinkAny = res
		}
	})

	b.Run("RealPECOFF/go-uefi", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			bin, err := authenticode.Parse(bytes.NewReader(data))
			if err != nil {
				b.Fatal(err)
			}
			ok, err := bin.Verify(dbCert)
			if err != nil || !ok {
				b.Fatalf("go-uefi verify = (%v, %v)", ok, err)
			}
			benchSinkAny = ok
		}
	})
}
