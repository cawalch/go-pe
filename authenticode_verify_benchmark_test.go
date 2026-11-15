package pe_test

import (
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkVerifyAuthenticode(b *testing.B) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	sigTime := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	makeSigned := func(extraPayload int, withTS, nested bool) ([]byte, *pe.File) {
		base := testfixture.MinimalAligned(true)
		if extraPayload > 0 {
			base = append(base, make([]byte, extraPayload)...)
		}
		bf, err := pe.New(base)
		if err != nil {
			b.Fatal(err)
		}
		digest, err := bf.AuthenticodeDigest(base, crypto.SHA256)
		if err != nil {
			b.Fatal(err)
		}
		var nestedBlobs [][]byte
		if nested {
			nestedBlobs = [][]byte{testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
				SignerCert:  pki.SignerCert,
				SignerKey:   pki.SignerKey,
				ExtraCerts:  []*x509.Certificate{pki.InterCert},
				ImageDigest: digest,
			})}
		}
		tsAt := time.Time{}
		if withTS {
			tsAt = sigTime
		}
		blob := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
			SignerCert:  pki.SignerCert,
			SignerKey:   pki.SignerKey,
			ExtraCerts:  []*x509.Certificate{pki.InterCert},
			ImageDigest: digest,
			RFC3161At:   tsAt,
			TSACert:     pki.TSACert,
			TSAKey:      pki.TSAKey,
			NestedBlobs: nestedBlobs,
		})
		signed := testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
			Revision: pe.CertificateRevision2_0,
			Type:     pe.CertificateTypePKCS7SignedData,
			Payload:  blob,
		})
		f, err := pe.New(signed)
		if err != nil {
			b.Fatal(err)
		}
		return signed, f
	}

	singleData, singleFile := makeSigned(0, false, false)
	nestedData, nestedFile := makeSigned(0, true, true)
	largeData, largeFile := makeSigned(4<<20, true, false)

	b.Run("ParseOnly/SingleSigned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sigs, err := singleFile.AuthenticodeSignatures(singleData)
			if err != nil || len(sigs) != 1 {
				b.Fatalf("sigs=%d err=%v", len(sigs), err)
			}
		}
	})

	b.Run("VerifyOffline/SingleSigned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			res, err := singleFile.VerifyAuthenticode(singleData, pe.AuthenticodeVerifyOptions{})
			if err != nil || res.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusValid {
				b.Fatalf("res=%+v err=%v", res, err)
			}
		}
	})

	b.Run("VerifyWithRoots/SingleSigned", func(b *testing.B) {
		opts := pe.AuthenticodeVerifyOptions{
			Roots:            pki.RootPool,
			VerificationTime: sigTime,
		}
		b.ReportAllocs()
		for b.Loop() {
			res, err := singleFile.VerifyAuthenticode(singleData, opts)
			if err != nil || res.Signatures[0].Signers[0].Trust.Status != pe.AuthenticodeStatusValid {
				b.Fatalf("res=%+v err=%v", res, err)
			}
		}
	})

	b.Run("VerifyWithRoots/NestedAndRFC3161", func(b *testing.B) {
		opts := pe.AuthenticodeVerifyOptions{Roots: pki.RootPool}
		b.ReportAllocs()
		for b.Loop() {
			res, err := nestedFile.VerifyAuthenticode(nestedData, opts)
			if err != nil || len(res.Signatures) != 2 || res.Signatures[0].Signers[0].Trust.Status != pe.AuthenticodeStatusValid {
				b.Fatalf("res=%+v err=%v", res, err)
			}
		}
	})

	b.Run("VerifyOffline/Large4MiBWithRFC3161", func(b *testing.B) {
		b.SetBytes(int64(len(largeData)))
		b.ReportAllocs()
		for b.Loop() {
			res, err := largeFile.VerifyAuthenticode(largeData, pe.AuthenticodeVerifyOptions{})
			if err != nil || res.Signatures[0].Digest.Status != pe.AuthenticodeStatusValid {
				b.Fatalf("res=%+v err=%v", res, err)
			}
		}
	})

	b.Run("NonSignatureCost/HeaderParseMinimal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := pe.New(singleData)
			if err != nil || !f.Is64Bit() {
				b.Fatalf("New=%v", err)
			}
		}
	})
}
