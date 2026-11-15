package exports_test

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func TestCrossLibraryAuthenticode(t *testing.T) {
	sigTime := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)

	t.Run("NestedAndValidECDSA", func(t *testing.T) {
		inner, innerCert := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
			CommonName:         "Nested ECDSA Signer",
			SigningTime:        sigTime.Add(time.Minute),
			IncludeCertificate: true,
		})
		outer, outerCert := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
			CommonName:         "Outer ECDSA Signer",
			SigningTime:        sigTime,
			IncludeCertificate: true,
			NestedBlobs:        [][]byte{inner},
		})
		data := testfixture.Certificates(true, testfixture.CertificateSpec{
			Revision: gope.CertificateRevision2_0,
			Type:     gope.CertificateTypePKCS7SignedData,
			Payload:  outer,
		})

		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		sigs, err := gp.AuthenticodeSignatures(data)
		if err != nil {
			t.Fatalf("go-pe AuthenticodeSignatures: %v", err)
		}
		if len(sigs) != 2 {
			t.Fatalf("go-pe sigs = %d, want 2", len(sigs))
		}
		if !bytes.Equal(sigs[0].Certificates[0].Raw, outerCert.Raw) ||
			!bytes.Equal(sigs[1].Certificates[0].Raw, innerCert.Raw) {
			t.Fatalf("go-pe certificate mismatch")
		}

		sw, err := saferwall.NewBytes(data, securityOptions())
		if err != nil {
			t.Fatalf("saferwall NewBytes: %v", err)
		}
		if err := sw.Parse(); err != nil {
			t.Fatalf("saferwall Parse: %v", err)
		}
		if len(sw.Certificates.Certificates) != 2 {
			t.Fatalf("saferwall certs = %d, want 2", len(sw.Certificates.Certificates))
		}
	})

	t.Run("UnknownSignatureOIDPreserved", func(t *testing.T) {
		customOID := asn1.ObjectIdentifier{1, 2, 3, 999, 42}
		blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
			SigAlgorithmOID:    customOID,
			IncludeCertificate: true,
		})
		data := testfixture.Certificates(true, testfixture.CertificateSpec{
			Revision: gope.CertificateRevision2_0,
			Type:     gope.CertificateTypePKCS7SignedData,
			Payload:  blob,
		})

		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		sigs, err := gp.AuthenticodeSignatures(data)
		if err != nil {
			t.Fatalf("go-pe AuthenticodeSignatures: %v", err)
		}
		if len(sigs) != 1 || !sigs[0].Signers[0].SignatureAlgorithm.Algorithm.Equal(customOID) {
			t.Fatalf("expected unknown signature OID %s preserved", customOID)
		}
	})

	t.Run("MalformedTruncatedHighTagBER", func(t *testing.T) {
		data := testfixture.Certificates(true, testfixture.CertificateSpec{
			Revision: gope.CertificateRevision2_0,
			Type:     gope.CertificateTypePKCS7SignedData,
			Payload:  []byte{0x1f, 0x81},
		})
		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		if _, err := gp.AuthenticodeSignatures(data); !errors.Is(err, gope.ErrInvalidAuthenticode) {
			t.Fatalf("go-pe err = %v, want ErrInvalidAuthenticode", err)
		}
	})
}

func BenchmarkParseAuthenticode(b *testing.B) {
	opts := securityOptions()
	inner, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		CommonName:         "Nested ECDSA Signer",
		SigningTime:        time.Date(2026, 6, 1, 10, 1, 0, 0, time.UTC),
		IncludeCertificate: true,
	})
	outer, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		CommonName:         "Outer ECDSA Signer",
		SigningTime:        time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC),
		IncludeCertificate: true,
		NestedBlobs:        [][]byte{inner},
	})
	signedPE := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: gope.CertificateRevision2_0,
		Type:     gope.CertificateTypePKCS7SignedData,
		Payload:  outer,
	})

	b.Run("Nested2/go-pe", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, err := gope.New(signedPE)
			if err != nil {
				b.Fatal(err)
			}
			sigs, err := f.AuthenticodeSignatures(signedPE)
			if err != nil {
				b.Fatal(err)
			}
			if len(sigs) != 2 {
				b.Fatalf("sigs = %d, want 2", len(sigs))
			}
			benchSinkAny = sigs
		}
	})

	b.Run("Nested2/saferwall-SecurityOnly", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			f, _ := saferwall.NewBytes(signedPE, opts)
			if err := f.Parse(); err != nil {
				b.Fatal(err)
			}
			benchSinkAny = f
		}
	})
}
