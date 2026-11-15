package pe_test

import (
	"crypto"
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzAuthenticodeVerify(f *testing.F) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	base := testfixture.MinimalAligned(true)
	bf, _ := pe.New(base)
	digest, _ := bf.AuthenticodeDigest(base, crypto.SHA256)
	validBlob := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
		SignerCert:  pki.SignerCert,
		SignerKey:   pki.SignerKey,
		ImageDigest: digest,
		RFC3161At:   time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		TSACert:     pki.TSACert,
		TSAKey:      pki.TSAKey,
	})
	dupBlob := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
		SignerCert:             pki.SignerCert,
		SignerKey:              pki.SignerKey,
		ImageDigest:            digest,
		DuplicateMessageDigest: true,
	})

	f.Add(testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  validBlob,
	}))
	f.Add(testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  dupBlob,
	}))
	f.Add(testfixture.Certificates(false))
	f.Add([]byte("MZ\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		parsed, err := pe.New(data)
		if err != nil {
			return
		}
		_, _ = parsed.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
		_, _ = parsed.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{
			Roots:            pki.RootPool,
			VerificationTime: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		})
	})
}
