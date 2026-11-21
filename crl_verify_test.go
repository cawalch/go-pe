package pe_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestVerifyAuthenticodeEmbeddedAndOptionCRLs(t *testing.T) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	base := testfixture.MinimalAligned(true)
	bf, err := pe.New(base)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := bf.AuthenticodeDigest(base, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	blob := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
		SignerCert:     pki.SignerCert,
		SignerKey:      pki.SignerKey,
		ExtraCerts:     []*x509.Certificate{pki.InterCert},
		ImageDigestAlg: crypto.SHA256,
		ImageDigest:    digest,
	})
	signedPE := testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  blob,
	})
	f, err := pe.New(signedPE)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := f.AuthenticodeSignatures(signedPE)
	if err != nil {
		t.Fatal(err)
	}

	// 1. No CRLs -> Revocation.Status == unchecked.
	res, err := f.VerifyAuthenticodeSignatures(signedPE, sigs, pe.AuthenticodeVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signatures[0].Signers[0].Revocation.Status != pe.AuthenticodeStatusUnchecked {
		t.Fatalf("no-CRL Revocation.Status = %v, want unchecked", res.Signatures[0].Signers[0].Revocation.Status)
	}

	// 2. Non-revoked CRL embedded in sigs[0].CRLs -> Revocation.Status == valid.
	cleanCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}, pki.InterCert, pki.InterKey)
	if err != nil {
		t.Fatal(err)
	}
	cleanCRL, err := x509.ParseRevocationList(cleanCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	sigsWithClean := append([]pe.AuthenticodeSignature(nil), sigs...)
	sigsWithClean[0].CRLs = []*x509.RevocationList{cleanCRL}
	res, err = f.VerifyAuthenticodeSignatures(signedPE, sigsWithClean, pe.AuthenticodeVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signatures[0].Signers[0].Revocation.Status != pe.AuthenticodeStatusValid {
		t.Fatalf("clean-CRL Revocation.Status = %v (%s), want valid",
			res.Signatures[0].Signers[0].Revocation.Status,
			res.Signatures[0].Signers[0].Revocation.Reason)
	}

	// 3. Revoked CRL -> Revocation.Status == invalid when evalTime >= RevocationTime.
	revTime := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	revCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: pki.SignerCert.SerialNumber, RevocationTime: revTime},
		},
	}, pki.InterCert, pki.InterKey)
	if err != nil {
		t.Fatal(err)
	}
	revCRL, err := x509.ParseRevocationList(revCRLDER)
	if err != nil {
		t.Fatal(err)
	}

	sigsWithRev := append([]pe.AuthenticodeSignature(nil), sigs...)
	sigsWithRev[0].CRLs = []*x509.RevocationList{revCRL}
	res, err = f.VerifyAuthenticodeSignatures(signedPE, sigsWithRev, pe.AuthenticodeVerifyOptions{
		VerificationTime: revTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signatures[0].Signers[0].Revocation.Status != pe.AuthenticodeStatusInvalid {
		t.Fatalf("revoked-CRL Revocation.Status = %v, want invalid", res.Signatures[0].Signers[0].Revocation.Status)
	}

	// 4. Evaluation time BEFORE RevocationTime -> Revocation.Status == valid.
	res, err = f.VerifyAuthenticodeSignatures(signedPE, sigsWithRev, pe.AuthenticodeVerifyOptions{
		VerificationTime: revTime.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signatures[0].Signers[0].Revocation.Status != pe.AuthenticodeStatusValid {
		t.Fatalf("pre-revocation Revocation.Status = %v, want valid", res.Signatures[0].Signers[0].Revocation.Status)
	}

	// 5. Caller-supplied CRL via AuthenticodeVerifyOptions.CRLs.
	res, err = f.VerifyAuthenticodeSignatures(signedPE, sigs, pe.AuthenticodeVerifyOptions{
		CRLs: []*x509.RevocationList{revCRL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signatures[0].Signers[0].Revocation.Status != pe.AuthenticodeStatusInvalid {
		t.Fatalf("option-CRL Revocation.Status = %v, want invalid", res.Signatures[0].Signers[0].Revocation.Status)
	}

	// 6. Spoofed CRL signed by wrong key -> Revocation.Status == unchecked.
	otherPKI := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	spoofCRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(3),
		ThisUpdate: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: pki.SignerCert.SerialNumber, RevocationTime: revTime},
		},
	}, otherPKI.InterCert, otherPKI.InterKey)
	if err != nil {
		t.Fatal(err)
	}
	spoofCRL, err := x509.ParseRevocationList(spoofCRLDER)
	if err != nil {
		t.Fatal(err)
	}
	spoofCRL.RawIssuer = append([]byte(nil), pki.InterCert.RawSubject...)
	res, err = f.VerifyAuthenticodeSignatures(signedPE, sigs, pe.AuthenticodeVerifyOptions{
		CRLs: []*x509.RevocationList{spoofCRL},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signatures[0].Signers[0].Revocation.Status != pe.AuthenticodeStatusUnchecked {
		t.Fatalf("spoofed-CRL Revocation.Status = %v, want unchecked", res.Signatures[0].Signers[0].Revocation.Status)
	}
}
