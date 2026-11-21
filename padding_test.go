package pe_test

import (
	"crypto"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestAuthenticodeTrailingPaddingAndStrictPadding(t *testing.T) {
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
		ImageDigestAlg: crypto.SHA256,
		ImageDigest:    digest,
	})

	// Clean signature: Padding.Status == valid.
	cleanPE := testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  blob,
	})
	cf, err := pe.New(cleanPE)
	if err != nil {
		t.Fatal(err)
	}
	cleanVer, err := cf.VerifyAuthenticode(cleanPE, pe.AuthenticodeVerifyOptions{StrictPadding: true})
	if err != nil {
		t.Fatal(err)
	}
	if cleanVer.Signatures[0].Padding.Status != pe.AuthenticodeStatusValid {
		t.Fatalf("clean Padding.Status = %v, want valid", cleanVer.Signatures[0].Padding.Status)
	}

	// Padded PKCS#7 payload with 8 trailing NUL bytes:
	// - TrailingPaddingBytes == 8
	// - StrictPadding=false -> Padding.Status == unchecked
	// - StrictPadding=true  -> Padding.Status == invalid
	paddedBlob := append(append([]byte(nil), blob...), make([]byte, 8)...)
	paddedPE := testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  paddedBlob,
	})
	pf, err := pe.New(paddedPE)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := pf.AuthenticodeSignatures(paddedPE)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0].TrailingPaddingBytes != 8 {
		t.Fatalf("TrailingPaddingBytes = %d, want 8", sigs[0].TrailingPaddingBytes)
	}

	permissive, err := pf.VerifyAuthenticodeSignatures(paddedPE, sigs, pe.AuthenticodeVerifyOptions{SkipImageDigest: true})
	if err != nil {
		t.Fatal(err)
	}
	if permissive.Signatures[0].Padding.Status != pe.AuthenticodeStatusUnchecked {
		t.Fatalf("permissive Padding.Status = %v, want unchecked", permissive.Signatures[0].Padding.Status)
	}

	strict, err := pf.VerifyAuthenticodeSignatures(paddedPE, sigs, pe.AuthenticodeVerifyOptions{
		SkipImageDigest: true,
		StrictPadding:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strict.Signatures[0].Padding.Status != pe.AuthenticodeStatusInvalid {
		t.Fatalf("strict Padding.Status = %v, want invalid", strict.Signatures[0].Padding.Status)
	}
}

func TestCertificateAlignmentPaddingNonZero(t *testing.T) {
	// 5-byte payload -> dwLength=13, 3 bytes of 8-byte alignment padding at end.
	img := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypeX509,
		Payload:  []byte{1, 2, 3, 4, 5},
	})
	f, err := pe.New(img)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := f.Certificates(img)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Certificates = (%v, %v)", recs, err)
	}
	if recs[0].PaddingNonZero {
		t.Fatal("expected PaddingNonZero=false for zeroed alignment padding")
	}

	// Flip a byte in the 8-byte alignment padding after dwLength.
	dir := f.OptionalHeader.DataDirectories[pe.DataDirectoryCertificate]
	padOff := int(dir.VirtualAddress) + int(binary.LittleEndian.Uint32(img[dir.VirtualAddress:]))
	img[padOff] = 0xff

	recs, err = f.Certificates(img)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Certificates(non-zero pad) = (%v, %v)", recs, err)
	}
	if !recs[0].PaddingNonZero {
		t.Fatal("expected PaddingNonZero=true for non-zero alignment padding")
	}
}
