package pe

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestDecodeSpcStringOddLengthUTF16(t *testing.T) {
	if _, err := decodeSpcString(rawSpcString{Unicode: []byte{0x00, 'A', 0x00}}); !errors.Is(err, ErrInvalidAuthenticode) {
		t.Fatalf("odd-length SpcString.Unicode err = %v, want ErrInvalidAuthenticode", err)
	}
	got, err := decodeSpcString(rawSpcString{Unicode: []byte{0x00, 'A', 0x00, 'B'}})
	if err != nil || got != "AB" {
		t.Fatalf("valid SpcString.Unicode = (%q, %v), want (\"AB\", nil)", got, err)
	}
}

func TestResolveSignaturePlanEd25519Digest(t *testing.T) {
	alg := pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
	if _, status, _ := resolveSignaturePlan(alg, crypto.SHA256); status != AuthenticodeStatusInvalid {
		t.Fatalf("Ed25519 with SHA-256 status = %v, want invalid", status)
	}
	plan, status, reason := resolveSignaturePlan(alg, crypto.SHA512)
	if status != AuthenticodeStatusValid {
		t.Fatalf("Ed25519 with SHA-512 status = %v (%s), want valid", status, reason)
	}
	if plan.keyKind != sigKeyEd25519 || plan.x509Alg != x509.PureEd25519 {
		t.Fatalf("unexpected Ed25519 plan: %+v", plan)
	}
}

func TestTSTInfoOptionalFieldsAndTrailingGarbage(t *testing.T) {
	tstBytes, err := asn1.Marshal(rawTSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3, 4},
		MessageImprint: rawDigestInfo{
			DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			Digest:          make([]byte, 32),
		},
		SerialNumber: big.NewInt(42),
		GenTime:      time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
		Nonce:        big.NewInt(999),
	})
	if err != nil {
		t.Fatal(err)
	}

	var parsed rawTSTInfo
	rest, err := asn1.Unmarshal(tstBytes, &parsed)
	if err != nil || len(rest) != 0 {
		t.Fatalf("valid TSTInfo with Nonce failed: rest=%d err=%v", len(rest), err)
	}
	if parsed.Nonce == nil || parsed.Nonce.Cmp(big.NewInt(999)) != 0 {
		t.Fatalf("parsed Nonce = %v, want 999", parsed.Nonce)
	}

	// Trailing garbage after TSTInfo must be rejected by decodeRFC3161Timestamp.
	withTrailing := append(append([]byte(nil), tstBytes...), 0x05, 0x00)
	var ci rawContentInfo
	encapBytes, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOctetString,
		Bytes: withTrailing,
	})
	if err != nil {
		t.Fatal(err)
	}
	sdBytes, err := asn1.Marshal(rawSignedData{
		Version: 3,
		EncapContentInfo: rawContentInfo{
			ContentType: OIDTSTInfo,
			Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: encapBytes},
		},
		SignerInfos: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	ci = rawContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	}
	tokenDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}

	var budget authParseBudget
	if _, err := decodeRFC3161Timestamp(tokenDER, &budget); !errors.Is(err, ErrInvalidAuthenticode) {
		t.Fatalf("TSTInfo with trailing bytes err = %v, want ErrInvalidAuthenticode", err)
	}
}

func TestDecodeCRLSetInSignedData(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}, caCert, priv)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha512.Sum512([]byte("dummy"))
	spcBytes, err := asn1.Marshal(rawSpcIndirectDataContent{
		Data: rawSpcAttribute{Type: OIDSpcPEImageData},
		MessageDigest: rawDigestInfo{
			DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA512},
			Digest:          digest[:],
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sdBytes, err := asn1.Marshal(rawSignedData{
		Version: 1,
		EncapContentInfo: rawContentInfo{
			ContentType: OIDSpcIndirectDataContent,
			Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: spcBytes},
		},
		CRLs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: crlDER},
		SignerInfos: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkcs7DER, err := asn1.Marshal(rawContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	})
	if err != nil {
		t.Fatal(err)
	}

	sigs, err := ParseAuthenticodeSignatures(pkcs7DER)
	if err != nil {
		t.Fatalf("ParseAuthenticodeSignatures: %v", err)
	}
	if len(sigs) != 1 || len(sigs[0].CRLs) != 1 {
		t.Fatalf("expected 1 signature with 1 CRL, got sigs=%d crls=%d", len(sigs), len(sigs[0].CRLs))
	}
	if sigs[0].CRLs[0].Number.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("CRL number = %v, want 7", sigs[0].CRLs[0].Number)
	}
}
