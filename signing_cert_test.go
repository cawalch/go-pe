package pe

import (
	"crypto/sha1" // #nosec G505 -- RFC 2634 SigningCertificate uses SHA-1.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestValidateSigningCertificateAttributes(t *testing.T) {
	rawCert := []byte("synthetic-der-cert-bytes")
	cert := &x509.Certificate{Raw: rawCert}
	sha1Sum := sha1.Sum(rawCert) // #nosec G401 -- RFC 2634 SigningCertificate uses SHA-1.
	sha256Sum := sha256.Sum256(rawCert)

	// 1. Valid SigningCertificate (RFC 2634).
	scBytes, err := asn1.Marshal(rawSigningCertificate{
		Certs: []rawESSCertID{{CertHash: sha1Sum[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	attr1 := AuthenticodeAttribute{Type: oidSigningCertificate, Values: [][]byte{scBytes}}
	if st, reason := validateSigningCertificateAttr(attr1, cert, AuthenticodeStatusValid); st != AuthenticodeStatusValid {
		t.Fatalf("valid SigningCertificate got %v (%s)", st, reason)
	}

	// Mismatched hash -> Invalid.
	badHash := append([]byte(nil), sha1Sum[:]...)
	badHash[0] ^= 0xff
	badSCBytes, err := asn1.Marshal(rawSigningCertificate{
		Certs: []rawESSCertID{{CertHash: badHash}},
	})
	if err != nil {
		t.Fatal(err)
	}
	badAttr1 := AuthenticodeAttribute{Type: oidSigningCertificate, Values: [][]byte{badSCBytes}}
	if st, _ := validateSigningCertificateAttr(badAttr1, cert, AuthenticodeStatusValid); st != AuthenticodeStatusInvalid {
		t.Fatalf("mismatched SigningCertificate got %v, want invalid", st)
	}

	// 2. Valid SigningCertificateV2 with default SHA-256 (omitted HashAlgorithm).
	scv2Default, err := asn1.Marshal(rawSigningCertificateV2{
		Certs: []rawESSCertIDv2{{CertHash: sha256Sum[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	attr2 := AuthenticodeAttribute{Type: oidSigningCertificateV2, Values: [][]byte{scv2Default}}
	if st, reason := validateSigningCertificateV2Attr(attr2, cert, AuthenticodeStatusValid); st != AuthenticodeStatusValid {
		t.Fatalf("valid SigningCertificateV2 (default SHA-256) got %v (%s)", st, reason)
	}

	// Mismatched SHA-256 -> Invalid.
	badSHA256 := append([]byte(nil), sha256Sum[:]...)
	badSHA256[0] ^= 0xff
	scv2Bad, err := asn1.Marshal(rawSigningCertificateV2{
		Certs: []rawESSCertIDv2{{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidDigestSHA256},
			CertHash:      badSHA256,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := validateSigningCertificateV2Attr(AuthenticodeAttribute{Type: oidSigningCertificateV2, Values: [][]byte{scv2Bad}}, cert, AuthenticodeStatusValid); st != AuthenticodeStatusInvalid {
		t.Fatalf("mismatched SigningCertificateV2 got %v, want invalid", st)
	}

	// Unsupported hash algorithm OID -> Unsupported.
	scv2Unsupported, err := asn1.Marshal(rawSigningCertificateV2{
		Certs: []rawESSCertIDv2{{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
			CertHash:      sha256Sum[:],
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := validateSigningCertificateV2Attr(AuthenticodeAttribute{Type: oidSigningCertificateV2, Values: [][]byte{scv2Unsupported}}, cert, AuthenticodeStatusValid); st != AuthenticodeStatusUnsupported {
		t.Fatalf("unsupported SigningCertificateV2 got %v, want unsupported", st)
	}
}
