package pe_test

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestAuthenticodeSignaturesMetadata(t *testing.T) {
	sigTime := time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	tsPKCS9 := time.Date(2026, 5, 1, 12, 31, 0, 0, time.UTC)
	tsRFC3161 := time.Date(2026, 5, 1, 12, 32, 0, 0, time.UTC)

	nestedBlob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		CommonName:         "Nested SHA256 Signer",
		Serial:             big.NewInt(0x7777),
		SigningTime:        sigTime.Add(time.Minute),
		IncludeCertificate: true,
	})

	// High-bit serial (0x80ff) requires an ASN.1 leading 0x00 octet in DER INTEGER.
	highBitSerial := new(big.Int).SetBytes([]byte{0x80, 0xab, 0xcd})
	primaryBlob, cert := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		CommonName:           "Primary Code Signer",
		Serial:               highBitSerial,
		DigestAlgorithmOID:   asn1.ObjectIdentifier{1, 2, 3, 999, 1}, // Unknown digest OID preserved.
		SigAlgorithmOID:      asn1.ObjectIdentifier{1, 2, 3, 999, 2}, // Unknown signature OID preserved.
		SigningTime:          sigTime,
		ProgramName:          "TestBinary",
		MoreInfoURL:          "https://example.invalid/info",
		IncludeCertificate:   true,
		SecondSigner:         true,
		DuplicateSigningTime: true,
		UnknownAttrOID:       asn1.ObjectIdentifier{1, 2, 3, 999, 3},
		PKCS9CountersignAt:   tsPKCS9,
		RFC3161TimestampAt:   tsRFC3161,
		NestedBlobs:          [][]byte{nestedBlob},
	})

	for _, tc := range []struct {
		name string
		is64 bool
	}{
		{name: "PE32", is64: false},
		{name: "PE32Plus", is64: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := testfixture.Certificates(tc.is64,
				testfixture.CertificateSpec{
					Revision: pe.CertificateRevision2_0,
					Type:     pe.CertificateTypeX509, // Non-PKCS7 entry must be skipped cleanly.
					Payload:  []byte{1, 2, 3},
				},
				testfixture.CertificateSpec{
					Revision: pe.CertificateRevision2_0,
					Type:     pe.CertificateTypePKCS7SignedData,
					Payload:  primaryBlob,
				},
			)
			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			sigs, err := f.AuthenticodeSignatures(data)
			if err != nil {
				t.Fatalf("AuthenticodeSignatures() error = %v", err)
			}
			if len(sigs) != 2 {
				t.Fatalf("len(sigs) = %d, want 2 (outer + nested)", len(sigs))
			}

			outer := sigs[0]
			if outer.NestedDepth != 0 {
				t.Errorf("outer.NestedDepth = %d, want 0", outer.NestedDepth)
			}
			if outer.RecordOffset == 0 {
				t.Errorf("outer.RecordOffset = 0, want nonzero PE offset")
			}
			if !outer.ContentType.Equal(pe.OIDSpcIndirectDataContent) {
				t.Errorf("outer.ContentType = %s, want %s", outer.ContentType, pe.OIDSpcIndirectDataContent)
			}
			if outer.IndirectData == nil || !outer.IndirectData.DataTypeOID.Equal(pe.OIDSpcPEImageData) {
				t.Fatalf("outer.IndirectData = %+v", outer.IndirectData)
			}
			if !outer.IndirectData.DigestAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 3, 999, 1}) {
				t.Errorf("unknown IndirectData digest OID not preserved: %s", outer.IndirectData.DigestAlgorithm.Algorithm)
			}
			if len(outer.Certificates) != 1 || !bytes.Equal(outer.Certificates[0].Raw, cert.Raw) {
				t.Fatalf("unexpected outer certificates: %d", len(outer.Certificates))
			}

			// Verify raw ASN.1 serial integer octets preserve leading 0x00 for high-bit serial.
			serialBytes, err := pe.CertificateSerialBytes(outer.Certificates[0])
			if err != nil {
				t.Fatalf("CertificateSerialBytes() error = %v", err)
			}
			wantSerialBytes := []byte{0x00, 0x80, 0xab, 0xcd}
			if !bytes.Equal(serialBytes, wantSerialBytes) {
				t.Errorf("CertificateSerialBytes() = %x, want %x", serialBytes, wantSerialBytes)
			}

			if len(outer.Signers) != 2 {
				t.Fatalf("len(outer.Signers) = %d, want 2", len(outer.Signers))
			}
			signer := outer.Signers[0]
			if !bytes.Equal(signer.SerialBytes, wantSerialBytes) {
				t.Errorf("signer.SerialBytes = %x, want %x", signer.SerialBytes, wantSerialBytes)
			}
			if !signer.HasSigningTime || !signer.SigningTime.Equal(sigTime) {
				t.Errorf("signer.SigningTime = (%v, %v), want (%v, true)", signer.SigningTime, signer.HasSigningTime, sigTime)
			}
			if signer.OpusInfo == nil || signer.OpusInfo.ProgramName != "TestBinary" || signer.OpusInfo.MoreInfoURL != "https://example.invalid/info" {
				t.Errorf("signer.OpusInfo = %+v", signer.OpusInfo)
			}
			if !signer.SignatureAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 3, 999, 2}) {
				t.Errorf("unknown signer signature OID not preserved: %s", signer.SignatureAlgorithm.Algorithm)
			}
			if len(signer.RawAuthenticatedAttributes) == 0 || signer.RawAuthenticatedAttributes[0] != 0x31 {
				t.Errorf("RawAuthenticatedAttributes header byte = %#x, want 0x31", signer.RawAuthenticatedAttributes[0])
			}

			// Unknown attribute OID preserved in file order alongside duplicate attributes.
			var unknownFound bool
			for _, attr := range signer.AuthenticatedAttributes {
				if attr.Type.Equal(asn1.ObjectIdentifier{1, 2, 3, 999, 3}) {
					unknownFound = true
				}
			}
			if !unknownFound {
				t.Errorf("unknown authenticated attribute OID not preserved")
			}

			// Verify both PKCS#9 and RFC 3161 timestamps were decoded.
			if len(signer.Timestamps) != 2 {
				t.Fatalf("len(signer.Timestamps) = %d, want 2", len(signer.Timestamps))
			}
			if signer.Timestamps[0].Kind != pe.AuthenticodeTimestampPKCS9 || !signer.Timestamps[0].SigningTime.Equal(tsPKCS9) {
				t.Errorf("PKCS#9 timestamp = %+v, want %v", signer.Timestamps[0], tsPKCS9)
			}
			if signer.Timestamps[1].Kind != pe.AuthenticodeTimestampRFC3161 || !signer.Timestamps[1].SigningTime.Equal(tsRFC3161) {
				t.Errorf("RFC3161 timestamp = %+v, want %v", signer.Timestamps[1], tsRFC3161)
			}

			nested := sigs[1]
			if nested.NestedDepth != 1 || nested.RecordOffset != outer.RecordOffset {
				t.Errorf("nested = (depth %d, off %#x), want (1, %#x)", nested.NestedDepth, nested.RecordOffset, outer.RecordOffset)
			}

			// Ownership invariant: clearing input buffers must not mutate returned slices or certs.
			wantCertRaw := bytes.Clone(outer.Certificates[0].Raw)
			wantContent := bytes.Clone(outer.Content)
			wantDigest := bytes.Clone(outer.IndirectData.Digest)
			wantIssuer := bytes.Clone(signer.IssuerRaw)
			wantTSRaw := bytes.Clone(signer.Timestamps[1].Raw)
			clear(data)
			if !bytes.Equal(outer.Certificates[0].Raw, wantCertRaw) ||
				!bytes.Equal(outer.Content, wantContent) ||
				!bytes.Equal(outer.IndirectData.Digest, wantDigest) ||
				!bytes.Equal(signer.IssuerRaw, wantIssuer) ||
				!bytes.Equal(signer.Timestamps[1].Raw, wantTSRaw) {
				t.Fatalf("returned metadata aliased caller PE buffer after clear(data)")
			}
		})
	}
}

func TestAuthenticodeIndefiniteBERMissingCertAndPadding(t *testing.T) {
	derBlob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: false, // Missing certificates bag allowed during metadata parse.
		SigningTime:        time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC),
	})

	// Test direct DER with trailing NUL padding inside WIN_CERTIFICATE.
	padded := append(bytes.Clone(derBlob), 0, 0, 0)
	sigs, err := pe.ParseAuthenticodeSignatures(padded)
	if err != nil {
		t.Fatalf("ParseAuthenticodeSignatures(padded) error = %v", err)
	}
	if len(sigs) != 1 || len(sigs[0].Certificates) != 0 || len(sigs[0].Signers) != 1 {
		t.Fatalf("unexpected missing-cert result: %+v", sigs)
	}

	// Wrap outer ContentInfo SEQUENCE with indefinite-length BER (0x30 0x80 ... 0x00 0x00).
	innerPos := 2
	if derBlob[1] >= 0x80 {
		innerPos += int(derBlob[1] & 0x7f)
	}
	indefBER := append([]byte{0x30, 0x80}, derBlob[innerPos:]...)
	indefBER = append(indefBER, 0x00, 0x00)
	berSigs, err := pe.ParseAuthenticodeSignatures(indefBER)
	if err != nil {
		t.Fatalf("ParseAuthenticodeSignatures(indefBER) error = %v", err)
	}
	if len(berSigs) != 1 || len(berSigs[0].Signers) != 1 {
		t.Fatalf("unexpected BER parse result: %+v", berSigs)
	}

	// Ownership on ParseAuthenticodeSignatures(buf) after clear(buf).
	wantContent := bytes.Clone(sigs[0].Content)
	clear(padded)
	if !bytes.Equal(sigs[0].Content, wantContent) {
		t.Fatalf("ParseAuthenticodeSignatures aliased caller input slice")
	}
}

func TestAuthenticodeAbsentDirectoryZeroAllocAndConcurrent(t *testing.T) {
	minimal := testfixture.Minimal(true, 1)
	fMin, err := pe.New(minimal)
	if err != nil {
		t.Fatalf("New(minimal) error = %v", err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		sigs, err := fMin.AuthenticodeSignatures(minimal)
		if err != nil || sigs != nil {
			t.Fatalf("AuthenticodeSignatures(minimal) = (%v, %v), want (nil, nil)", sigs, err)
		}
	})
	if allocs != 0 {
		t.Fatalf("absent security directory allocs = %v, want 0", allocs)
	}

	blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{IncludeCertificate: true})
	signed := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  blob,
	})
	f, err := pe.New(signed)
	if err != nil {
		t.Fatalf("New(signed) error = %v", err)
	}

	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			sigs, err := f.AuthenticodeSignatures(signed)
			if err != nil || len(sigs) != 1 {
				t.Errorf("concurrent AuthenticodeSignatures = (%d sigs, %v)", len(sigs), err)
			}
		})
	}
	wg.Wait()
}
