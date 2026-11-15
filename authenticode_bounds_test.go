package pe_test

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestAuthenticodeMalformedBERAndCMS(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "Empty", raw: nil, want: pe.ErrInvalidAuthenticode},
		{name: "TruncatedHighTag", raw: []byte{0x1f, 0x81}, want: pe.ErrInvalidAuthenticode},
		{name: "NonMinimalHighTag", raw: []byte{0x1f, 0x80, 0x01, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "TooManyHighTagOctets", raw: []byte{0x1f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "PrimitiveIndefinite", raw: []byte{0x04, 0x80, 0x00, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "UnterminatedIndefinite", raw: []byte{0x30, 0x80, 0x05, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "ChildExceedsParent", raw: []byte{0x30, 0x02, 0x04, 0x05, 1, 2, 3, 4, 5}, want: pe.ErrInvalidAuthenticode},
		{name: "EOCOutsideParent", raw: []byte{0x30, 0x02, 0x30, 0x80, 0x00, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "LongForm31BitOverflow", raw: []byte{0x30, 0x84, 0x80, 0x00, 0x00, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "UnsupportedLengthBytes", raw: []byte{0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, want: pe.ErrInvalidAuthenticode},
		{name: "TrailingNonZeroBytes", raw: []byte{0x30, 0x00, 0x01}, want: pe.ErrInvalidAuthenticode},
		{name: "WrongContentType", raw: func() []byte {
			b, _ := asn1.Marshal(struct {
				OID     asn1.ObjectIdentifier
				Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
			}{OID: asn1.ObjectIdentifier{1, 2, 3, 4}})
			return b
		}(), want: pe.ErrInvalidAuthenticode},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs, err := pe.ParseAuthenticodeSignatures(tc.raw)
			if !errors.Is(err, tc.want) || sigs != nil {
				t.Fatalf("ParseAuthenticodeSignatures() = (%v, %v), want (nil, %v)", sigs, err, tc.want)
			}
		})
	}
}

func TestAuthenticodeLimits(t *testing.T) {
	t.Run("BERNestingDepth", func(t *testing.T) {
		// Build MaxASN1Depth + 1 nested indefinite SEQUENCEs around NULL.
		buf := []byte{0x05, 0x00}
		for range pe.MaxASN1Depth + 1 {
			buf = append(append([]byte{0x30, 0x80}, buf...), 0x00, 0x00)
		}
		if sigs, err := pe.ParseAuthenticodeSignatures(buf); !errors.Is(err, pe.ErrAuthenticodeLimit) || sigs != nil {
			t.Fatalf("depth limit = (%v, %v), want (nil, ErrAuthenticodeLimit)", sigs, err)
		}
	})

	t.Run("BERElementCount", func(t *testing.T) {
		elem := []byte{0x05, 0x00}
		count := pe.MaxASN1Elements + 1
		body := bytes.Repeat(elem, count)
		outer := []byte{0x30, 0x83, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
		outer = append(outer, body...)
		if sigs, err := pe.ParseAuthenticodeSignatures(outer); !errors.Is(err, pe.ErrAuthenticodeLimit) || sigs != nil {
			t.Fatalf("element limit = (%v, %v), want (nil, ErrAuthenticodeLimit)", sigs, err)
		}
	})

	t.Run("NestedSignatureDepth", func(t *testing.T) {
		blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{})
		for range pe.MaxNestedSignatures + 1 {
			blob, _ = testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
				NestedBlobs: [][]byte{blob},
			})
		}
		if sigs, err := pe.ParseAuthenticodeSignatures(blob); !errors.Is(err, pe.ErrAuthenticodeLimit) || sigs != nil {
			t.Fatalf("nested limit = (%v, %v), want (nil, ErrAuthenticodeLimit)", sigs, err)
		}
	})

	t.Run("CertificateCountLimit", func(t *testing.T) {
		blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
			ExtraCertificates: pe.MaxAuthenticodeCertificates + 1,
		})
		if sigs, err := pe.ParseAuthenticodeSignatures(blob); !errors.Is(err, pe.ErrAuthenticodeLimit) || sigs != nil {
			t.Fatalf("certificate limit = (%v, %v), want (nil, ErrAuthenticodeLimit)", sigs, err)
		}
	})

	t.Run("MultiRecordFailureReturnsNilSlice", func(t *testing.T) {
		validBlob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{IncludeCertificate: true})
		data := testfixture.Certificates(true,
			testfixture.CertificateSpec{
				Revision: pe.CertificateRevision2_0,
				Type:     pe.CertificateTypePKCS7SignedData,
				Payload:  validBlob,
			},
			testfixture.CertificateSpec{
				Revision: pe.CertificateRevision2_0,
				Type:     pe.CertificateTypePKCS7SignedData,
				Payload:  []byte{0x30, 0x80, 0x04, 0x01}, // Malformed second record.
			},
		)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if sigs, err := f.AuthenticodeSignatures(data); !errors.Is(err, pe.ErrInvalidAuthenticode) || sigs != nil {
			t.Fatalf("partial record failure = (%v, %v), want (nil, ErrInvalidAuthenticode)", sigs, err)
		}
	})

	t.Run("CertificateSerialBytesErrors", func(t *testing.T) {
		if b, err := pe.CertificateSerialBytes(nil); !errors.Is(err, pe.ErrInvalidAuthenticode) || b != nil {
			t.Fatalf("nil cert = (%v, %v), want (nil, ErrInvalidAuthenticode)", b, err)
		}
		badCert := &x509.Certificate{RawTBSCertificate: []byte{0x30, 0x02, 0x05, 0x00}}
		if b, err := pe.CertificateSerialBytes(badCert); !errors.Is(err, pe.ErrInvalidAuthenticode) || b != nil {
			t.Fatalf("bad TBS = (%v, %v), want (nil, ErrInvalidAuthenticode)", b, err)
		}
	})

	t.Run("SignerAndSignatureLimits", func(t *testing.T) {
		// Build > MaxAuthenticodeSignatures WIN_CERTIFICATE records.
		baseBlob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{})
		tooManyRecs := make([]testfixture.CertificateSpec, pe.MaxAuthenticodeSignatures+1)
		for i := range tooManyRecs {
			tooManyRecs[i] = testfixture.CertificateSpec{
				Revision: pe.CertificateRevision2_0,
				Type:     pe.CertificateTypePKCS7SignedData,
				Payload:  baseBlob,
			}
		}
		peMany := testfixture.Certificates(true, tooManyRecs...)
		fMany, err := pe.New(peMany)
		if err != nil {
			t.Fatalf("New(peMany) error = %v", err)
		}
		if sigs, err := fMany.AuthenticodeSignatures(peMany); !errors.Is(err, pe.ErrAuthenticodeLimit) || sigs != nil {
			t.Fatalf("signature limit = (%v, %v), want (nil, ErrAuthenticodeLimit)", sigs, err)
		}

		// Exceed MaxAuthenticodeSignatures via multiple nested entries in one layer (exceeding MaxAuthenticodeSigners/Signatures).
		leaf, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{})
		manyNested := make([][]byte, pe.MaxAuthenticodeSignatures)
		for i := range manyNested {
			manyNested[i] = leaf
		}
		fanout, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
			NestedBlobs: manyNested,
		})
		if sigs, err := pe.ParseAuthenticodeSignatures(fanout); !errors.Is(err, pe.ErrAuthenticodeLimit) || sigs != nil {
			t.Fatalf("nested fanout limit = (%v, %v), want (nil, ErrAuthenticodeLimit)", sigs, err)
		}
	})
}
