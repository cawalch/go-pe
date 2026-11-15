package exports_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func securityOptions() *saferwall.Options {
	opts := exportOptions()
	opts.OmitExportDirectory = true
	opts.OmitSecurityDirectory = false
	opts.DisableCertValidation = true
	opts.DisableSignatureValidation = true
	opts.Logger = discardLogger{}
	return opts
}

func TestCrossLibraryCertificates(t *testing.T) {
	t.Run("Absent", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		recs, err := gp.Certificates(data)
		if err != nil || recs != nil {
			t.Fatalf("go-pe Certificates = (%v, %v), want (nil, nil)", recs, err)
		}

		sw, err := saferwall.NewBytes(data, securityOptions())
		if err != nil {
			t.Fatalf("saferwall NewBytes: %v", err)
		}
		if err := sw.Parse(); err != nil {
			t.Fatalf("saferwall Parse: %v", err)
		}
		if sw.HasCertificate {
			t.Fatalf("saferwall HasCertificate = true, want false")
		}
	})

	t.Run("MultiRecordAndUnsupportedTypes", func(t *testing.T) {
		specs := []testfixture.CertificateSpec{
			{
				Revision: gope.CertificateRevision2_0,
				Type:     gope.CertificateTypePKCS7SignedData,
				Payload:  []byte("not-der-pkcs7"),
			},
			{
				Revision: gope.CertificateRevision1_0,
				Type:     gope.CertificateTypeX509,
				Payload:  []byte("x509-bytes"),
			},
			{
				Revision: 0x0300,
				Type:     0x9999,
				Payload:  []byte("custom-type"),
			},
		}
		data := testfixture.Certificates(true, specs...)

		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		recs, err := gp.Certificates(data)
		if err != nil {
			t.Fatalf("go-pe Certificates: %v", err)
		}
		if len(recs) != len(specs) {
			t.Fatalf("go-pe records = %d, want %d", len(recs), len(specs))
		}
		for i, rec := range recs {
			payload, err := gp.CertificatePayload(data, rec)
			if err != nil {
				t.Fatalf("go-pe CertificatePayload(%d): %v", i, err)
			}
			if !bytes.Equal(payload, specs[i].Payload) {
				t.Fatalf("payload[%d] = %q, want %q", i, payload, specs[i].Payload)
			}
		}

		// Document behavioral difference: saferwall/pe reads only the first
		// WIN_CERTIFICATE entry, swallows the pkcs7.Parse error in Parse(),
		// and never exposes subsequent WIN_CERTIFICATE records.
		sw, err := saferwall.NewBytes(data, securityOptions())
		if err != nil {
			t.Fatalf("saferwall NewBytes: %v", err)
		}
		if err := sw.Parse(); err != nil {
			t.Fatalf("saferwall Parse: %v", err)
		}
		if !sw.HasCertificate || sw.IsSigned || len(sw.Certificates.Certificates) != 0 ||
			sw.Certificates.Header.Length != recs[0].Length {
			t.Fatalf("saferwall state HasCert=%v IsSigned=%v Certs=%d Header.Length=%d, want true/false/0/%d",
				sw.HasCertificate, sw.IsSigned, len(sw.Certificates.Certificates),
				sw.Certificates.Header.Length, recs[0].Length)
		}
	})

	t.Run("TruncatedPadding", func(t *testing.T) {
		data := testfixture.Certificates(true, testfixture.CertificateSpec{
			Revision: gope.CertificateRevision2_0,
			Type:     gope.CertificateTypePKCS7SignedData,
			Payload:  []byte{1, 2, 3}, // dwLength = 11; requires 16-byte padded directory.
		})
		dirOff := testfixture.CertificateDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 15) // 1 byte short of 8-byte padding.

		gp, err := gope.New(data)
		if err != nil {
			t.Fatalf("go-pe New: %v", err)
		}
		if _, err := gp.Certificates(data); !errors.Is(err, gope.ErrInvalidCertificate) {
			t.Fatalf("go-pe Certificates err = %v, want ErrInvalidCertificate", err)
		}
	})
}

func BenchmarkParseCertificates(b *testing.B) {
	opts := securityOptions()
	noCert := testfixture.Minimal(true, 1)
	single4KiB := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: gope.CertificateRevision2_0,
		Type:     gope.CertificateTypePKCS7SignedData,
		Payload:  bytes.Repeat([]byte{0x30}, 4096),
	})
	fourRecords := testfixture.Certificates(true,
		testfixture.CertificateSpec{Revision: gope.CertificateRevision2_0, Type: gope.CertificateTypePKCS7SignedData, Payload: bytes.Repeat([]byte{0x30}, 2048)},
		testfixture.CertificateSpec{Revision: gope.CertificateRevision2_0, Type: gope.CertificateTypeX509, Payload: bytes.Repeat([]byte{0x30}, 1024)},
		testfixture.CertificateSpec{Revision: gope.CertificateRevision2_0, Type: gope.CertificateTypeTSStackSigned, Payload: bytes.Repeat([]byte{0x01}, 512)},
		testfixture.CertificateSpec{Revision: 0x0300, Type: 0x9999, Payload: bytes.Repeat([]byte{0x02}, 256)},
	)

	cases := []struct {
		name      string
		data      []byte
		wantCount int
	}{
		{name: "NoDirectory", data: noCert, wantCount: 0},
		{name: "Records1_4KiB", data: single4KiB, wantCount: 1},
		{name: "Records4", data: fourRecords, wantCount: 4},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("go-pe-Enumerate", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := gope.New(tc.data)
					if err != nil {
						b.Fatal(err)
					}
					recs, err := f.Certificates(tc.data)
					if err != nil {
						b.Fatal(err)
					}
					if len(recs) != tc.wantCount {
						b.Fatalf("count = %d, want %d", len(recs), tc.wantCount)
					}
					benchSinkAny = recs
				}
			})
			b.Run("go-pe-EnumerateAndCopy", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, err := gope.New(tc.data)
					if err != nil {
						b.Fatal(err)
					}
					recs, err := f.Certificates(tc.data)
					if err != nil {
						b.Fatal(err)
					}
					for _, rec := range recs {
						p, err := f.CertificatePayload(tc.data, rec)
						if err != nil {
							b.Fatal(err)
						}
						benchSinkAny = p
					}
				}
			})
			b.Run("saferwall-SecurityOnly", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					f, _ := saferwall.NewBytes(tc.data, opts)
					benchSinkAny = f.Parse()
				}
			})
		})
	}
}
