package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkCertificates(b *testing.B) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{
			name: "PE32/Records1",
			data: testfixture.Certificates(false, testfixture.CertificateSpec{
				Revision: pe.CertificateRevision2_0,
				Type:     pe.CertificateTypePKCS7SignedData,
				Payload:  bytes.Repeat([]byte{0x30}, 4096),
			}),
		},
		{
			name: "PE32Plus/Records1",
			data: testfixture.Certificates(true, testfixture.CertificateSpec{
				Revision: pe.CertificateRevision2_0,
				Type:     pe.CertificateTypePKCS7SignedData,
				Payload:  bytes.Repeat([]byte{0x30}, 4096),
			}),
		},
		{
			name: "PE32Plus/Records4",
			data: testfixture.Certificates(true,
				testfixture.CertificateSpec{Revision: pe.CertificateRevision2_0, Type: pe.CertificateTypePKCS7SignedData, Payload: bytes.Repeat([]byte{0x30}, 2048)},
				testfixture.CertificateSpec{Revision: pe.CertificateRevision2_0, Type: pe.CertificateTypeX509, Payload: bytes.Repeat([]byte{0x30}, 1024)},
				testfixture.CertificateSpec{Revision: pe.CertificateRevision2_0, Type: pe.CertificateTypeTSStackSigned, Payload: bytes.Repeat([]byte{0x01}, 512)},
				testfixture.CertificateSpec{Revision: 0x0300, Type: 0x9999, Payload: bytes.Repeat([]byte{0x02}, 256)},
			),
		},
		{
			name: "NoDirectory",
			data: testfixture.Minimal(true, 1),
		},
		{
			name: "OverLimit",
			data: func() []byte {
				d := testfixture.Minimal(true, 1)
				dirOff := testfixture.CertificateDirOffset(true)
				binary.LittleEndian.PutUint32(d[dirOff:], 0x400)
				binary.LittleEndian.PutUint32(d[dirOff+4:], pe.MaxCertificateBytes+8)
				return d
			}(),
			want: pe.ErrCertificateLimit,
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			f, err := pe.New(tc.data)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				recs, err := f.Certificates(tc.data)
				if tc.want != nil {
					if !errors.Is(err, tc.want) {
						b.Fatalf("got err=%v want %v", err, tc.want)
					}
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
				_ = recs
			}
		})
	}
}

func BenchmarkCertificatePayload(b *testing.B) {
	data := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  bytes.Repeat([]byte{0x30}, 4096),
	})
	f, err := pe.New(data)
	if err != nil {
		b.Fatal(err)
	}
	recs, err := f.Certificates(data)
	if err != nil || len(recs) != 1 {
		b.Fatalf("Certificates() = (%v, %v)", recs, err)
	}
	rec := recs[0]
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		payload, err := f.CertificatePayload(data, rec)
		if err != nil {
			b.Fatal(err)
		}
		if len(payload) != 4096 {
			b.Fatalf("len = %d, want 4096", len(payload))
		}
	}
}
