package pe_test

import (
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkAuthenticodeSignatures(b *testing.B) {
	noCert := testfixture.Minimal(true, 1)

	singleBlob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
		SigningTime:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ProgramName:        "BenchApp",
		MoreInfoURL:        "https://example.invalid",
	})
	singlePE := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  singleBlob,
	})

	nestedInner, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
		SigningTime:        time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	})
	nestedOuter, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
		SigningTime:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		RFC3161TimestampAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
		NestedBlobs:        [][]byte{nestedInner},
	})
	nestedPE := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  nestedOuter,
	})

	for _, tc := range []struct {
		name      string
		data      []byte
		wantCount int
	}{
		{name: "NoDirectory", data: noCert, wantCount: 0},
		{name: "SingleSigned", data: singlePE, wantCount: 1},
		{name: "NestedAndRFC3161", data: nestedPE, wantCount: 2},
	} {
		b.Run(tc.name, func(b *testing.B) {
			f, err := pe.New(tc.data)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				sigs, err := f.AuthenticodeSignatures(tc.data)
				if err != nil {
					b.Fatal(err)
				}
				if len(sigs) != tc.wantCount {
					b.Fatalf("count = %d, want %d", len(sigs), tc.wantCount)
				}
			}
		})
	}
}
