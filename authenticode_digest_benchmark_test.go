package pe_test

import (
	"crypto"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func BenchmarkAuthenticodeDigest(b *testing.B) {
	blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
	})
	signedSmall := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  blob,
	})
	signed1MiB := appendCertificateTable(
		append(testfixture.Minimal(true, 1), make([]byte, 1<<20)...),
		true, nil, pe.CertificateTypePKCS7SignedData, blob,
	)
	signed16MiB := appendCertificateTable(
		append(testfixture.Minimal(true, 1), make([]byte, 16<<20)...),
		true, nil, pe.CertificateTypePKCS7SignedData, blob,
	)

	cases := []struct {
		name string
		data []byte
	}{
		{name: "SignedSmall/SHA256", data: signedSmall},
		{name: "Signed1MiB/SHA256", data: signed1MiB},
		{name: "Signed16MiB/SHA256", data: signed16MiB},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			f, err := pe.New(tc.data)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				digest, err := f.AuthenticodeDigest(tc.data, crypto.SHA256)
				if err != nil {
					b.Fatal(err)
				}
				if len(digest) != crypto.SHA256.Size() {
					b.Fatalf("digest len = %d", len(digest))
				}
			}
		})
	}

	b.Run("Signed1MiB/SHA1AndSHA256", func(b *testing.B) {
		f, err := pe.New(signed1MiB)
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(int64(len(signed1MiB)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			digests, err := f.AuthenticodeDigests(signed1MiB, crypto.SHA1, crypto.SHA256)
			if err != nil || len(digests) != 2 {
				b.Fatalf("AuthenticodeDigests() = (%d, %v)", len(digests), err)
			}
		}
	})
}
