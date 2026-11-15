package pe_test

import (
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzAuthenticode(f *testing.F) {
	blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		CommonName:         "Fuzz Signer",
		SigningTime:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ProgramName:        "FuzzBin",
		IncludeCertificate: true,
		RFC3161TimestampAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
	})
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add([]byte{0x1f, 0x81})
	f.Add(blob)

	f.Fuzz(func(t *testing.T, data []byte) {
		sigs, err := pe.ParseAuthenticodeSignatures(data)
		if err != nil {
			if sigs != nil {
				t.Fatalf("non-nil signatures on error %v", err)
			}
			return
		}
		if len(sigs) > pe.MaxAuthenticodeSignatures {
			t.Fatalf("signature count %d exceeds limit %d", len(sigs), pe.MaxAuthenticodeSignatures)
		}
		for _, sig := range sigs {
			for _, cert := range sig.Certificates {
				if len(cert.Raw) == 0 {
					t.Fatal("parsed certificate with empty Raw bytes")
				}
			}
		}
	})
}
