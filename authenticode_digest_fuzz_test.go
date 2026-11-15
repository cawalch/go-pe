package pe_test

import (
	"crypto"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzAuthenticodeDigest(f *testing.F) {
	f.Add(testfixture.Minimal(false, 1))
	f.Add(testfixture.Minimal(true, 2))
	blob, _ := testfixture.AuthenticodeBlob(testfixture.AuthenticodeOptions{
		IncludeCertificate: true,
	})
	f.Add(testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  blob,
	}))
	badOverflow := testfixture.Minimal(true, 1)
	binary.LittleEndian.PutUint32(badOverflow[152+240+20:], 0xfffff000)
	binary.LittleEndian.PutUint32(badOverflow[152+240+16:], 0x2000)
	f.Add(badOverflow)

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := pe.New(data)
		if err != nil {
			return
		}
		ranges, err := parsed.AuthenticodeDigestRanges(data)
		if err != nil {
			if ranges != nil {
				t.Fatalf("non-nil ranges on error %v", err)
			}
			return
		}
		var total int64
		for i, r := range ranges {
			if r.Offset < 0 || r.Length <= 0 || r.Offset+r.Length > int64(len(data)) {
				t.Fatalf("invalid range[%d]: %+v (len=%d)", i, r, len(data))
			}
			if i > 0 && r.Offset <= ranges[i-1].Offset+ranges[i-1].Length {
				t.Fatalf("unsorted or overlapping ranges: %+v vs %+v", ranges[i-1], r)
			}
			total += r.Length
		}
		if total > int64(len(data)) {
			t.Fatalf("included bytes %d exceed file length %d", total, len(data))
		}
		digest, err := parsed.AuthenticodeDigest(data, crypto.SHA256)
		if err != nil {
			t.Fatalf("AuthenticodeDigest() error after Ranges() succeeded: %v", err)
		}
		if len(digest) != crypto.SHA256.Size() {
			t.Fatalf("digest len = %d, want %d", len(digest), crypto.SHA256.Size())
		}
	})
}
