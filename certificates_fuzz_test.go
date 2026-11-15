package pe_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzCertificates(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("MZ"))
	f.Add(testfixture.Minimal(false, 1))
	f.Add(testfixture.Minimal(true, 1))
	f.Add(testfixture.Certificates(false, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  []byte{0x30, 0x03, 0x01, 0x02, 0x03},
	}))
	f.Add(testfixture.Certificates(true,
		testfixture.CertificateSpec{
			Revision: pe.CertificateRevision2_0,
			Type:     pe.CertificateTypePKCS7SignedData,
			Payload:  []byte("sig"),
		},
		testfixture.CertificateSpec{
			Revision: pe.CertificateRevision1_0,
			Type:     pe.CertificateTypeX509,
			Payload:  []byte("x509"),
		},
	))

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := pe.New(data)
		if err == nil {
			assertCertificateInvariants(t, parsed, data)
		}

		// Also wrap arbitrary bytes inside the security directory of valid PE32/PE32+ shells.
		for _, is64 := range []bool{false, true} {
			img := append([]byte(nil), testfixture.Minimal(is64, 1)...)
			tableOff := uint32(len(img))
			img = append(img, data...)
			dirOff := testfixture.CertificateDirOffset(is64)
			img[dirOff] = byte(tableOff)
			img[dirOff+1] = byte(tableOff >> 8)
			img[dirOff+2] = byte(tableOff >> 16)
			img[dirOff+3] = byte(tableOff >> 24)
			sz := uint32(len(data))
			img[dirOff+4] = byte(sz)
			img[dirOff+5] = byte(sz >> 8)
			img[dirOff+6] = byte(sz >> 16)
			img[dirOff+7] = byte(sz >> 24)

			shell, err := pe.New(img)
			if err != nil {
				t.Fatalf("New(shell) failed: %v", err)
			}
			assertCertificateInvariants(t, shell, img)
		}
	})
}

func assertCertificateInvariants(t *testing.T, parsed *pe.File, data []byte) {
	t.Helper()
	recs, err := parsed.Certificates(data)
	if err != nil {
		if recs != nil {
			t.Fatalf("Certificates returned non-nil slice on error %v", err)
		}
		return
	}
	if len(recs) > pe.MaxCertificateRecords {
		t.Fatalf("record count %d exceeds MaxCertificateRecords %d", len(recs), pe.MaxCertificateRecords)
	}
	var dirStart, dirEnd uint64
	if parsed.OptionalHeader.NumberOfRvaAndSizes > pe.DataDirectoryCertificate {
		dir := parsed.OptionalHeader.DataDirectories[pe.DataDirectoryCertificate]
		dirStart = uint64(dir.VirtualAddress)
		dirEnd = dirStart + uint64(dir.Size)
	}
	for i, rec := range recs {
		if rec.Offset%8 != 0 {
			t.Fatalf("record %d offset %#x not 8-byte aligned", i, rec.Offset)
		}
		if rec.Length < 8 {
			t.Fatalf("record %d length %d < 8", i, rec.Length)
		}
		end := uint64(rec.Offset) + uint64(rec.Length)
		if uint64(rec.Offset) < dirStart || ((end+7)&^7) > dirEnd {
			t.Fatalf("record %d [%#x, %#x) exceeds dir [%#x, %#x)", i, rec.Offset, end, dirStart, dirEnd)
		}
		payload, err := parsed.CertificatePayload(data, rec)
		if err != nil {
			t.Fatalf("CertificatePayload(%d) error = %v", i, err)
		}
		if len(payload) != int(rec.Length-8) {
			t.Fatalf("payload len = %d, want %d", len(payload), rec.Length-8)
		}
	}
}
