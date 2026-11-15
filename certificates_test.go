package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestCertificatesAndPayloadPE32AndPE32Plus(t *testing.T) {
	for _, tc := range []struct {
		name string
		is64 bool
	}{
		{name: "PE32", is64: false},
		{name: "PE32Plus", is64: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			specs := []testfixture.CertificateSpec{
				{
					Revision: pe.CertificateRevision2_0,
					Type:     pe.CertificateTypePKCS7SignedData,
					Payload:  []byte{0x30, 0x82, 0x01, 0x02, 0x03},
				},
				{
					Revision: pe.CertificateRevision1_0,
					Type:     pe.CertificateTypeX509,
					Payload:  []byte{0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd},
				},
				{
					Revision: pe.CertificateRevision2_0,
					Type:     pe.CertificateTypeTSStackSigned,
					Payload:  nil, // Empty payload (dwLength == 8).
				},
				{
					Revision: 0x0300, // Unknown revision.
					Type:     0x9999, // Unknown type preserved without error.
					Payload:  []byte("custom-cert-payload"),
				},
			}

			data := testfixture.Certificates(tc.is64, specs...)
			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			records, err := f.Certificates(data)
			if err != nil {
				t.Fatalf("Certificates() error = %v", err)
			}
			if len(records) != len(specs) {
				t.Fatalf("len(records) = %d, want %d", len(records), len(specs))
			}

			dir := f.OptionalHeader.DataDirectories[pe.DataDirectoryCertificate]
			wantOffset := dir.VirtualAddress
			for i, rec := range records {
				spec := specs[i]
				wantLen := uint32(8 + len(spec.Payload))
				if rec.Offset != wantOffset {
					t.Errorf("record[%d].Offset = %#x, want %#x", i, rec.Offset, wantOffset)
				}
				if rec.Length != wantLen {
					t.Errorf("record[%d].Length = %d, want %d", i, rec.Length, wantLen)
				}
				if rec.Revision != spec.Revision {
					t.Errorf("record[%d].Revision = %#x, want %#x", i, rec.Revision, spec.Revision)
				}
				if rec.Type != spec.Type {
					t.Errorf("record[%d].Type = %#x, want %#x", i, rec.Type, spec.Type)
				}

				gotPayload, err := f.CertificatePayload(data, rec)
				if err != nil {
					t.Fatalf("CertificatePayload(%d) error = %v", i, err)
				}
				if !bytes.Equal(gotPayload, spec.Payload) {
					t.Errorf("CertificatePayload(%d) = %x, want %x", i, gotPayload, spec.Payload)
				}

				wantOffset += (wantLen + 7) &^ 7
			}

			// CertificatePayload must return an owned copy independent of data.
			firstPayload, err := f.CertificatePayload(data, records[0])
			if err != nil {
				t.Fatalf("CertificatePayload(0) error = %v", err)
			}
			wantFirst := bytes.Clone(specs[0].Payload)
			clear(data)
			if !bytes.Equal(firstPayload, wantFirst) {
				t.Fatalf("payload mutated after clearing input buffer: got %x, want %x", firstPayload, wantFirst)
			}
		})
	}
}

func TestCertificatesAbsentDirectoryAndZeroAlloc(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Minimal(is64, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		records, err := f.Certificates(data)
		if err != nil || records != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, nil)", records, err)
		}

		allocs := testing.AllocsPerRun(100, func() {
			recs, err := f.Certificates(data)
			if err != nil || recs != nil {
				t.Fatalf("Certificates() = (%v, %v), want (nil, nil)", recs, err)
			}
		})
		if allocs != 0 {
			t.Fatalf("absent security directory allocs = %v, want 0", allocs)
		}
	}

	// Fewer than 5 data directories declared.
	data := testfixture.Minimal(true, 1)
	binary.LittleEndian.PutUint32(data[260:], pe.DataDirectoryCertificate) // NumberOfRvaAndSizes = 4
	f, err := pe.New(data)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	records, err := f.Certificates(data)
	if err != nil || records != nil {
		t.Fatalf("Certificates() with truncated dir count = (%v, %v), want (nil, nil)", records, err)
	}
}

func TestCertificatesInvalidFileAndConcurrentCalls(t *testing.T) {
	var nilFile *pe.File
	if recs, err := nilFile.Certificates(nil); !errors.Is(err, pe.ErrInvalidHeader) || recs != nil {
		t.Fatalf("nilFile.Certificates() = (%v, %v), want (nil, ErrInvalidHeader)", recs, err)
	}
	var zeroFile pe.File
	if recs, err := zeroFile.Certificates(nil); !errors.Is(err, pe.ErrInvalidHeader) || recs != nil {
		t.Fatalf("zeroFile.Certificates() = (%v, %v), want (nil, ErrInvalidHeader)", recs, err)
	}
	if payload, err := zeroFile.CertificatePayload(nil, pe.CertificateRecord{}); !errors.Is(err, pe.ErrInvalidHeader) || payload != nil {
		t.Fatalf("zeroFile.CertificatePayload() = (%v, %v), want (nil, ErrInvalidHeader)", payload, err)
	}

	// Zero-value and section-limit File guards.
	data := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  []byte("concurrent-payload"),
	})
	f, err := pe.New(data)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			recs, err := f.Certificates(data)
			if err != nil || len(recs) != 1 {
				t.Errorf("concurrent Certificates() = (%v, %v), want 1 record", recs, err)
				return
			}
			payload, err := f.CertificatePayload(data, recs[0])
			if err != nil || !bytes.Equal(payload, []byte("concurrent-payload")) {
				t.Errorf("concurrent CertificatePayload() = (%q, %v), want %q", payload, err, "concurrent-payload")
			}
		})
	}
	wg.Wait()
}
