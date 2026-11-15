package pe_test

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestCertificatesTruncationSweep(t *testing.T) {
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
					Type:     pe.CertificateTypePKCS7SignedData,
					Payload:  []byte{1, 2, 3, 4, 5},
				},
				testfixture.CertificateSpec{
					Revision: pe.CertificateRevision2_0,
					Type:     pe.CertificateTypeX509,
					Payload:  []byte{6, 7, 8},
				},
			)
			full, err := pe.New(data)
			if err != nil {
				t.Fatalf("New(full) error = %v", err)
			}

			// New(short) must fail Certificates(full) because f recorded the shorter fileSize.
			dirOff := int(full.OptionalHeader.DataDirectories[pe.DataDirectoryCertificate].VirtualAddress)
			short, err := pe.New(data[:dirOff+8])
			if err != nil {
				t.Fatalf("New(short) error = %v", err)
			}
			if recs, err := short.Certificates(data); !errors.Is(err, pe.ErrOutOfBounds) || recs != nil {
				t.Fatalf("short.Certificates(full) = (%v, %v), want (nil, ErrOutOfBounds)", recs, err)
			}

			// Every truncated prefix shorter than the full security directory must fail.
			for n := range len(data) {
				prefix := data[:n]
				parsed, err := pe.New(prefix)
				if err != nil {
					continue
				}
				if recs, err := parsed.Certificates(prefix); !errors.Is(err, pe.ErrOutOfBounds) || recs != nil {
					t.Fatalf("truncate %d/%d: parsed.Certificates() = (%v, %v), want (nil, ErrOutOfBounds)", n, len(data), recs, err)
				}
				if recs, err := full.Certificates(prefix); !errors.Is(err, pe.ErrOutOfBounds) || recs != nil {
					t.Fatalf("truncate %d/%d: full.Certificates() = (%v, %v), want (nil, ErrOutOfBounds)", n, len(data), recs, err)
				}
			}
		})
	}
}

func TestCertificatesValidationErrors(t *testing.T) {
	singleSpec := testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  []byte{1, 2, 3},
	}

	t.Run("IncompleteDirectory", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			offset uint32
			size   uint32
		}{
			{name: "ZeroOffsetNonZeroSize", offset: 0, size: 16},
			{name: "NonZeroOffsetZeroSize", offset: 0x400, size: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				data := testfixture.Minimal(true, 1)
				dirOff := testfixture.CertificateDirOffset(true)
				binary.LittleEndian.PutUint32(data[dirOff:], tc.offset)
				binary.LittleEndian.PutUint32(data[dirOff+4:], tc.size)
				f, err := pe.New(data)
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrInvalidCertificate) || recs != nil {
					t.Fatalf("Certificates() = (%v, %v), want (nil, ErrInvalidCertificate)", recs, err)
				}
			})
		}
	})

	t.Run("DirectoryOffsetOverflow", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		dirOff := testfixture.CertificateDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff:], math.MaxUint32-7)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 16)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrIntegerOverflow) || recs != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, ErrIntegerOverflow)", recs, err)
		}
	})

	t.Run("UnalignedDirectoryOffset", func(t *testing.T) {
		data := testfixture.Certificates(true, singleSpec)
		data = append(data, make([]byte, 4)...)
		dirOff := testfixture.CertificateDirOffset(true)
		origOff := binary.LittleEndian.Uint32(data[dirOff:])
		copy(data[origOff+4:], data[origOff:])
		binary.LittleEndian.PutUint32(data[dirOff:], origOff+4)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrInvalidCertificate) || recs != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, ErrInvalidCertificate)", recs, err)
		}
	})

	t.Run("HeaderOverlap", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		// Place valid-looking 8-byte record inside the header padding at offset 0x1e0 (aligned to 8).
		tableOff := uint32(0x1e0)
		binary.LittleEndian.PutUint32(data[tableOff:], 16)
		binary.LittleEndian.PutUint16(data[tableOff+4:], pe.CertificateRevision2_0)
		binary.LittleEndian.PutUint16(data[tableOff+6:], pe.CertificateTypePKCS7SignedData)
		dirOff := testfixture.CertificateDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff:], tableOff)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 16)

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrInvalidCertificate) || recs != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, ErrInvalidCertificate)", recs, err)
		}
	})

	t.Run("SectionOverlap", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		// First section starts at 0x200 with size 0x200. Put a valid record at 0x200.
		tableOff := uint32(0x200)
		binary.LittleEndian.PutUint32(data[tableOff:], 16)
		binary.LittleEndian.PutUint16(data[tableOff+4:], pe.CertificateRevision2_0)
		binary.LittleEndian.PutUint16(data[tableOff+6:], pe.CertificateTypePKCS7SignedData)
		dirOff := testfixture.CertificateDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff:], tableOff)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 16)

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrInvalidCertificate) || recs != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, ErrInvalidCertificate)", recs, err)
		}
	})

	t.Run("RecordLengthsAndPadding", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			dwLength uint32
			dirSize  uint32
			trailing int
		}{
			{name: "ZeroLength", dwLength: 0, dirSize: 16},
			{name: "ShortLength4", dwLength: 4, dirSize: 16},
			{name: "ShortLength7", dwLength: 7, dirSize: 16},
			{name: "RecordPastDirectory", dwLength: 24, dirSize: 16},
			{name: "TruncatedPaddingExact", dwLength: 11, dirSize: 11},
			{name: "TruncatedPaddingPartial", dwLength: 11, dirSize: 15},
			{name: "TruncatedTrailingHeader", dwLength: 8, dirSize: 12},
		} {
			t.Run(tc.name, func(t *testing.T) {
				data := testfixture.Certificates(true, singleSpec)
				data = append(data, make([]byte, 32)...)
				dirOff := testfixture.CertificateDirOffset(true)
				tableOff := binary.LittleEndian.Uint32(data[dirOff:])
				binary.LittleEndian.PutUint32(data[tableOff:], tc.dwLength)
				binary.LittleEndian.PutUint32(data[dirOff+4:], tc.dirSize)

				f, err := pe.New(data)
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrInvalidCertificate) || recs != nil {
					t.Fatalf("Certificates() = (%v, %v), want (nil, ErrInvalidCertificate)", recs, err)
				}
			})
		}
	})

	t.Run("PartialMultiRecordFailureReturnsNilSlice", func(t *testing.T) {
		data := testfixture.Certificates(true, singleSpec, singleSpec)
		dirOff := testfixture.CertificateDirOffset(true)
		tableOff := binary.LittleEndian.Uint32(data[dirOff:])
		secondOff := tableOff + 16
		binary.LittleEndian.PutUint32(data[secondOff:], 4) // Malformed second record.

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrInvalidCertificate) || recs != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, ErrInvalidCertificate)", recs, err)
		}
	})

	t.Run("Limits", func(t *testing.T) {
		// Directory size over MaxCertificateBytes.
		data := testfixture.Minimal(true, 1)
		dirOff := testfixture.CertificateDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff:], 0x400)
		binary.LittleEndian.PutUint32(data[dirOff+4:], pe.MaxCertificateBytes+8)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrCertificateLimit) || recs != nil {
			t.Fatalf("oversize dir Certificates() = (%v, %v), want (nil, ErrCertificateLimit)", recs, err)
		}

		// Record count over MaxCertificateRecords.
		specs := make([]testfixture.CertificateSpec, pe.MaxCertificateRecords+1)
		for i := range specs {
			specs[i] = testfixture.CertificateSpec{
				Revision: pe.CertificateRevision2_0,
				Type:     pe.CertificateTypePKCS7SignedData,
			}
		}
		many := testfixture.Certificates(true, specs...)
		fMany, err := pe.New(many)
		if err != nil {
			t.Fatalf("New(many) error = %v", err)
		}
		if recs, err := fMany.Certificates(many); !errors.Is(err, pe.ErrCertificateLimit) || recs != nil {
			t.Fatalf("too many records Certificates() = (%v, %v), want (nil, ErrCertificateLimit)", recs, err)
		}

		// Exactly MaxCertificateRecords succeeds.
		atLimit := testfixture.Certificates(true, specs[:pe.MaxCertificateRecords]...)
		fLimit, err := pe.New(atLimit)
		if err != nil {
			t.Fatalf("New(atLimit) error = %v", err)
		}
		recs, err := fLimit.Certificates(atLimit)
		if err != nil || len(recs) != pe.MaxCertificateRecords {
			t.Fatalf("at limit Certificates() = (%d recs, %v), want %d", len(recs), err, pe.MaxCertificateRecords)
		}
	})

	t.Run("SectionLimitGuard", func(t *testing.T) {
		data := testfixture.Certificates(true, singleSpec)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		f.Sections = make([]pe.Section, pe.MaxSections+1)
		if recs, err := f.Certificates(data); !errors.Is(err, pe.ErrSectionLimit) || recs != nil {
			t.Fatalf("Certificates() = (%v, %v), want (nil, ErrSectionLimit)", recs, err)
		}
	})
}

func TestCertificatePayloadErrors(t *testing.T) {
	data := testfixture.Certificates(true, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	})
	f, err := pe.New(data)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	recs, err := f.Certificates(data)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Certificates() = (%v, %v), want 1 record", recs, err)
	}
	rec := recs[0]

	for _, tc := range []struct {
		name string
		mod  func(pe.CertificateRecord) pe.CertificateRecord
		want error
	}{
		{
			name: "UnalignedOffset",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Offset += 4; return r },
			want: pe.ErrInvalidCertificate,
		},
		{
			name: "ShortLength",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Length = 7; return r },
			want: pe.ErrInvalidCertificate,
		},
		{
			name: "LengthOverLimit",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Length = pe.MaxCertificateBytes + 1; return r },
			want: pe.ErrCertificateLimit,
		},
		{
			name: "BeforeDirectory",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Offset -= 8; return r },
			want: pe.ErrInvalidCertificate,
		},
		{
			name: "PastDirectory",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Length = 100; return r },
			want: pe.ErrInvalidCertificate,
		},
		{
			name: "MismatchedRevision",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Revision ^= 1; return r },
			want: pe.ErrInvalidCertificate,
		},
		{
			name: "MismatchedType",
			mod:  func(r pe.CertificateRecord) pe.CertificateRecord { r.Type ^= 1; return r },
			want: pe.ErrInvalidCertificate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if payload, err := f.CertificatePayload(data, tc.mod(rec)); !errors.Is(err, tc.want) || payload != nil {
				t.Fatalf("CertificatePayload() = (%v, %v), want (nil, %v)", payload, err, tc.want)
			}
		})
	}

	// Valid empty image without security directory rejects payload read.
	noCert := testfixture.Minimal(true, 1)
	fNoCert, err := pe.New(noCert)
	if err != nil {
		t.Fatalf("New(noCert) error = %v", err)
	}
	if payload, err := fNoCert.CertificatePayload(noCert, rec); !errors.Is(err, pe.ErrInvalidCertificate) || payload != nil {
		t.Fatalf("CertificatePayload on absent dir = (%v, %v), want (nil, ErrInvalidCertificate)", payload, err)
	}
}
