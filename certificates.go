package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Attribute certificate revisions and types defined by the PE/COFF WIN_CERTIFICATE
// format.
const (
	// CertificateRevision1_0 identifies the legacy WIN_CERT_REVISION_1_0 format.
	CertificateRevision1_0 uint16 = 0x0100
	// CertificateRevision2_0 identifies the WIN_CERT_REVISION_2_0 format.
	CertificateRevision2_0 uint16 = 0x0200

	// CertificateTypeX509 identifies an X.509 certificate (WIN_CERT_TYPE_X509).
	CertificateTypeX509 uint16 = 0x0001
	// CertificateTypePKCS7SignedData identifies a PKCS#7 SignedData structure
	// (WIN_CERT_TYPE_PKCS_SIGNED_DATA).
	CertificateTypePKCS7SignedData uint16 = 0x0002
	// CertificateTypeReserved1 is the reserved WIN_CERT_TYPE_RESERVED_1 value.
	CertificateTypeReserved1 uint16 = 0x0003
	// CertificateTypeTSStackSigned identifies a Terminal Server protocol stack
	// certificate (WIN_CERT_TYPE_TS_STACK_SIGNED).
	CertificateTypeTSStackSigned uint16 = 0x0004
)

// Parser limits bound attribute certificate enumeration and payload reads.
// They are resource limits, not Windows loader requirements.
const (
	// MaxCertificateRecords limits the number of WIN_CERTIFICATE entries.
	MaxCertificateRecords = 1024
	// MaxCertificateBytes limits the total byte size of the security directory
	// and individual extracted payloads.
	MaxCertificateBytes = 4 << 20
)

var (
	// ErrInvalidCertificate indicates inconsistent or malformed security
	// directory or WIN_CERTIFICATE metadata.
	ErrInvalidCertificate = errors.New("invalid certificate metadata")
	// ErrCertificateLimit indicates that certificate parsing exceeded a
	// resource limit.
	ErrCertificateLimit = errors.New("certificate parser limit exceeded")
)

const certificateHeaderSize = 8

// CertificateRecord describes one WIN_CERTIFICATE entry in the security
// directory. Offset is the file offset of the 8-byte header, Length is dwLength
// including that header, and Revision and Type preserve the unmodified header
// fields.
//
// Enumerating records validates record framing and directory bounds, and doesn't
// verify Authenticode signatures or decode embedded payloads.
type CertificateRecord struct {
	Offset         uint32
	Length         uint32
	Revision       uint16
	Type           uint16
	PaddingNonZero bool
}

// Certificates enumerates the WIN_CERTIFICATE records in the security data
// directory without decoding payloads or verifying signatures.
//
// If the optional header doesn't include [DataDirectoryCertificate] or its
// offset and size are both zero, Certificates returns nil, nil. On error, it
// returns a nil slice rather than partial records.
//
// Certificates validates 8-byte table and record alignment, alignment padding,
// file bounds, overlap with PE headers or sections, and [MaxCertificateRecords]
// and [MaxCertificateBytes]. It preserves records with unrecognized revision or
// type values. Callers should pass the same PE image slice that was passed to
// [New]; passing a different slice returns an error if bounds or metadata no
// longer match.
func (f *File) Certificates(data []byte) ([]CertificateRecord, error) {
	dirStart, dirEnd, ok, err := certificateDirectoryBounds(f, data)
	if err != nil || !ok {
		return nil, err
	}
	return parseCertificateRecords(data[dirStart:dirEnd], dirStart)
}

func parseCertificateRecords(dirBytes []byte, dirStart uint64) ([]CertificateRecord, error) {
	dirEnd := dirStart + uint64(len(dirBytes))
	var records []CertificateRecord
	cursor := dirStart
	for cursor < dirEnd {
		if len(records) == MaxCertificateRecords {
			return nil, fmt.Errorf("%w: certificate count exceeds %d", ErrCertificateLimit, MaxCertificateRecords)
		}
		if dirEnd-cursor < certificateHeaderSize {
			return nil, fmt.Errorf("%w: truncated certificate header at offset %#x", ErrInvalidCertificate, cursor)
		}

		rel := cursor - dirStart
		hdr := dirBytes[rel : rel+certificateHeaderSize]
		length := binary.LittleEndian.Uint32(hdr[0:4])
		revision := binary.LittleEndian.Uint16(hdr[4:6])
		certType := binary.LittleEndian.Uint16(hdr[6:8])

		if length < certificateHeaderSize {
			return nil, fmt.Errorf("%w: certificate length %d at offset %#x is smaller than %d-byte header", ErrInvalidCertificate, length, cursor, certificateHeaderSize)
		}

		recEnd := cursor + uint64(length)
		if recEnd > dirEnd {
			return nil, fmt.Errorf("%w: certificate record at offset %#x extends past security directory", ErrInvalidCertificate, cursor)
		}

		next := align8(recEnd)
		if next > dirEnd {
			return nil, fmt.Errorf("%w: certificate alignment padding at offset %#x extends past security directory", ErrInvalidCertificate, cursor)
		}
		paddingNonZero := false
		for _, b := range dirBytes[recEnd-dirStart : next-dirStart] {
			if b != 0 {
				paddingNonZero = true
				break
			}
		}

		records = append(records, CertificateRecord{
			Offset:         uint32(cursor),
			Length:         length,
			Revision:       revision,
			Type:           certType,
			PaddingNonZero: paddingNonZero,
		})
		cursor = next
	}

	return records, nil
}

// CertificatePayload returns a newly allocated copy of the bCertificate payload
// bytes for record, excluding its 8-byte WIN_CERTIFICATE header.
//
// Callers may modify or clear data after CertificatePayload returns without
// affecting the returned slice.
func (f *File) CertificatePayload(data []byte, record CertificateRecord) ([]byte, error) {
	dirStart, dirEnd, ok, err := certificateDirectoryBounds(f, data)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: security directory not present", ErrInvalidCertificate)
	}

	recStart := uint64(record.Offset)
	if recStart%8 != 0 {
		return nil, fmt.Errorf("%w: unaligned certificate record at offset %#x", ErrInvalidCertificate, record.Offset)
	}
	if record.Length < certificateHeaderSize {
		return nil, fmt.Errorf("%w: certificate length %d is smaller than %d-byte header", ErrInvalidCertificate, record.Length, certificateHeaderSize)
	}
	if uint64(record.Length) > MaxCertificateBytes {
		return nil, fmt.Errorf("%w: certificate record length %d exceeds %d", ErrCertificateLimit, record.Length, MaxCertificateBytes)
	}

	recEnd := recStart + uint64(record.Length)
	if recStart < dirStart || recEnd > dirEnd {
		return nil, fmt.Errorf("%w: certificate record [%#x, %#x) outside security directory [%#x, %#x)", ErrInvalidCertificate, recStart, recEnd, dirStart, dirEnd)
	}
	if align8(recEnd) > dirEnd {
		return nil, fmt.Errorf("%w: certificate alignment padding at offset %#x extends past security directory", ErrInvalidCertificate, record.Offset)
	}

	hdr := data[recStart : recStart+certificateHeaderSize]
	if binary.LittleEndian.Uint32(hdr[0:4]) != record.Length ||
		binary.LittleEndian.Uint16(hdr[4:6]) != record.Revision ||
		binary.LittleEndian.Uint16(hdr[6:8]) != record.Type {
		return nil, fmt.Errorf("%w: certificate header at offset %#x does not match record", ErrInvalidCertificate, record.Offset)
	}

	payload := data[recStart+certificateHeaderSize : recEnd]
	out := make([]byte, len(payload))
	copy(out, payload)
	return out, nil
}

func certificateDirectoryBounds(f *File, data []byte) (dirStart, dirEnd uint64, ok bool, err error) {
	return certificateDirectoryBoundsFromSize(f, int64(len(data)))
}

func certificateDirectoryBoundsFromSize(f *File, dataLen int64) (dirStart, dirEnd uint64, ok bool, err error) {
	dir, hasDir, err := f.dataDirectory(DataDirectoryCertificate, ErrInvalidCertificate)
	if err != nil || !hasDir {
		return 0, 0, false, err
	}

	dirStart = uint64(dir.VirtualAddress)
	dirSize := uint64(dir.Size)
	if dirStart%8 != 0 {
		return 0, 0, false, fmt.Errorf("%w: unaligned security directory at offset %#x", ErrInvalidCertificate, dir.VirtualAddress)
	}
	if dirSize > MaxCertificateBytes {
		return 0, 0, false, fmt.Errorf("%w: security directory size %d exceeds %d", ErrCertificateLimit, dirSize, MaxCertificateBytes)
	}

	dirEnd = dirStart + dirSize
	limit := min(f.fileSize, dataLen)
	if limit < 0 || dirEnd > uint64(limit) {
		return 0, 0, false, fmt.Errorf("%w: security directory [%#x, %#x) exceeds file size %d", ErrOutOfBounds, dirStart, dirEnd, limit)
	}

	headerEnd := certificateHeaderEnd(f)
	if dirStart < headerEnd {
		return 0, 0, false, fmt.Errorf("%w: security directory offset %#x overlaps PE headers ending at %#x", ErrInvalidCertificate, dirStart, headerEnd)
	}
	for _, sec := range f.Sections {
		if sec.SizeOfRawData == 0 {
			continue
		}
		secStart := uint64(sec.PointerToRawData)
		secEnd := secStart + uint64(sec.SizeOfRawData)
		if dirStart < secEnd && secStart < dirEnd {
			return 0, 0, false, fmt.Errorf("%w: security directory [%#x, %#x) overlaps section %q [%#x, %#x)", ErrInvalidCertificate, dirStart, dirEnd, sec.Name, secStart, secEnd)
		}
	}

	return dirStart, dirEnd, true, nil
}

func certificateHeaderEnd(f *File) uint64 {
	// Include the full DOS header, COFF header, optional header, and section table.
	tableEnd := uint64(f.DOSHeader.AddressOfNewEXEHeader) + 24 + uint64(f.FileHeader.SizeOfOptionalHeader) + uint64(len(f.Sections))*40
	return max(tableEnd, 64, uint64(f.OptionalHeader.SizeOfHeaders))
}

func align8(n uint64) uint64 {
	return (n + 7) &^ 7
}
