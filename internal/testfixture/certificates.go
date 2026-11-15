package testfixture

import "encoding/binary"

// CertificateSpec describes one synthetic WIN_CERTIFICATE record.
type CertificateSpec struct {
	Revision uint16
	Type     uint16
	Payload  []byte
}

// CertificateDirOffset returns the byte offset of DataDirectory[4] (Security)
// in a Minimal image.
func CertificateDirOffset(is64 bool) int {
	// PE32 optional header starts at 152 and data directories at +96 (4 entries * 8 bytes).
	if is64 {
		// PE32+ data directories start at 152 + 112 = 264; index 4 is +32 = 296.
		return 296
	}
	return 280
}

// Certificates builds a PE32 or PE32+ image containing an 8-byte aligned
// security directory appended after the section data with one WIN_CERTIFICATE
// record per spec.
func Certificates(is64 bool, specs ...CertificateSpec) []byte {
	data := Minimal(is64, 1)
	if len(specs) == 0 {
		return data
	}

	tableOff := (len(data) + 7) &^ 7
	if pad := tableOff - len(data); pad > 0 {
		data = append(data, make([]byte, pad)...)
	}

	var table []byte
	for _, spec := range specs {
		recLen := 8 + len(spec.Payload)
		paddedLen := (recLen + 7) &^ 7
		buf := make([]byte, paddedLen)
		binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
		binary.LittleEndian.PutUint16(buf[4:6], spec.Revision)
		binary.LittleEndian.PutUint16(buf[6:8], spec.Type)
		copy(buf[8:], spec.Payload)
		table = append(table, buf...)
	}

	dirOff := CertificateDirOffset(is64)
	binary.LittleEndian.PutUint32(data[dirOff:], uint32(tableOff))
	binary.LittleEndian.PutUint32(data[dirOff+4:], uint32(len(table)))
	return append(data, table...)
}
