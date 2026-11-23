package pe

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- Rich header MD5 is standard for threat-intel clustering.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// Rich header signatures found between the 64-byte DOS header and e_lfanew.
const (
	// RichMarker is the unmasked "Rich" signature (0x68636952) ending the
	// Rich header body, followed immediately by the 4-byte XOR key.
	RichMarker uint32 = 0x68636952
	// DanSMarker is the unmasked "DanS" signature (0x536e6144) starting the
	// Rich header body.
	DanSMarker uint32 = 0x536e6144
)

// Parser limits bounding DOS-stub scans and Rich header decoding work.
// They are resource limits, not Windows loader requirements.
const (
	// MaxRichStubBytes limits the byte span [64, e_lfanew) scanned between the
	// DOS header and PE signature when locating Rich markers.
	MaxRichStubBytes = 1 << 20
	// MaxRichHeaderBytes limits the byte length [DanS, Rich) accepted for one
	// decoded Rich header body.
	MaxRichHeaderBytes = 64 << 10
	// MaxRichEntries limits the maximum number of 8-byte (@comp.id, count)
	// entries decoded from one Rich header.
	MaxRichEntries = 4096
)

const (
	dosHeaderSize      = 64
	dosLfanewOffset    = 0x3c
	richHeaderMinBytes = 16
	richEntrySize      = 8
)

var richMarkerBytes = []byte{'R', 'i', 'c', 'h'}

var (
	// ErrInvalidRichHeader indicates malformed, truncated, misaligned, or
	// inconsistent Rich header metadata.
	ErrInvalidRichHeader = errors.New("invalid rich header metadata")
	// ErrRichHeaderLimit indicates that Rich header scanning or decoding
	// exceeded a parser limit.
	ErrRichHeaderLimit = errors.New("rich header parser limit exceeded")
)

// RichEntry describes one decoded (@comp.id, count) entry in a [RichHeader].
// ToolID and Version preserve the raw 16-bit linker/compiler identifiers
// without product-name lookup or aggregate queries.
type RichEntry struct {
	ToolID  uint16
	Version uint16
	Count   uint32
}

// RichHeader describes a decoded MSVC-style Rich header located between the DOS
// header and the PE signature. RawData and ClearData retain owned copies of the
// [Offset, RichOffset) byte span before the trailing "Rich" marker and XOR key.
type RichHeader struct {
	Offset           int64
	Length           int64
	RichOffset       int64
	Key              uint32
	ComputedChecksum uint32
	ChecksumValid    bool
	PaddingNonZero   bool
	RawData          []byte
	ClearData        []byte
	Entries          []RichEntry
}

// MD5 returns the lowercase hexadecimal MD5 digest of r.ClearData (the
// standard threat-intel Rich header hash), or "" when r is nil or ClearData is
// empty.
func (r *RichHeader) MD5() string {
	if r == nil || len(r.ClearData) == 0 {
		return ""
	}
	sum := md5.Sum(r.ClearData) // #nosec G401 -- Rich header MD5 is standard for threat-intel clustering.
	return hex.EncodeToString(sum[:])
}

// SHA256 returns the lowercase hexadecimal SHA-256 digest of r.ClearData, or ""
// when r is nil or ClearData is empty.
func (r *RichHeader) SHA256() string {
	if r == nil || len(r.ClearData) == 0 {
		return ""
	}
	sum := sha256.Sum256(r.ClearData)
	return hex.EncodeToString(sum[:])
}

// RichHeader locates and decodes the Rich header from the DOS stub using f's
// validated header offsets. Pass the complete byte slice used with [New].
//
// When no "Rich" marker exists between the 64-byte DOS header and e_lfanew,
// RichHeader returns (nil, nil). When multiple markers exist, RichHeader scans
// backward from e_lfanew for the last "Rich" marker and then backward in 4-byte
// steps for the nearest matching XOR-encoded "DanS" marker. Missing matching
// markers, zero XOR keys, and short or unaligned spans return
// [ErrInvalidRichHeader]; non-zero padding words in [4, 16) after "DanS" are
// preserved with PaddingNonZero set to true, and checksum mismatches return the
// decoded header with ChecksumValid set to false.
//
// Results own their slices and retain no reference to data. Calls don't cache
// results or modify f.
func (f *File) RichHeader(data []byte) (*RichHeader, error) {
	if f == nil || len(data) < dosHeaderSize {
		return nil, fmt.Errorf("%w: missing DOS header", ErrInvalidRichHeader)
	}
	if !f.Is32Bit() && !f.Is64Bit() {
		return nil, fmt.Errorf("%w: file headers not parsed", ErrInvalidHeader)
	}
	peOffset := int64(f.DOSHeader.AddressOfNewEXEHeader)
	if peOffset < dosHeaderSize {
		return nil, fmt.Errorf("%w: PE header offset %d overlaps DOS header", ErrInvalidRichHeader, peOffset)
	}
	if int64(len(data)) < peOffset {
		return nil, fmt.Errorf("%w: truncated input (%d < e_lfanew %d)", ErrInvalidRichHeader, len(data), peOffset)
	}

	stubLen := peOffset - dosHeaderSize
	if stubLen > MaxRichStubBytes {
		return nil, fmt.Errorf("%w: DOS stub length %d exceeds max %d", ErrRichHeaderLimit, stubLen, MaxRichStubBytes)
	}
	if stubLen < 4 {
		return nil, nil
	}

	stub := data[dosHeaderSize:peOffset]
	relRich := bytes.LastIndex(stub, richMarkerBytes)
	if relRich < 0 {
		return nil, nil
	}
	richOffset := dosHeaderSize + int64(relRich)
	if richOffset+8 > peOffset {
		return nil, fmt.Errorf("%w: truncated XOR key after Rich marker", ErrInvalidRichHeader)
	}

	key := binary.LittleEndian.Uint32(data[richOffset+4 : richOffset+8])
	if key == 0 {
		return nil, fmt.Errorf("%w: Rich header XOR key is zero", ErrInvalidRichHeader)
	}

	dansOffset, found := int64(0), false
	for pos := richOffset - 4; pos >= dosHeaderSize; pos -= 4 {
		if richOffset-pos > MaxRichHeaderBytes {
			return nil, fmt.Errorf("%w: Rich header search exceeds max %d bytes", ErrRichHeaderLimit, MaxRichHeaderBytes)
		}
		if binary.LittleEndian.Uint32(data[pos:pos+4])^key == DanSMarker {
			dansOffset = pos
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: missing DanS marker", ErrInvalidRichHeader)
	}

	bodyLen := richOffset - dansOffset
	if bodyLen < richHeaderMinBytes {
		return nil, fmt.Errorf("%w: Rich header length %d below minimum %d", ErrInvalidRichHeader, bodyLen, richHeaderMinBytes)
	}
	if bodyLen > MaxRichHeaderBytes {
		return nil, fmt.Errorf("%w: Rich header length %d exceeds max %d", ErrRichHeaderLimit, bodyLen, MaxRichHeaderBytes)
	}
	if (bodyLen-richHeaderMinBytes)%richEntrySize != 0 {
		return nil, fmt.Errorf("%w: Rich header length %d not aligned to %d-byte entries", ErrInvalidRichHeader, bodyLen, richEntrySize)
	}

	entryCount := int((bodyLen - richHeaderMinBytes) / richEntrySize)
	if entryCount > MaxRichEntries {
		return nil, fmt.Errorf("%w: %d Rich entries exceed max %d", ErrRichHeaderLimit, entryCount, MaxRichEntries)
	}

	span := int(bodyLen)
	raw := make([]byte, span)
	copy(raw, data[dansOffset:richOffset])
	clearBuf := make([]byte, span)
	for off := 0; off < span; off += 4 {
		val := binary.LittleEndian.Uint32(raw[off:off+4]) ^ key
		binary.LittleEndian.PutUint32(clearBuf[off:off+4], val)
	}

	paddingNonZero := false
	for off := 4; off < richHeaderMinBytes; off += 4 {
		if binary.LittleEndian.Uint32(clearBuf[off:off+4]) != 0 {
			paddingNonZero = true
			break
		}
	}

	entries := make([]RichEntry, entryCount)
	if dansOffset > math.MaxUint32 {
		return nil, fmt.Errorf("%w: DanS offset %d exceeds uint32", ErrInvalidRichHeader, dansOffset)
	}
	checksum := uint32(dansOffset)
	for i := range int(dansOffset) {
		if i >= dosLfanewOffset && i < dosLfanewOffset+4 {
			continue
		}
		checksum += bits.RotateLeft32(uint32(data[i]), i&31)
	}

	for i := range entryCount {
		off := richHeaderMinBytes + i*richEntrySize
		compID := binary.LittleEndian.Uint32(clearBuf[off : off+4])
		count := binary.LittleEndian.Uint32(clearBuf[off+4 : off+8])
		entries[i] = RichEntry{
			ToolID:  uint16(compID >> 16),
			Version: uint16(compID & 0xffff),
			Count:   count,
		}
		checksum += bits.RotateLeft32(compID, int(count&31))
	}

	return &RichHeader{
		Offset:           dansOffset,
		Length:           bodyLen,
		RichOffset:       richOffset,
		Key:              key,
		ComputedChecksum: checksum,
		ChecksumValid:    checksum == key,
		PaddingNonZero:   paddingNonZero,
		RawData:          raw,
		ClearData:        clearBuf,
		Entries:          entries,
	}, nil
}
