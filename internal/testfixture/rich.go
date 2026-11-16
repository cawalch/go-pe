package testfixture

import (
	"encoding/binary"
	"math/bits"
)

// RichEntrySpec describes one Rich header entry in test fixtures.
type RichEntrySpec struct {
	ToolID  uint16
	Version uint16
	Count   uint32
}

// RichOptions controls synthetic Rich header generation inside DOS stub bytes.
type RichOptions struct {
	DOSStubPrefix []byte
	Entries       []RichEntrySpec
	Padding       [3]uint32
	UseCustomKey  bool
	CustomKey     uint32
	Trailer       []byte
}

// EncodeRichBlock builds a raw DanS..Rich+Key byte slice for a known dansOffset
// and DOS stub bytes [0:dansOffset], returning both the block and computed
// checksum.
func EncodeRichBlock(dosAndPrefix []byte, opts RichOptions) (block []byte, checksum uint32) {
	dansOffset := len(dosAndPrefix)
	checksum = uint32(dansOffset)
	for i := range dansOffset {
		if i >= 0x3c && i < 0x40 {
			continue
		}
		checksum += bits.RotateLeft32(uint32(dosAndPrefix[i]), i&31)
	}
	for _, e := range opts.Entries {
		compID := uint32(e.ToolID)<<16 | uint32(e.Version)
		checksum += bits.RotateLeft32(compID, int(e.Count&31))
	}
	key := checksum
	if opts.UseCustomKey {
		key = opts.CustomKey
	}

	words := make([]uint32, 4+len(opts.Entries)*2)
	words[0] = 0x536e6144 ^ key
	words[1] = opts.Padding[0] ^ key
	words[2] = opts.Padding[1] ^ key
	words[3] = opts.Padding[2] ^ key
	for i, e := range opts.Entries {
		compID := uint32(e.ToolID)<<16 | uint32(e.Version)
		words[4+i*2] = compID ^ key
		words[4+i*2+1] = e.Count ^ key
	}

	block = make([]byte, 0, len(words)*4+8+len(opts.Trailer))
	for _, w := range words {
		block = binary.LittleEndian.AppendUint32(block, w)
	}
	block = append(block, 'R', 'i', 'c', 'h')
	block = binary.LittleEndian.AppendUint32(block, key)
	block = append(block, opts.Trailer...)
	return block, checksum
}

// WithDOSStub builds a PE32 or PE32+ image whose DOS stub [0x40:e_lfanew] is
// stub (preserving the first 60 DOS header bytes from stubPrefix if needed).
func WithDOSStub(is64 bool, dosBytes []byte, stub []byte) []byte {
	base := Minimal(is64, 1)
	optSize := 224
	if is64 {
		optSize = 240
	}
	peHeaders := append([]byte(nil), base[0x80:0x80+4+20+optSize+40]...)
	peOffset := 0x40 + len(stub)
	totalHdr := (peOffset + len(peHeaders) + 511) &^ 511
	out := make([]byte, totalHdr+512)
	copy(out[:0x3c], base[:0x3c])
	if len(dosBytes) > 0 {
		limit := min(len(dosBytes), 0x3c)
		copy(out[:limit], dosBytes[:limit])
	}
	out[0], out[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(out[0x3c:], uint32(peOffset))
	copy(out[0x40:], stub)
	copy(out[peOffset:], peHeaders)

	opt := out[peOffset+24 : peOffset+24+optSize]
	binary.LittleEndian.PutUint32(opt[60:], uint32(totalHdr))
	sec := out[peOffset+24+optSize : peOffset+24+optSize+40]
	binary.LittleEndian.PutUint32(sec[20:], uint32(totalHdr))
	return out
}

// RichPE builds a PE32 or PE32+ image with a Rich header encoded according to
// opts (with default 64-byte MS-DOS stub prefix if DOSStubPrefix is empty).
func RichPE(is64 bool, opts RichOptions) ([]byte, uint32) {
	dosPrefix := make([]byte, 0x40)
	dosPrefix[0], dosPrefix[1] = 'M', 'Z'
	dosPrefix[0x02] = 0x90
	dosPrefix[0x04] = 0x03
	dosPrefix[0x18] = 0x40
	stubPrefix := opts.DOSStubPrefix
	if stubPrefix == nil {
		// Realistic 64-byte stub padding before DanS at offset 0x80.
		stubPrefix = []byte(
			"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00",
		)
		if len(stubPrefix) < 64 {
			stubPrefix = append(stubPrefix, make([]byte, 64-len(stubPrefix))...)
		} else {
			stubPrefix = stubPrefix[:64]
		}
	}
	dosAndStubPrefix := append(append([]byte(nil), dosPrefix...), stubPrefix...)
	block, checksum := EncodeRichBlock(dosAndStubPrefix, opts)
	stub := append(append([]byte(nil), stubPrefix...), block...)
	return WithDOSStub(is64, dosPrefix, stub), checksum
}
