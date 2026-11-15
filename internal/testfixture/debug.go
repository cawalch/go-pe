package testfixture

import "encoding/binary"

// DebugEntrySpec describes one debug directory entry and optional payload bytes
// to embed in a synthetic PE image built by [DebugPE].
type DebugEntrySpec struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32

	// Payload, when non-empty, is embedded and wired automatically unless
	// RawOnly, RVAOnly, or explicit AddressOfRawData/PointerToRawData are set.
	Payload  []byte
	RawOnly  bool
	RVAOnly  bool
	Overlay  bool
	KeepSize bool
}

// EncodeCodeViewRSDS encodes an RSDS (PDB 7.0) CodeView payload. If includeNUL
// is true, a trailing 0x00 terminator is appended to path.
func EncodeCodeViewRSDS(guid [16]byte, age uint32, path []byte, includeNUL bool) []byte {
	n := 24 + len(path)
	if includeNUL {
		n++
	}
	out := make([]byte, n)
	binary.LittleEndian.PutUint32(out[0:4], 0x53445352)
	copy(out[4:20], guid[:])
	binary.LittleEndian.PutUint32(out[20:24], age)
	copy(out[24:], path)
	return out
}

// EncodeCodeViewNB10 encodes an NB10 (PDB 2.0) CodeView payload. If includeNUL
// is true, a trailing 0x00 terminator is appended to path.
func EncodeCodeViewNB10(offset, signature, age uint32, path []byte, includeNUL bool) []byte {
	n := 16 + len(path)
	if includeNUL {
		n++
	}
	out := make([]byte, n)
	binary.LittleEndian.PutUint32(out[0:4], 0x3031424e)
	binary.LittleEndian.PutUint32(out[4:8], offset)
	binary.LittleEndian.PutUint32(out[8:12], signature)
	binary.LittleEndian.PutUint32(out[12:16], age)
	copy(out[16:], path)
	return out
}

// DebugPE builds a PE32 or PE32+ image containing a debug directory in a single
// .rdata section and optional overlay bytes after the section.
func DebugPE(is64 bool, specs []DebugEntrySpec) []byte {
	data := Minimal(is64, 1)
	dirOff, secOff := 248, 376
	if is64 {
		dirOff, secOff = 264, 392
	}
	debugDirOff := dirOff + 6*8

	const secFileStart = 512
	const secRVAStart = 0x1000
	tableSize := len(specs) * 28

	sectionBytes := make([]byte, tableSize)
	var overlayBytes []byte
	overlayStartDelta := uint32(0)

	// Measure section size first so overlay offsets can follow aligned section end.
	secPayloadPos := tableSize
	for _, s := range specs {
		if len(s.Payload) > 0 && !s.Overlay {
			secPayloadPos += len(s.Payload)
		}
	}
	alignedSecSize := (max(secPayloadPos, 1) + 511) &^ 511
	sectionBytes = append(sectionBytes, make([]byte, alignedSecSize-len(sectionBytes))...)
	overlayBase := uint32(secFileStart + alignedSecSize)

	curSecPos := tableSize
	for i, s := range specs {
		sizeOfData := s.SizeOfData
		addrOfRaw := s.AddressOfRawData
		ptrOfRaw := s.PointerToRawData

		if len(s.Payload) > 0 {
			if !s.KeepSize && sizeOfData == 0 {
				sizeOfData = uint32(len(s.Payload))
			}
			if s.Overlay {
				off := overlayBase + overlayStartDelta
				overlayBytes = append(overlayBytes, s.Payload...)
				overlayStartDelta += uint32(len(s.Payload))
				if ptrOfRaw == 0 {
					ptrOfRaw = off
				}
			} else {
				copy(sectionBytes[curSecPos:], s.Payload)
				rva := uint32(secRVAStart + curSecPos)
				raw := uint32(secFileStart + curSecPos)
				curSecPos += len(s.Payload)
				if addrOfRaw == 0 && !s.RawOnly {
					addrOfRaw = rva
				}
				if ptrOfRaw == 0 && !s.RVAOnly {
					ptrOfRaw = raw
				}
			}
		}

		ent := sectionBytes[i*28 : (i+1)*28]
		binary.LittleEndian.PutUint32(ent[0:4], s.Characteristics)
		binary.LittleEndian.PutUint32(ent[4:8], s.TimeDateStamp)
		binary.LittleEndian.PutUint16(ent[8:10], s.MajorVersion)
		binary.LittleEndian.PutUint16(ent[10:12], s.MinorVersion)
		binary.LittleEndian.PutUint32(ent[12:16], s.Type)
		binary.LittleEndian.PutUint32(ent[16:20], sizeOfData)
		binary.LittleEndian.PutUint32(ent[20:24], addrOfRaw)
		binary.LittleEndian.PutUint32(ent[24:28], ptrOfRaw)
	}

	copy(data[secOff:secOff+8], ".rdata\x00\x00")
	binary.LittleEndian.PutUint32(data[secOff+8:], uint32(alignedSecSize))
	binary.LittleEndian.PutUint32(data[secOff+12:], secRVAStart)
	binary.LittleEndian.PutUint32(data[secOff+16:], uint32(alignedSecSize))
	binary.LittleEndian.PutUint32(data[secOff+20:], secFileStart)
	binary.LittleEndian.PutUint32(data[secOff+36:], 0x40000040)

	sizeOfImage := uint32(secRVAStart) + ((uint32(alignedSecSize) + 0xfff) &^ 0xfff)
	binary.LittleEndian.PutUint32(data[152+56:], sizeOfImage)

	if len(specs) > 0 {
		binary.LittleEndian.PutUint32(data[debugDirOff:], secRVAStart)
		binary.LittleEndian.PutUint32(data[debugDirOff+4:], uint32(tableSize))
	}

	out := make([]byte, 0, secFileStart+len(sectionBytes)+len(overlayBytes))
	out = append(out, data[:secFileStart]...)
	out = append(out, sectionBytes...)
	out = append(out, overlayBytes...)
	return out
}
