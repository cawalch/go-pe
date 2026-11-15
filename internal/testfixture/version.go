package testfixture

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// VersionNodeSpec describes one raw VS_VERSION_INFO node for synthetic fixtures.
type VersionNodeSpec struct {
	Key            string
	RawKeyUnits    []uint16
	OmitKeyNUL     bool
	Type           uint16
	HasCustomValLn bool
	CustomValLn    uint16
	ValueBytes     []byte
	TextValue      string
	HasTextValue   bool
	OmitTextNUL    bool
	PadInsideNode  bool
	CustomLength   uint16
	HasCustomLen   bool
	Children       []VersionNodeSpec
}

// BuildVersionNode encodes spec (and its aligned children) into binary
// VS_VERSION_INFO format.
func BuildVersionNode(spec VersionNodeSpec) []byte {
	var buf []byte
	buf = append(buf, make([]byte, 6)...)

	var units []uint16
	if spec.RawKeyUnits != nil {
		units = append(units, spec.RawKeyUnits...)
	} else {
		units = utf16.Encode([]rune(spec.Key))
	}
	if !spec.OmitKeyNUL {
		units = append(units, 0)
	}
	for _, u := range units {
		buf = appendUint16(buf, u)
	}

	var val []byte
	var wValueLength uint16
	switch {
	case spec.HasTextValue:
		textUnits := utf16.Encode([]rune(spec.TextValue))
		if !spec.OmitTextNUL {
			textUnits = append(textUnits, 0)
		}
		for _, u := range textUnits {
			val = appendUint16(val, u)
		}
		wValueLength = uint16(len(textUnits))
	case len(spec.ValueBytes) > 0:
		val = spec.ValueBytes
		wValueLength = uint16(len(val))
	}
	if spec.HasCustomValLn {
		wValueLength = spec.CustomValLn
	}

	if len(val) > 0 {
		buf = pad4(buf)
		buf = append(buf, val...)
	}

	if len(spec.Children) > 0 {
		for _, child := range spec.Children {
			buf = pad4(buf)
			buf = append(buf, BuildVersionNode(child)...)
		}
	}

	if spec.PadInsideNode {
		buf = pad4(buf)
	}

	wLength := uint16(len(buf))
	if spec.HasCustomLen {
		wLength = spec.CustomLength
	}
	binary.LittleEndian.PutUint16(buf[0:2], wLength)
	binary.LittleEndian.PutUint16(buf[2:4], wValueLength)
	binary.LittleEndian.PutUint16(buf[4:6], spec.Type)
	return buf
}

func appendUint16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// StandardVersionPayload builds a realistic VS_VERSION_INFO payload with fixed
// file info, ordered StringFileInfo tables, duplicate/empty/Unicode keys, and
// VarFileInfo translation pairs.
func StandardVersionPayload(entriesPerTable int) []byte {
	ffi := make([]byte, 52)
	binary.LittleEndian.PutUint32(ffi[0:4], 0xFEEF04BD)
	binary.LittleEndian.PutUint32(ffi[4:8], 0x00010000)
	binary.LittleEndian.PutUint32(ffi[8:12], 0x00030004)
	binary.LittleEndian.PutUint32(ffi[12:16], 0x00050006)
	binary.LittleEndian.PutUint32(ffi[16:20], 0x00070008)
	binary.LittleEndian.PutUint32(ffi[20:24], 0x0009000A)
	binary.LittleEndian.PutUint32(ffi[24:28], 0x0000003F)
	binary.LittleEndian.PutUint32(ffi[28:32], 0x00000002)
	binary.LittleEndian.PutUint32(ffi[32:36], 0x00040004)
	binary.LittleEndian.PutUint32(ffi[36:40], 0x00000001)

	strings := make([]VersionNodeSpec, entriesPerTable)
	for i := range entriesPerTable {
		strings[i] = VersionNodeSpec{
			Key:          fmt.Sprintf("Key%04d", i),
			Type:         1,
			TextValue:    fmt.Sprintf("Value-%04d", i),
			HasTextValue: true,
		}
	}

	trans := []byte{0x09, 0x04, 0xb0, 0x04}
	return BuildVersionNode(VersionNodeSpec{
		Key:        "VS_VERSION_INFO",
		Type:       0,
		ValueBytes: ffi,
		Children: []VersionNodeSpec{
			{
				Key:  "StringFileInfo",
				Type: 1,
				Children: []VersionNodeSpec{
					{
						Key:      "040904B0",
						Type:     1,
						Children: strings,
					},
				},
			},
			{
				Key:  "VarFileInfo",
				Type: 1,
				Children: []VersionNodeSpec{
					{
						Key:        "Translation",
						Type:       0,
						ValueBytes: trans,
					},
				},
			},
		},
	})
}
