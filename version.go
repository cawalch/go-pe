package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Version-information record constants from the Windows VS_VERSIONINFO layout.
const (
	// VersionFixedInfoSignature is the magic dwSignature value (0xFEEF04BD)
	// required when VS_FIXEDFILEINFO is present in a VS_VERSIONINFO record.
	VersionFixedInfoSignature uint32 = 0xFEEF04BD

	// VersionValueBinary indicates binary data in a version record (wType == 0).
	// Its wValueLength field specifies a byte count.
	VersionValueBinary uint16 = 0

	// VersionValueText indicates UTF-16LE text data in a version record (wType == 1).
	// Its wValueLength field specifies a count of 16-bit UTF-16 code units.
	VersionValueText uint16 = 1

	versionHeaderSize    = 6
	fixedFileInfoSize    = 52
	versionStringCost    = 32
	versionTableCost     = 32
	versionVarCost       = 48
	versionBlockCost     = 64
	versionTranslationSz = 4
)

// Parser limits bounding VS_VERSIONINFO decoding work and allocations.
// They are resource limits, not Windows loader requirements.
const (
	// MaxVersionPayloadBytes limits the input payload byte size accepted by
	// [ParseVersionInfo].
	MaxVersionPayloadBytes = MaxResourcePayloadBytes
	// MaxVersionNodes limits total VS_VERSIONINFO tree nodes visited across the
	// root, containers, tables, string entries, var entries, and unknown blocks.
	MaxVersionNodes = 4096
	// MaxVersionTables limits total StringTable blocks decoded across all
	// StringFileInfo containers.
	MaxVersionTables = 256
	// MaxVersionStrings limits total String entries decoded across all StringTables.
	MaxVersionStrings = 4096
	// MaxVersionTranslations limits cumulative (LanguageID, CodePage) pairs
	// decoded from Var "Translation" records.
	MaxVersionTranslations = 1024
	// MaxVersionNameUnits limits the UTF-16 code unit length of one node key (szKey).
	MaxVersionNameUnits = 2048
	// MaxVersionValueUnits limits the UTF-16 code unit length of one text value.
	MaxVersionValueUnits = 32768
	// MaxVersionOutputBytes limits cumulative decoded strings, binary values,
	// and entry overhead retained in a [VersionInfo].
	MaxVersionOutputBytes = 4 << 20
)

var (
	// ErrInvalidVersionInfo indicates malformed, truncated, misaligned, or
	// inconsistent VS_VERSIONINFO metadata.
	ErrInvalidVersionInfo = errors.New("invalid version info metadata")
	// ErrVersionInfoLimit indicates that version-info decoding exceeded a parser
	// limit.
	ErrVersionInfoLimit = errors.New("version info parser limit exceeded")
)

// FixedFileInfo represents the Windows VS_FIXEDFILEINFO structure embedded in
// the root VS_VERSION_INFO record.
type FixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

// VersionString represents one ordered key-value entry inside a [VersionStringTable].
// Duplicate keys and empty values are preserved without overwriting.
type VersionString struct {
	Key   string
	Value string
}

// VersionStringTable represents one ordered language/code-page StringTable
// child block inside a StringFileInfo container.
type VersionStringTable struct {
	Key     string
	Entries []VersionString
}

// VersionTranslation represents one (LanguageID, CodePage) pair from a
// VarFileInfo "Translation" record.
type VersionTranslation struct {
	LanguageID uint16
	CodePage   uint16
}

// VersionVar represents one Var record inside a VarFileInfo container. When
// Key is "Translation", Translations holds the decoded (LanguageID, CodePage)
// pairs in file order. RawValue retains an owned copy of the value bytes.
type VersionVar struct {
	Key          string
	Type         uint16
	Translations []VersionTranslation
	RawValue     []byte
}

// VersionBlock preserves an unrecognized child block encountered directly inside
// VS_VERSION_INFO without discarding custom metadata.
type VersionBlock struct {
	Key       string
	Type      uint16
	RawValue  []byte
	RawRemain []byte
}

// VersionInfo holds decoded Windows VS_VERSION_INFO records from a resource
// payload in file order. All strings, slices, and byte buffers are owned by the
// returned value and retain no reference to the input slice.
type VersionInfo struct {
	Key           string
	Type          uint16
	HasFixedInfo  bool
	FixedInfo     FixedFileInfo
	StringTables  []VersionStringTable
	Vars          []VersionVar
	Translations  []VersionTranslation
	UnknownBlocks []VersionBlock
}

// ParseVersionInfo decodes a Windows VS_VERSION_INFO resource payload under
// explicit node, count, string-unit, and output-byte limits.
//
// Pass a single RT_VERSION resource payload (for example from
// [File.ResourcePayload]). Bytes after the root structure's declared length
// are ignored to accommodate section padding. Malformed, truncated, or
// over-limit structures return nil and an error classified with
// [ErrInvalidVersionInfo] or [ErrVersionInfoLimit].
func ParseVersionInfo(payload []byte) (*VersionInfo, error) {
	if len(payload) > MaxVersionPayloadBytes {
		return nil, fmt.Errorf("%w: version info payload size %d exceeds %d bytes", ErrVersionInfoLimit, len(payload), MaxVersionPayloadBytes)
	}
	if len(payload) < versionHeaderSize {
		return nil, fmt.Errorf("%w: version info payload %d bytes smaller than %d-byte header", ErrInvalidVersionInfo, len(payload), versionHeaderSize)
	}

	p := versionParser{data: payload}
	root, err := p.parseNode(0, len(payload), false)
	if err != nil {
		return nil, err
	}
	if root.key != "VS_VERSION_INFO" {
		return nil, fmt.Errorf("%w: unexpected root key %q", ErrInvalidVersionInfo, root.key)
	}

	out := &VersionInfo{
		Key:  root.key,
		Type: root.wType,
	}
	if err := p.addOutput(len(root.key)); err != nil {
		return nil, err
	}

	if root.valLen > 0 {
		if root.wType != VersionValueBinary {
			return nil, fmt.Errorf("%w: root fixed info has non-binary type %d", ErrInvalidVersionInfo, root.wType)
		}
		if root.valEnd-root.valStart < fixedFileInfoSize {
			return nil, fmt.Errorf("%w: fixed file info size %d smaller than %d", ErrInvalidVersionInfo, root.valEnd-root.valStart, fixedFileInfoSize)
		}
		ffi := parseFixedFileInfo(payload[root.valStart : root.valStart+fixedFileInfoSize])
		if ffi.Signature != VersionFixedInfoSignature {
			return nil, fmt.Errorf("%w: invalid fixed file info signature %#x", ErrInvalidVersionInfo, ffi.Signature)
		}
		out.HasFixedInfo = true
		out.FixedInfo = ffi
	}

	cur := align4(root.valEnd)
	for cur < root.nodeEnd {
		child, err := p.parseNode(cur, root.nodeEnd, true)
		if err != nil {
			return nil, err
		}
		switch child.key {
		case "StringFileInfo":
			if child.valLen != 0 {
				return nil, fmt.Errorf("%w: StringFileInfo carries unexpected %d-byte value", ErrInvalidVersionInfo, child.valLen)
			}
			if err := p.parseStringFileInfo(child, out); err != nil {
				return nil, err
			}
		case "VarFileInfo":
			if child.valLen != 0 {
				return nil, fmt.Errorf("%w: VarFileInfo carries unexpected %d-byte value", ErrInvalidVersionInfo, child.valLen)
			}
			if err := p.parseVarFileInfo(child, out); err != nil {
				return nil, err
			}
		default:
			if err := p.parseUnknownBlock(child, out); err != nil {
				return nil, err
			}
		}
		cur = align4(child.nodeEnd)
	}

	return out, nil
}

type versionParser struct {
	data         []byte
	nodes        int
	tables       int
	strings      int
	translations int
	outputBytes  int
	utf16Buf     []uint16
}

type versionNode struct {
	key      string
	wType    uint16
	valLen   uint16
	valStart int
	valEnd   int
	nodeEnd  int
}

func align4(n int) int {
	return (n + 3) &^ 3
}

func (p *versionParser) addOutput(n int) error {
	if n > MaxVersionOutputBytes-p.outputBytes {
		return fmt.Errorf("%w: decoded version info output exceeds %d bytes", ErrVersionInfoLimit, MaxVersionOutputBytes)
	}
	p.outputBytes += n
	return nil
}

func (p *versionParser) parseNode(off, limit int, checkValueLimit bool) (versionNode, error) {
	if p.nodes == MaxVersionNodes {
		return versionNode{}, fmt.Errorf("%w: visited version nodes exceed %d", ErrVersionInfoLimit, MaxVersionNodes)
	}
	p.nodes++

	if limit-off < versionHeaderSize {
		return versionNode{}, fmt.Errorf("%w: truncated version node header at offset %#x", ErrInvalidVersionInfo, off)
	}
	hdr := p.data[off : off+versionHeaderSize]
	wLength := int(binary.LittleEndian.Uint16(hdr[0:2]))
	wValueLength := binary.LittleEndian.Uint16(hdr[2:4])
	wType := binary.LittleEndian.Uint16(hdr[4:6])

	if wLength < versionHeaderSize || wLength > limit-off {
		return versionNode{}, fmt.Errorf("%w: version node at %#x length %d outside container end %#x", ErrInvalidVersionInfo, off, wLength, limit)
	}
	nodeEnd := off + wLength

	key, keyEnd, err := p.decodeUTF16Z(off+versionHeaderSize, nodeEnd)
	if err != nil {
		return versionNode{}, fmt.Errorf("version node key at %#x: %w", off, err)
	}

	var valBytes int
	switch wType {
	case VersionValueBinary:
		valBytes = int(wValueLength)
	case VersionValueText:
		if checkValueLimit && int(wValueLength) > MaxVersionValueUnits {
			return versionNode{}, fmt.Errorf("%w: text value length %d exceeds %d UTF-16 units", ErrVersionInfoLimit, wValueLength, MaxVersionValueUnits)
		}
		valBytes = int(wValueLength) * 2
	default:
		return versionNode{}, fmt.Errorf("%w: unsupported version value type %d at %#x", ErrInvalidVersionInfo, wType, off)
	}

	valStart := keyEnd
	valEnd := keyEnd
	if valBytes > 0 {
		valStart = align4(keyEnd)
		if valStart > nodeEnd || valBytes > nodeEnd-valStart {
			return versionNode{}, fmt.Errorf("%w: version value (%d bytes) exceeds node end %#x", ErrInvalidVersionInfo, valBytes, nodeEnd)
		}
		valEnd = valStart + valBytes
	}

	return versionNode{
		key:      key,
		wType:    wType,
		valLen:   wValueLength,
		valStart: valStart,
		valEnd:   valEnd,
		nodeEnd:  nodeEnd,
	}, nil
}

func (p *versionParser) decodeUTF16Z(start, end int) (string, int, error) {
	units := 0
	for pos := start; pos+2 <= end; pos += 2 {
		u := binary.LittleEndian.Uint16(p.data[pos : pos+2])
		if u == 0 {
			if units == 0 {
				return "", pos + 2, nil
			}
			return string(utf16.Decode(p.utf16Buf[:units])), pos + 2, nil
		}
		if units == MaxVersionNameUnits {
			return "", 0, fmt.Errorf("%w: key length exceeds %d UTF-16 units", ErrVersionInfoLimit, MaxVersionNameUnits)
		}
		if units < len(p.utf16Buf) {
			p.utf16Buf[units] = u
		} else {
			p.utf16Buf = append(p.utf16Buf, u)
		}
		units++
	}
	return "", 0, fmt.Errorf("%w: unterminated UTF-16 key", ErrInvalidVersionInfo)
}

func (p *versionParser) decodeUTF16Units(raw []byte) string {
	count := len(raw) / 2
	if count == 0 {
		return ""
	}
	if cap(p.utf16Buf) < count {
		p.utf16Buf = make([]uint16, count)
	} else {
		p.utf16Buf = p.utf16Buf[:count]
	}
	n := 0
	for i := range count {
		u := binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
		if u == 0 {
			break
		}
		p.utf16Buf[n] = u
		n++
	}
	if n == 0 {
		return ""
	}
	return string(utf16.Decode(p.utf16Buf[:n]))
}

func parseFixedFileInfo(b []byte) FixedFileInfo {
	return FixedFileInfo{
		Signature:        binary.LittleEndian.Uint32(b[0:4]),
		StrucVersion:     binary.LittleEndian.Uint32(b[4:8]),
		FileVersionMS:    binary.LittleEndian.Uint32(b[8:12]),
		FileVersionLS:    binary.LittleEndian.Uint32(b[12:16]),
		ProductVersionMS: binary.LittleEndian.Uint32(b[16:20]),
		ProductVersionLS: binary.LittleEndian.Uint32(b[20:24]),
		FileFlagsMask:    binary.LittleEndian.Uint32(b[24:28]),
		FileFlags:        binary.LittleEndian.Uint32(b[28:32]),
		FileOS:           binary.LittleEndian.Uint32(b[32:36]),
		FileType:         binary.LittleEndian.Uint32(b[36:40]),
		FileSubtype:      binary.LittleEndian.Uint32(b[40:44]),
		FileDateMS:       binary.LittleEndian.Uint32(b[44:48]),
		FileDateLS:       binary.LittleEndian.Uint32(b[48:52]),
	}
}

func (p *versionParser) parseStringFileInfo(container versionNode, out *VersionInfo) error {
	cur := align4(container.valEnd)
	for cur < container.nodeEnd {
		if p.tables == MaxVersionTables {
			return fmt.Errorf("%w: StringTable count exceeds %d", ErrVersionInfoLimit, MaxVersionTables)
		}
		p.tables++

		tableNode, err := p.parseNode(cur, container.nodeEnd, true)
		if err != nil {
			return err
		}
		if tableNode.valLen != 0 {
			return fmt.Errorf("%w: StringTable %q carries unexpected %d-byte value", ErrInvalidVersionInfo, tableNode.key, tableNode.valLen)
		}
		if err := p.addOutput(versionTableCost + len(tableNode.key)); err != nil {
			return err
		}

		table := VersionStringTable{Key: tableNode.key}
		sCur := align4(tableNode.valEnd)
		for sCur < tableNode.nodeEnd {
			if p.strings == MaxVersionStrings {
				return fmt.Errorf("%w: String entry count exceeds %d", ErrVersionInfoLimit, MaxVersionStrings)
			}
			p.strings++

			entry, err := p.parseNode(sCur, tableNode.nodeEnd, true)
			if err != nil {
				return err
			}
			// Leaf String entries cannot contain child structures; only trailing
			// DWORD alignment padding (< 4 bytes) may remain inside wLength.
			if entry.nodeEnd-entry.valEnd >= 4 {
				return fmt.Errorf("%w: String %q has %d unexpected trailing bytes", ErrInvalidVersionInfo, entry.key, entry.nodeEnd-entry.valEnd)
			}
			rawVal := p.data[entry.valStart:entry.valEnd]
			if entry.wType == VersionValueBinary && len(rawVal)%2 != 0 {
				return fmt.Errorf("%w: String %q binary UTF-16 value has odd length %d", ErrInvalidVersionInfo, entry.key, len(rawVal))
			}
			val := p.decodeUTF16Units(rawVal)
			if err := p.addOutput(versionStringCost + len(entry.key) + len(val)); err != nil {
				return err
			}
			table.Entries = append(table.Entries, VersionString{
				Key:   entry.key,
				Value: val,
			})
			sCur = align4(entry.nodeEnd)
		}

		out.StringTables = append(out.StringTables, table)
		cur = align4(tableNode.nodeEnd)
	}
	return nil
}

func (p *versionParser) parseVarFileInfo(container versionNode, out *VersionInfo) error {
	cur := align4(container.valEnd)
	for cur < container.nodeEnd {
		varNode, err := p.parseNode(cur, container.nodeEnd, true)
		if err != nil {
			return err
		}
		if varNode.nodeEnd-varNode.valEnd >= 4 {
			return fmt.Errorf("%w: Var %q has %d unexpected trailing bytes", ErrInvalidVersionInfo, varNode.key, varNode.nodeEnd-varNode.valEnd)
		}
		rawLen := varNode.valEnd - varNode.valStart
		if err := p.addOutput(versionVarCost + len(varNode.key) + rawLen); err != nil {
			return err
		}

		var rawCopy []byte
		if rawLen > 0 {
			rawCopy = make([]byte, rawLen)
			copy(rawCopy, p.data[varNode.valStart:varNode.valEnd])
		}

		v := VersionVar{
			Key:      varNode.key,
			Type:     varNode.wType,
			RawValue: rawCopy,
		}
		if varNode.key == "Translation" {
			if varNode.wType != VersionValueBinary || rawLen%versionTranslationSz != 0 {
				return fmt.Errorf("%w: malformed Translation Var (type=%d bytes=%d)", ErrInvalidVersionInfo, varNode.wType, rawLen)
			}
			pairCount := rawLen / versionTranslationSz
			if pairCount > MaxVersionTranslations-p.translations {
				return fmt.Errorf("%w: translation pairs exceed %d", ErrVersionInfoLimit, MaxVersionTranslations)
			}
			p.translations += pairCount
			if err := p.addOutput(pairCount * versionTranslationSz); err != nil {
				return err
			}
			if pairCount > 0 {
				translations := make([]VersionTranslation, pairCount)
				for i := range pairCount {
					pair := rawCopy[i*4:]
					translations[i] = VersionTranslation{
						LanguageID: binary.LittleEndian.Uint16(pair[0:2]),
						CodePage:   binary.LittleEndian.Uint16(pair[2:4]),
					}
				}
				v.Translations = translations
				out.Translations = append(out.Translations, translations...)
			}
		}

		out.Vars = append(out.Vars, v)
		cur = align4(varNode.nodeEnd)
	}
	return nil
}

func (p *versionParser) parseUnknownBlock(node versionNode, out *VersionInfo) error {
	valLen := node.valEnd - node.valStart
	remStart := align4(node.valEnd)
	remLen := 0
	if remStart < node.nodeEnd {
		remLen = node.nodeEnd - remStart
	}
	if err := p.addOutput(versionBlockCost + len(node.key) + valLen + remLen); err != nil {
		return err
	}
	var rawVal []byte
	if valLen > 0 {
		rawVal = make([]byte, valLen)
		copy(rawVal, p.data[node.valStart:node.valEnd])
	}
	var rawRem []byte
	if remLen > 0 {
		rawRem = make([]byte, remLen)
		copy(rawRem, p.data[remStart:node.nodeEnd])
	}
	out.UnknownBlocks = append(out.UnknownBlocks, VersionBlock{
		Key:       node.key,
		Type:      node.wType,
		RawValue:  rawVal,
		RawRemain: rawRem,
	})
	return nil
}
