package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf16"
)

// Parser limits bound resource directory traversal, decoding, and payload reads.
// They are resource limits, not Windows loader requirements.
const (
	// MaxResourceDepth limits directory recursion depth and maximum resource
	// path component length.
	MaxResourceDepth = 16
	// MaxResourceNodes limits total visited directory tables during traversal,
	// including repeated visits across shared subtrees.
	MaxResourceNodes = 8192
	// MaxResourceEntries limits total directory entries read across all visited
	// directory tables.
	MaxResourceEntries = 32768
	// MaxResourceRecords limits total leaf resource records returned.
	MaxResourceRecords = 16384
	// MaxResourceNameUnits limits the UTF-16 code unit length of one named
	// resource component.
	MaxResourceNameUnits = 2048
	// MaxResourceStringUnits limits total UTF-16 code units decoded across all
	// visited named entries, including repeated visits in shared subtrees.
	MaxResourceStringUnits = 1 << 17
	// MaxResourceOutputBytes limits the cumulative logical byte size of returned
	// leaf records, path components, and component names.
	MaxResourceOutputBytes = 4 << 20
	// MaxResourcePayloadBytes limits the byte size of one extracted payload in
	// [File.ResourcePayload].
	MaxResourcePayloadBytes = 16 << 20
)

var (
	// ErrInvalidResource indicates malformed, cyclic, or out-of-directory
	// resource metadata.
	ErrInvalidResource = errors.New("invalid resource metadata")
	// ErrResourceLimit indicates that resource parsing or payload extraction
	// exceeded a parser limit.
	ErrResourceLimit = errors.New("resource parser limit exceeded")
)

const (
	resourceDirectoryHeaderSize = 16
	resourceDirectoryEntrySize  = 8
	resourceDataEntrySize       = 16
	resourceHighBit             = 1 << 31
	resourceRecordOutputBytes   = 48
	resourceComponentBytes      = 24
)

// ResourceDirectory describes the root IMAGE_RESOURCE_DIRECTORY header and all
// leaf resource records reached during bounded traversal.
type ResourceDirectory struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIDEntries    uint16
	Records              []ResourceRecord
}

// ResourceComponent identifies one named UTF-16 or numeric step in a resource
// path. When Named is true, Name holds the decoded string and ID is zero.
// Otherwise, Name is empty and ID holds the entry's 31-bit numeric identifier.
// Named distinguishes an empty string name from numeric identifier zero.
type ResourceComponent struct {
	Name  string
	ID    uint32
	Named bool
}

// ResourceRecord describes one IMAGE_RESOURCE_DATA_ENTRY leaf record and the
// path of components from the root directory to the leaf. Standard Windows
// resources use three components (Type, Name or ID, Language), while nonstandard
// trees produce shorter or longer paths up to [MaxResourceDepth].
//
// DataRVA, Size, CodePage, and Reserved preserve the raw entry fields without
// validating or copying payload bytes. Call [File.ResourcePayload] to read
// requested payload bytes.
type ResourceRecord struct {
	Path     []ResourceComponent
	DataRVA  uint32
	Size     uint32
	CodePage uint32
	Reserved uint32
}

// Resources reads resource directory metadata and leaf records from data using
// f's headers without copying resource payloads. Pass the original file bytes
// used by [New]. Don't modify data or f during the call. Results own their
// slices and decoded strings; neither f nor the results retain data. Calls don't
// cache results or modify f.
//
// A missing directory (absent from data directories, or both RVA and size zero)
// returns nil, nil. Malformed, truncated, cyclic, or over-limit resource graphs
// return nil and an error, never partial results.
//
// Resources traverses nodes in depth-first pre-order, iterating entries in file
// order (`NumberOfNamedEntries` entries followed by `NumberOfIDEntries`
// entries) at each directory node. Cycles (an entry targeting an active ancestor
// node) return [ErrInvalidResource]. Shared non-ancestor subtrees (DAGs) are
// re-traversed along each reaching path so all distinct resource paths are
// preserved, with every visit charged against cumulative node, entry, string,
// leaf, and output byte limits ([ErrResourceLimit]).
//
// Offsets inside the resource directory (directory pointers, named string
// offsets, and data entry pointers) are validated relative to the resource root
// within the declared resource directory size and mapped via [File.rvaSpan].
// Named entries are decoded as little-endian UTF-16 strings with unpaired
// surrogates replaced by U+FFFD. Leaf payload RVAs (`DataRVA`) are preserved as
// raw metadata independent of the resource directory bounds and may point to any
// section when later read via [File.ResourcePayload].
func (f *File) Resources(data []byte) (*ResourceDirectory, error) {
	if f == nil || (!f.Is32Bit() && !f.Is64Bit()) {
		return nil, fmt.Errorf("%w: file headers not parsed", ErrInvalidHeader)
	}
	if len(f.Sections) > MaxSections {
		return nil, fmt.Errorf("%w: %d exceeds %d", ErrSectionLimit, len(f.Sections), MaxSections)
	}
	if f.OptionalHeader.NumberOfRvaAndSizes <= DataDirectoryResource {
		return nil, nil
	}
	dir := f.OptionalHeader.DataDirectories[DataDirectoryResource]
	if dir.VirtualAddress == 0 && dir.Size == 0 {
		return nil, nil
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil, fmt.Errorf("%w: incomplete resource data directory", ErrInvalidResource)
	}
	if uint64(dir.VirtualAddress)+uint64(dir.Size) > uint64(math.MaxUint32)+1 {
		return nil, fmt.Errorf("%w: resource directory extends past 32-bit RVA space", ErrIntegerOverflow)
	}
	if dir.Size < resourceDirectoryHeaderSize {
		return nil, fmt.Errorf("%w: resource directory size %d smaller than %d-byte header", ErrInvalidResource, dir.Size, resourceDirectoryHeaderSize)
	}

	p := resourceParser{
		file:    f,
		data:    data,
		rootRVA: dir.VirtualAddress,
		dirSize: dir.Size,
	}
	var out ResourceDirectory
	if err := p.walkDir(0, 0, &out); err != nil {
		return nil, err
	}
	out.Records = p.records
	return &out, nil
}

// ResourcePayload returns a newly allocated copy of the payload bytes for
// record, validating integer bounds, [MaxResourcePayloadBytes], and section
// mapping via [File.RVAToOffset].
//
// Pass the original file bytes used by [New]. Callers may modify or clear data
// after ResourcePayload returns without affecting the returned slice. Payload
// RVAs may point to any mapped header or raw section range, including sections
// other than `.rsrc`, provided the full byte range fits within one contiguous
// mapped span.
func (f *File) ResourcePayload(data []byte, record ResourceRecord) ([]byte, error) {
	if f == nil || (!f.Is32Bit() && !f.Is64Bit()) {
		return nil, fmt.Errorf("%w: file headers not parsed", ErrInvalidHeader)
	}
	if len(f.Sections) > MaxSections {
		return nil, fmt.Errorf("%w: %d exceeds %d", ErrSectionLimit, len(f.Sections), MaxSections)
	}
	if uint64(record.Size) > MaxResourcePayloadBytes {
		return nil, fmt.Errorf("%w: resource payload size %d exceeds %d", ErrResourceLimit, record.Size, MaxResourcePayloadBytes)
	}
	if uint64(record.DataRVA)+uint64(record.Size) > uint64(math.MaxUint32)+1 {
		return nil, fmt.Errorf("%w: resource payload RVA %#x + size %#x overflows 32-bit RVA space", ErrIntegerOverflow, record.DataRVA, record.Size)
	}
	span, err := f.rvaSpan(data, record.DataRVA)
	if err != nil {
		return nil, err
	}
	if uint64(len(span)) < uint64(record.Size) {
		return nil, fmt.Errorf("%w: resource payload [%#x, %#x) truncated at %d bytes", ErrOutOfBounds, record.DataRVA, uint64(record.DataRVA)+uint64(record.Size), len(span))
	}
	out := make([]byte, int(record.Size))
	copy(out, span[:int(record.Size)])
	return out, nil
}

type resourceParser struct {
	file        *File
	data        []byte
	rootRVA     uint32
	dirSize     uint32
	nodes       int
	entries     int
	stringUnits int
	outputBytes int
	stack       [MaxResourceDepth]uint32
	path        [MaxResourceDepth]ResourceComponent
	utf16Buf    []uint16
	records     []ResourceRecord
}

func (p *resourceParser) spanAt(relOffset uint32, size uint64) ([]byte, error) {
	endRel := uint64(relOffset) + size
	if endRel < uint64(relOffset) || uint64(p.rootRVA)+endRel > uint64(math.MaxUint32)+1 {
		return nil, ErrIntegerOverflow
	}
	if endRel > uint64(p.dirSize) {
		return nil, fmt.Errorf("%w: resource offset %#x..%#x exceeds directory size %#x", ErrInvalidResource, relOffset, endRel, p.dirSize)
	}
	span, err := p.file.rvaSpan(p.data, p.rootRVA+relOffset)
	if err != nil {
		return nil, err
	}
	if uint64(len(span)) < size {
		return nil, ErrOutOfBounds
	}
	return span[:size], nil
}

func (p *resourceParser) walkDir(relOffset uint32, depth int, rootOut *ResourceDirectory) error {
	if depth >= MaxResourceDepth {
		return fmt.Errorf("%w: resource depth exceeds %d", ErrResourceLimit, MaxResourceDepth)
	}
	if p.nodes == MaxResourceNodes {
		return fmt.Errorf("%w: visited resource nodes exceed %d", ErrResourceLimit, MaxResourceNodes)
	}
	p.nodes++

	hdr, err := p.spanAt(relOffset, resourceDirectoryHeaderSize)
	if err != nil {
		return fmt.Errorf("resource directory at %#x: %w", relOffset, err)
	}

	characteristics := binary.LittleEndian.Uint32(hdr[0:4])
	timeDateStamp := binary.LittleEndian.Uint32(hdr[4:8])
	majorVersion := binary.LittleEndian.Uint16(hdr[8:10])
	minorVersion := binary.LittleEndian.Uint16(hdr[10:12])
	namedCount := binary.LittleEndian.Uint16(hdr[12:14])
	idCount := binary.LittleEndian.Uint16(hdr[14:16])

	if rootOut != nil {
		rootOut.Characteristics = characteristics
		rootOut.TimeDateStamp = timeDateStamp
		rootOut.MajorVersion = majorVersion
		rootOut.MinorVersion = minorVersion
		rootOut.NumberOfNamedEntries = namedCount
		rootOut.NumberOfIDEntries = idCount
	}

	entryCount := uint32(namedCount) + uint32(idCount)
	if entryCount > uint32(MaxResourceEntries-p.entries) {
		return fmt.Errorf("%w: resource directory entries exceed %d", ErrResourceLimit, MaxResourceEntries)
	}
	p.entries += int(entryCount)
	if entryCount == 0 {
		return nil
	}

	tableBytes := uint64(entryCount) * resourceDirectoryEntrySize
	fullNode, err := p.spanAt(relOffset, resourceDirectoryHeaderSize+tableBytes)
	if err != nil {
		return fmt.Errorf("resource directory entries at %#x: %w", relOffset, err)
	}
	table := fullNode[resourceDirectoryHeaderSize:]
	p.stack[depth] = relOffset

	for i := range int(entryCount) {
		entry := table[i*resourceDirectoryEntrySize:]
		rawName := binary.LittleEndian.Uint32(entry[0:4])
		rawOffset := binary.LittleEndian.Uint32(entry[4:8])

		var comp ResourceComponent
		if rawName&resourceHighBit != 0 {
			name, err := p.decodeName(rawName &^ resourceHighBit)
			if err != nil {
				return fmt.Errorf("resource entry %d name: %w", i, err)
			}
			comp = ResourceComponent{Named: true, Name: name}
		} else {
			comp = ResourceComponent{ID: rawName}
		}
		p.path[depth] = comp

		targetRel := rawOffset &^ resourceHighBit
		if rawOffset&resourceHighBit != 0 {
			if slices.Contains(p.stack[:depth+1], targetRel) {
				return fmt.Errorf("%w: resource directory cycle targeting offset %#x", ErrInvalidResource, targetRel)
			}
			if err := p.walkDir(targetRel, depth+1, nil); err != nil {
				return err
			}
			continue
		}

		if err := p.addLeaf(targetRel, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (p *resourceParser) decodeName(relOffset uint32) (string, error) {
	hdr, err := p.spanAt(relOffset, 2)
	if err != nil {
		return "", err
	}
	units := binary.LittleEndian.Uint16(hdr)
	if int(units) > MaxResourceNameUnits {
		return "", fmt.Errorf("%w: name length %d exceeds %d UTF-16 units", ErrResourceLimit, units, MaxResourceNameUnits)
	}
	if int(units) > MaxResourceStringUnits-p.stringUnits {
		return "", fmt.Errorf("%w: total decoded UTF-16 units exceed %d", ErrResourceLimit, MaxResourceStringUnits)
	}
	if units == 0 {
		return "", nil
	}
	raw, err := p.spanAt(relOffset, 2+uint64(units)*2)
	if err != nil {
		return "", err
	}
	p.stringUnits += int(units)
	if cap(p.utf16Buf) < int(units) {
		p.utf16Buf = make([]uint16, int(units))
	} else {
		p.utf16Buf = p.utf16Buf[:int(units)]
	}
	for i := range int(units) {
		p.utf16Buf[i] = binary.LittleEndian.Uint16(raw[2+i*2:])
	}
	return string(utf16.Decode(p.utf16Buf)), nil
}

func (p *resourceParser) addLeaf(relOffset uint32, pathLen int) error {
	if len(p.records) == MaxResourceRecords {
		return fmt.Errorf("%w: resource record count exceeds %d", ErrResourceLimit, MaxResourceRecords)
	}
	raw, err := p.spanAt(relOffset, resourceDataEntrySize)
	if err != nil {
		return fmt.Errorf("resource data entry at %#x: %w", relOffset, err)
	}

	cost := resourceRecordOutputBytes + pathLen*resourceComponentBytes
	if cost > MaxResourceOutputBytes-p.outputBytes {
		return fmt.Errorf("%w: resource output size exceeds %d bytes", ErrResourceLimit, MaxResourceOutputBytes)
	}
	for i := range pathLen {
		nameLen := len(p.path[i].Name)
		if nameLen > MaxResourceOutputBytes-p.outputBytes-cost {
			return fmt.Errorf("%w: resource output size exceeds %d bytes", ErrResourceLimit, MaxResourceOutputBytes)
		}
		cost += nameLen
	}
	p.outputBytes += cost

	path := make([]ResourceComponent, pathLen)
	copy(path, p.path[:pathLen])

	p.records = append(p.records, ResourceRecord{
		Path:     path,
		DataRVA:  binary.LittleEndian.Uint32(raw[0:4]),
		Size:     binary.LittleEndian.Uint32(raw[4:8]),
		CodePage: binary.LittleEndian.Uint32(raw[8:12]),
		Reserved: binary.LittleEndian.Uint32(raw[12:16]),
	})
	return nil
}
