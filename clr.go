package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// CLIMetadataSignature is the "BSJB" magic value starting a .NET CLI metadata root.
const CLIMetadataSignature uint32 = 0x424A5342

// .NET IMAGE_COR20_HEADER flags (COMIMAGE_FLAGS_*).
const (
	CLRFlagILOnly           uint32 = 0x00000001
	CLRFlag32BitRequired    uint32 = 0x00000002
	CLRFlagILLibrary        uint32 = 0x00000004
	CLRFlagStrongNameSigned uint32 = 0x00000008
	CLRFlagNativeEntryPoint uint32 = 0x00000010
	CLRFlagTrackDebugData   uint32 = 0x00010000
	CLRFlag32BitPreferred   uint32 = 0x00020000
)

// Parser limits bounding .NET CLR metadata decoding.
const (
	MaxCLIVersionBytes = 256
	MaxCLRStreams      = 64
	clrHeaderMinSize   = 72
	cliRootMinSize     = 16
)

var (
	// ErrInvalidCLR indicates malformed or inconsistent .NET CLR header or metadata.
	ErrInvalidCLR = errors.New("invalid CLR metadata")
	// ErrCLRLimit indicates that CLR metadata parsing exceeded a parser limit.
	ErrCLRLimit = errors.New("CLR parser limit exceeded")
)

// CLRStreamHeader describes one stream entry in the .NET CLI metadata root.
type CLRStreamHeader struct {
	Offset uint32
	Size   uint32
	Name   string
}

// CLRHeader describes the IMAGE_COR20_HEADER and optional CLI metadata root
// ("BSJB") of a .NET PE image.
type CLRHeader struct {
	CB                      uint32
	MajorRuntimeVersion     uint16
	MinorRuntimeVersion     uint16
	MetaData                DataDirectory
	Flags                   uint32
	EntryPointTokenOrRVA    uint32
	Resources               DataDirectory
	StrongNameSignature     DataDirectory
	CodeManagerTable        DataDirectory
	VTableFixups            DataDirectory
	ExportAddressTableJumps DataDirectory
	ManagedNativeHeader     DataDirectory

	HasMetadata   bool
	MetadataMajor uint16
	MetadataMinor uint16
	VersionString string
	MetadataFlags uint16
	Streams       []CLRStreamHeader
}

// IsMixedMode reports whether the .NET assembly contains native code or a
// native entry point rather than being pure IL.
func (c *CLRHeader) IsMixedMode() bool {
	if c == nil {
		return false
	}
	return c.Flags&CLRFlagILOnly == 0 || c.Flags&CLRFlagNativeEntryPoint != 0
}

// CLR reads the .NET CLR runtime header ([DataDirectoryCLRRuntime], index 14)
// and, when present, the CLI metadata root ("BSJB") and its stream headers.
//
// A missing directory returns nil, nil. Malformed, truncated, or over-limit
// metadata returns nil and an error.
func (f *File) CLR(data []byte) (*CLRHeader, error) {
	dir, ok, err := f.dataDirectory(DataDirectoryCLRRuntime, ErrInvalidCLR)
	if err != nil || !ok {
		return nil, err
	}
	if dir.Size < clrHeaderMinSize {
		return nil, fmt.Errorf("%w: CLR header size %d smaller than %d", ErrInvalidCLR, dir.Size, clrHeaderMinSize)
	}
	span, err := f.rvaSpan(data, dir.VirtualAddress)
	if err != nil {
		return nil, fmt.Errorf("CLR header: %w", err)
	}
	if len(span) < clrHeaderMinSize {
		return nil, fmt.Errorf("CLR header: %w", ErrOutOfBounds)
	}

	cb := binary.LittleEndian.Uint32(span[0:4])
	if cb < clrHeaderMinSize {
		return nil, fmt.Errorf("%w: CLR header cb %d smaller than %d", ErrInvalidCLR, cb, clrHeaderMinSize)
	}

	out := &CLRHeader{
		CB:                      cb,
		MajorRuntimeVersion:     binary.LittleEndian.Uint16(span[4:6]),
		MinorRuntimeVersion:     binary.LittleEndian.Uint16(span[6:8]),
		MetaData:                readDataDir(span[8:16]),
		Flags:                   binary.LittleEndian.Uint32(span[16:20]),
		EntryPointTokenOrRVA:    binary.LittleEndian.Uint32(span[20:24]),
		Resources:               readDataDir(span[24:32]),
		StrongNameSignature:     readDataDir(span[32:40]),
		CodeManagerTable:        readDataDir(span[40:48]),
		VTableFixups:            readDataDir(span[48:56]),
		ExportAddressTableJumps: readDataDir(span[56:64]),
		ManagedNativeHeader:     readDataDir(span[64:72]),
	}

	if out.MetaData.VirtualAddress != 0 && out.MetaData.Size != 0 {
		if err := f.parseCLIMetadata(data, out); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func readDataDir(b []byte) DataDirectory {
	return DataDirectory{
		VirtualAddress: binary.LittleEndian.Uint32(b[0:4]),
		Size:           binary.LittleEndian.Uint32(b[4:8]),
	}
}

func (f *File) parseCLIMetadata(data []byte, out *CLRHeader) error {
	if out.MetaData.Size < cliRootMinSize {
		return fmt.Errorf("%w: CLI metadata size %d smaller than %d", ErrInvalidCLR, out.MetaData.Size, cliRootMinSize)
	}
	span, err := f.rvaSpan(data, out.MetaData.VirtualAddress)
	if err != nil {
		return fmt.Errorf("CLI metadata: %w", err)
	}
	if uint64(len(span)) < uint64(out.MetaData.Size) {
		return fmt.Errorf("CLI metadata: %w", ErrOutOfBounds)
	}
	meta := span[:out.MetaData.Size]

	sig := binary.LittleEndian.Uint32(meta[0:4])
	if sig != CLIMetadataSignature {
		return fmt.Errorf("%w: invalid CLI metadata signature %#x", ErrInvalidCLR, sig)
	}
	out.HasMetadata = true
	out.MetadataMajor = binary.LittleEndian.Uint16(meta[4:6])
	out.MetadataMinor = binary.LittleEndian.Uint16(meta[6:8])
	// meta[8:12] is reserved.
	verLen := binary.LittleEndian.Uint32(meta[12:16])
	if verLen > MaxCLIVersionBytes {
		return fmt.Errorf("%w: CLI version string length %d exceeds %d", ErrCLRLimit, verLen, MaxCLIVersionBytes)
	}
	paddedVerLen := (uint64(verLen) + 3) &^ 3
	if uint64(16)+paddedVerLen+4 > uint64(len(meta)) {
		return fmt.Errorf("%w: truncated CLI metadata header", ErrInvalidCLR)
	}
	verBytes := meta[16 : 16+verLen]
	if before, _, ok := bytes.Cut(verBytes, []byte{0}); ok {
		verBytes = before
	}
	out.VersionString = string(verBytes)

	pos := int(16 + paddedVerLen)
	out.MetadataFlags = binary.LittleEndian.Uint16(meta[pos : pos+2])
	streamCount := binary.LittleEndian.Uint16(meta[pos+2 : pos+4])
	if int(streamCount) > MaxCLRStreams {
		return fmt.Errorf("%w: CLI stream count %d exceeds %d", ErrCLRLimit, streamCount, MaxCLRStreams)
	}
	pos += 4

	out.Streams = make([]CLRStreamHeader, 0, streamCount)
	for range streamCount {
		if pos+8 > len(meta) {
			return fmt.Errorf("%w: truncated CLI stream header", ErrInvalidCLR)
		}
		sOff := binary.LittleEndian.Uint32(meta[pos : pos+4])
		sSize := binary.LittleEndian.Uint32(meta[pos+4 : pos+8])
		pos += 8

		nulIdx := bytes.IndexByte(meta[pos:], 0)
		if nulIdx < 0 {
			return fmt.Errorf("%w: unterminated CLI stream name", ErrInvalidCLR)
		}
		name := string(meta[pos : pos+nulIdx])
		nameBytes := nulIdx + 1
		paddedNameBytes := (nameBytes + 3) &^ 3
		if pos+paddedNameBytes > len(meta) {
			return fmt.Errorf("%w: truncated CLI stream name padding", ErrInvalidCLR)
		}
		pos += paddedNameBytes
		out.Streams = append(out.Streams, CLRStreamHeader{
			Offset: sOff,
			Size:   sSize,
			Name:   name,
		})
	}
	return nil
}
