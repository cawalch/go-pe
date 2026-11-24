package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestCLRHeaderAndMetadata(t *testing.T) {
	minData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(minData)
	if err != nil {
		t.Fatal(err)
	}
	if clr, err := fMin.CLR(minData); err != nil || clr != nil {
		t.Fatalf("missing CLR = (%+v, %v), want (nil, nil)", clr, err)
	}

	data := testfixture.Minimal(true, 1)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	secOff := int(f.Sections[0].PointerToRawData)
	secRVA := f.Sections[0].VirtualAddress
	dirOff := 152 + 112 + pe.DataDirectoryCLRRuntime*8

	metaRVA := secRVA + 128
	metaOff := secOff + 128
	verStr := "v4.0.30319\x00\x00"
	stream1 := "#~\x00\x00"
	stream2 := "#Strings\x00\x00\x00\x00"
	metaSize := 16 + len(verStr) + 4 + 8 + len(stream1) + 8 + len(stream2)

	binary.LittleEndian.PutUint32(data[dirOff:], secRVA)
	binary.LittleEndian.PutUint32(data[dirOff+4:], 72)

	binary.LittleEndian.PutUint32(data[secOff:], 72)
	binary.LittleEndian.PutUint16(data[secOff+4:], 2)
	binary.LittleEndian.PutUint16(data[secOff+6:], 5)
	binary.LittleEndian.PutUint32(data[secOff+8:], metaRVA)
	binary.LittleEndian.PutUint32(data[secOff+12:], uint32(metaSize))
	binary.LittleEndian.PutUint32(data[secOff+16:], pe.CLRFlagILOnly)
	binary.LittleEndian.PutUint32(data[secOff+20:], 0x06000001)

	binary.LittleEndian.PutUint32(data[metaOff:], 0x424A5342) // "BSJB"
	binary.LittleEndian.PutUint16(data[metaOff+4:], 1)
	binary.LittleEndian.PutUint16(data[metaOff+6:], 1)
	binary.LittleEndian.PutUint32(data[metaOff+12:], uint32(len(verStr)))
	copy(data[metaOff+16:], verStr)
	pos := metaOff + 16 + len(verStr)
	binary.LittleEndian.PutUint16(data[pos:], 0)
	binary.LittleEndian.PutUint16(data[pos+2:], 2)
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], 100)
	binary.LittleEndian.PutUint32(data[pos+4:], 200)
	copy(data[pos+8:], stream1)
	pos += 8 + len(stream1)
	binary.LittleEndian.PutUint32(data[pos:], 300)
	binary.LittleEndian.PutUint32(data[pos+4:], 400)
	copy(data[pos+8:], stream2)

	fCLR, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	clr, err := fCLR.CLR(data)
	if err != nil {
		t.Fatal(err)
	}
	if !clr.HasMetadata || clr.VersionString != "v4.0.30319" || clr.Flags&pe.CLRFlagILOnly == 0 {
		t.Fatalf("unexpected CLR: %+v", clr)
	}
	if len(clr.Streams) != 2 || clr.Streams[0].Name != "#~" || clr.Streams[1].Name != "#Strings" {
		t.Fatalf("unexpected CLR streams: %+v", clr.Streams)
	}

	binary.LittleEndian.PutUint32(data[metaOff:], 0x12345678)
	if _, err := fCLR.CLR(data); !errors.Is(err, pe.ErrInvalidCLR) {
		t.Fatalf("bad BSJB err = %v, want ErrInvalidCLR", err)
	}
}
