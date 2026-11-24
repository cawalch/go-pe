package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestBaseRelocs(t *testing.T) {
	minData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(minData)
	if err != nil {
		t.Fatal(err)
	}
	if br, err := fMin.BaseRelocs(minData); err != nil || br != nil {
		t.Fatalf("missing BaseRelocs = (%+v, %v), want (nil, nil)", br, err)
	}

	data := testfixture.Minimal(true, 1)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	secOff := int(f.Sections[0].PointerToRawData)
	secRVA := f.Sections[0].VirtualAddress
	dirOff := 152 + 112 + pe.DataDirectoryBaseReloc*8

	// Block of 16 bytes: 8-byte header + 4 entries (3 DIR64 + 1 ABSOLUTE padding).
	binary.LittleEndian.PutUint32(data[dirOff:], secRVA)
	binary.LittleEndian.PutUint32(data[dirOff+4:], 16)
	binary.LittleEndian.PutUint32(data[secOff:], 0x1000)
	binary.LittleEndian.PutUint32(data[secOff+4:], 16)
	binary.LittleEndian.PutUint16(data[secOff+8:], (pe.RelocBasedDir64<<12)|0x10)
	binary.LittleEndian.PutUint16(data[secOff+10:], (pe.RelocBasedDir64<<12)|0x20)
	binary.LittleEndian.PutUint16(data[secOff+12:], (pe.RelocBasedDir64<<12)|0x30)
	binary.LittleEndian.PutUint16(data[secOff+14:], pe.RelocBasedAbsolute<<12)

	fBR, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	br, err := fBR.BaseRelocs(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(br.Blocks) != 1 || br.TotalEntries != 4 || br.ActiveEntries != 3 {
		t.Fatalf("unexpected BaseRelocs: %+v", br)
	}

	// HIGHADJ consumes the following 16-bit parameter word and should count as 1 active entry.
	binary.LittleEndian.PutUint16(data[secOff+8:], (pe.RelocBasedHighAdj<<12)|0x10)
	binary.LittleEndian.PutUint16(data[secOff+10:], 0x1234) // parameter word
	binary.LittleEndian.PutUint16(data[secOff+12:], (pe.RelocBasedDir64<<12)|0x30)
	binary.LittleEndian.PutUint16(data[secOff+14:], pe.RelocBasedAbsolute<<12)
	brAdj, err := fBR.BaseRelocs(data)
	if err != nil {
		t.Fatal(err)
	}
	if brAdj.ActiveEntries != 2 {
		t.Fatalf("HIGHADJ ActiveEntries = %d, want 2", brAdj.ActiveEntries)
	}

	// Truncated block returns ErrInvalidBaseReloc.
	binary.LittleEndian.PutUint32(data[dirOff+4:], 12)
	fBad, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fBad.BaseRelocs(data); !errors.Is(err, pe.ErrInvalidBaseReloc) {
		t.Fatalf("truncated BaseRelocs err = %v, want ErrInvalidBaseReloc", err)
	}
}
