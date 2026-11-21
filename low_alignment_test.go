package pe_test

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/cawalch/go-pe"
)

// buildLowAlignmentPE builds a Corkami-style low-alignment PE32 or PE32+ image
// with FileAlignment == SectionAlignment == 4, containing an import directory
// (1 DLL, 1 symbol) and an export directory (1 DLL, 1 symbol) packed tightly
// at 4-byte boundaries (VirtualAddress == PointerToRawData).
func buildLowAlignmentPE(is64 bool) []byte {
	const peOff = 64
	optSize := 224
	if is64 {
		optSize = 240
	}
	secOff := peOff + 24 + optSize
	hdrEnd := (secOff + 40 + 3) &^ 3 // 4-byte aligned

	// Layout inside .text (at RVA == file offset == hdrEnd):
	// +0..+40:   import descriptor (20 B) + 20 B zero terminator
	// +40..+56:  ILT (1 entry + terminator: 8 B for PE32, 16 B for PE32+)
	// +56..+68:  "k32.dll\x00" (8 B) + padding
	// +68..+80:  Hint (2 B) + "Exit\x00" (5 B) + padding -> 8 B
	// +80..+120: export directory (40 B)
	// +120..+124: EAT (4 B)
	// +124..+128: NamePtr (4 B)
	// +128..+132: OrdTable (2 B) + padding
	// +132..+140: "app.dll\x00" (8 B)
	// +140..+148: "Run\x00" (4 B)
	const secBodyLen = 148
	total := hdrEnd + secBodyLen
	buf := make([]byte, total)

	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[60:], peOff)
	copy(buf[peOff:], []byte{'P', 'E', 0, 0})

	coff := buf[peOff+4:]
	machine := uint16(pe.MachineI386)
	if is64 {
		machine = pe.MachineAMD64
	}
	binary.LittleEndian.PutUint16(coff[0:], machine)
	binary.LittleEndian.PutUint16(coff[2:], 1) // 1 section
	binary.LittleEndian.PutUint16(coff[16:], uint16(optSize))
	binary.LittleEndian.PutUint16(coff[18:], pe.CharacteristicsExecutableImage)

	opt := buf[peOff+24:]
	var ddOff int
	if is64 {
		binary.LittleEndian.PutUint16(opt[0:], pe.OptionalHeaderMagicPE32P)
		binary.LittleEndian.PutUint64(opt[24:], 0x140000000)
		binary.LittleEndian.PutUint32(opt[108:], pe.NumberOfDataDirectories)
		ddOff = 112
	} else {
		binary.LittleEndian.PutUint16(opt[0:], pe.OptionalHeaderMagicPE32)
		binary.LittleEndian.PutUint32(opt[28:], 0x400000)
		binary.LittleEndian.PutUint32(opt[92:], pe.NumberOfDataDirectories)
		ddOff = 96
	}
	binary.LittleEndian.PutUint32(opt[16:], uint32(hdrEnd)) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[32:], 4)              // SectionAlignment = 4 (low alignment)
	binary.LittleEndian.PutUint32(opt[36:], 4)              // FileAlignment = 4 (low alignment)
	binary.LittleEndian.PutUint32(opt[56:], uint32(total))  // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:], uint32(hdrEnd)) // SizeOfHeaders

	// Data directories: Export (0) and Import (1).
	binary.LittleEndian.PutUint32(opt[ddOff+0:], uint32(hdrEnd+80))
	binary.LittleEndian.PutUint32(opt[ddOff+4:], 40)
	binary.LittleEndian.PutUint32(opt[ddOff+8:], uint32(hdrEnd))
	binary.LittleEndian.PutUint32(opt[ddOff+12:], 40)

	// Section header.
	sec := buf[secOff:]
	copy(sec[:8], ".tiny")
	binary.LittleEndian.PutUint32(sec[8:], secBodyLen)
	binary.LittleEndian.PutUint32(sec[12:], uint32(hdrEnd)) // VA == PointerToRawData
	binary.LittleEndian.PutUint32(sec[16:], secBodyLen)
	binary.LittleEndian.PutUint32(sec[20:], uint32(hdrEnd))
	binary.LittleEndian.PutUint32(sec[36:], pe.SectionCntCode|pe.SectionMemExecute|pe.SectionMemRead)

	// Populate imports.
	base := uint32(hdrEnd)
	desc := buf[hdrEnd:]
	binary.LittleEndian.PutUint32(desc[0:], base+40)  // OriginalFirstThunk
	binary.LittleEndian.PutUint32(desc[12:], base+56) // Name
	binary.LittleEndian.PutUint32(desc[16:], base+40) // FirstThunk
	if is64 {
		binary.LittleEndian.PutUint64(buf[hdrEnd+40:], uint64(base+68))
	} else {
		binary.LittleEndian.PutUint32(buf[hdrEnd+40:], base+68)
	}
	copy(buf[hdrEnd+56:], "k32.dll\x00")
	binary.LittleEndian.PutUint16(buf[hdrEnd+68:], 7)
	copy(buf[hdrEnd+70:], "Exit\x00")

	// Populate exports.
	exp := buf[hdrEnd+80:]
	binary.LittleEndian.PutUint32(exp[12:], base+132) // Name ("app.dll")
	binary.LittleEndian.PutUint32(exp[16:], 1)        // OrdinalBase
	binary.LittleEndian.PutUint32(exp[20:], 1)        // NumberOfFunctions
	binary.LittleEndian.PutUint32(exp[24:], 1)        // NumberOfNames
	binary.LittleEndian.PutUint32(exp[28:], base+120) // AddressOfFunctions
	binary.LittleEndian.PutUint32(exp[32:], base+124) // AddressOfNames
	binary.LittleEndian.PutUint32(exp[36:], base+128) // AddressOfNameOrdinals
	binary.LittleEndian.PutUint32(buf[hdrEnd+120:], base)
	binary.LittleEndian.PutUint32(buf[hdrEnd+124:], base+140)
	binary.LittleEndian.PutUint16(buf[hdrEnd+128:], 0)
	copy(buf[hdrEnd+132:], "app.dll\x00")
	copy(buf[hdrEnd+140:], "Run\x00")

	return buf
}

func TestLowAlignmentPE(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := buildLowAlignmentPE(is64)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("PE64=%t New: %v", is64, err)
		}
		if f.OptionalHeader.FileAlignment != 4 || f.OptionalHeader.SectionAlignment != 4 {
			t.Fatalf("unexpected alignments: file=%d sec=%d", f.OptionalHeader.FileAlignment, f.OptionalHeader.SectionAlignment)
		}

		rva := f.Sections[0].VirtualAddress + 12
		off, ok := f.RVAToOffset(rva)
		if !ok || off != rva {
			t.Fatalf("RVAToOffset(%#x) = (%#x, %t), want (%#x, true)", rva, off, ok, rva)
		}
		roundTrip, ok := f.OffsetToRVA(off)
		if !ok || roundTrip != rva {
			t.Fatalf("OffsetToRVA(%#x) = (%#x, %t), want (%#x, true)", off, roundTrip, ok, rva)
		}

		rf, err := pe.NewFromReaderAt(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("NewFromReaderAt: %v", err)
		}

		imps, err := f.Imports(data)
		if err != nil || len(imps) != 1 || imps[0].DLL != "k32.dll" || len(imps[0].Symbols) != 1 || imps[0].Symbols[0].Name != "Exit" {
			t.Fatalf("PE64=%t Imports = (%+v, %v)", is64, imps, err)
		}
		rImps, err := rf.ImportsFromReaderAt(bytes.NewReader(data))
		if err != nil || !reflect.DeepEqual(rImps, imps) {
			t.Fatalf("PE64=%t ImportsFromReaderAt = (%+v, %v)", is64, rImps, err)
		}

		exps, err := f.Exports(data)
		if err != nil || exps == nil || exps.DLL != "app.dll" || len(exps.Symbols) != 1 || exps.Symbols[0].Names[0] != "Run" {
			t.Fatalf("PE64=%t Exports = (%+v, %v)", is64, exps, err)
		}
		rExps, err := rf.ExportsFromReaderAt(bytes.NewReader(data))
		if err != nil || !reflect.DeepEqual(rExps, exps) {
			t.Fatalf("PE64=%t ExportsFromReaderAt = (%+v, %v)", is64, rExps, err)
		}
	}
}
