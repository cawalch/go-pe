package pe

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalPE creates a synthetically valid minimal PE32+ executable.
func buildMinimalPE(numSections int) []byte {
	// DOS Header: 64 bytes
	headerSize := (392 + numSections*40 + 511) &^ 511
	data := make([]byte, headerSize+numSections*512)
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80) // e_lfanew = 128

	// PE Signature at 128
	copy(data[0x80:], []byte{'P', 'E', 0, 0})

	// COFF File Header at 132 (20 bytes)
	coff := data[132 : 132+20]
	binary.LittleEndian.PutUint16(coff[0:], MachineAMD64)
	binary.LittleEndian.PutUint16(coff[2:], uint16(numSections))
	binary.LittleEndian.PutUint32(coff[4:], 1700000000) // Timestamp
	binary.LittleEndian.PutUint16(coff[16:], 240)       // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], CharacteristicsExecutableImage|CharacteristicsLargeAddressAware)

	// Optional Header at 152 (PE32+ is 240 bytes)
	opt := data[152 : 152+240]
	binary.LittleEndian.PutUint16(opt[0:], OptionalHeaderMagicPE32P) // Magic
	opt[2] = 14                                                      // MajorLinker
	opt[3] = 0                                                       // MinorLinker
	binary.LittleEndian.PutUint32(opt[16:], 0x1000)                  // AddressOfEntryPoint
	binary.LittleEndian.PutUint64(opt[24:], 0x140000000)             // ImageBase
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)                  // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], 0x200)                   // FileAlignment
	binary.LittleEndian.PutUint32(opt[60:], uint32(headerSize))      // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:], SubsystemWindowsGUI)     // Subsystem
	binary.LittleEndian.PutUint32(opt[108:], NumberOfDataDirectories)

	// Section Table at 152 + 240 = 392 (40 bytes per section)
	secOffset := 392
	for i := 0; i < numSections; i++ {
		sec := data[secOffset+i*40 : secOffset+(i+1)*40]
		name := ".text"
		if i == 1 {
			name = ".data"
		} else if i > 1 {
			name = ".rsrc"
		}
		copy(sec[:8], []byte(name))
		binary.LittleEndian.PutUint32(sec[8:], 0x1000)                                           // VirtualSize
		binary.LittleEndian.PutUint32(sec[12:], uint32(0x1000*(i+1)))                            // VirtualAddress
		binary.LittleEndian.PutUint32(sec[16:], 0x200)                                           // SizeOfRawData
		binary.LittleEndian.PutUint32(sec[20:], uint32(headerSize+512*i))                        // PointerToRawData
		binary.LittleEndian.PutUint32(sec[36:], SectionMemExecute|SectionMemRead|SectionCntCode) // Characteristics
	}

	return data
}

func TestValidPEParsing(t *testing.T) {
	data := buildMinimalPE(2)
	peFile, err := New(data)
	if err != nil {
		t.Fatalf("failed to parse valid PE: %v", err)
	}

	if !peFile.Is64Bit() {
		t.Error("expected 64-bit PE")
	}
	if peFile.Is32Bit() {
		t.Error("expected not 32-bit PE")
	}
	if peFile.IsDLL() {
		t.Error("expected executable, not DLL")
	}
	if peFile.NumberOfSections() != 2 {
		t.Fatalf("expected 2 sections, got %d", peFile.NumberOfSections())
	}
	if peFile.OptionalHeader.AddressOfEntryPoint != 0x1000 {
		t.Errorf("expected entry point 0x1000, got 0x%x", peFile.OptionalHeader.AddressOfEntryPoint)
	}
	if peFile.OptionalHeader.ImageBase != 0x140000000 {
		t.Errorf("expected image base 0x140000000, got 0x%x", peFile.OptionalHeader.ImageBase)
	}

	text := peFile.SectionByName(".text")
	if text == nil {
		t.Fatal("section .text not found")
	}
	if text.VirtualAddress != 0x1000 {
		t.Errorf("expected .text VA 0x1000, got 0x%x", text.VirtualAddress)
	}

	// Test RVA to Offset translation
	offset, ok := peFile.RVAToOffset(0x1050)
	if !ok || offset != 0x250 {
		t.Errorf("RVAToOffset(0x1050) = (0x%x, %v), want (0x250, true)", offset, ok)
	}
}

func TestOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(path, buildMinimalPE(2), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil || f == nil || f.NumberOfSections() != 2 {
		t.Fatalf("Open = (%v, %v)", f, err)
	}
	if _, err := Open(path + ".missing"); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestNonPEInput(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("hello world"),
		[]byte("MZ"),
		make([]byte, 63),
	}

	for _, tc := range cases {
		_, err := New(tc)
		if err == nil {
			t.Errorf("expected error for non-PE data of length %d, got nil", len(tc))
		}
	}
}
