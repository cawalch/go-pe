package testfixture

import (
	"encoding/binary"
	"fmt"
)

// Minimal builds a PE32 or PE32+ image with zeroed section payloads.
func Minimal(is64 bool, sections int) []byte {
	optSize, dirOff, dirCountOff := 224, 248, 244
	machine := uint16(0x014c)
	optMagic := uint16(0x10b)
	if is64 {
		optSize, dirOff, dirCountOff = 240, 264, 260
		machine = 0x8664
		optMagic = 0x20b
	}
	headerSize := (152 + optSize + sections*40 + 511) &^ 511
	data := make([]byte, headerSize+sections*512)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], []byte{'P', 'E', 0, 0})

	coff := data[132 : 132+20]
	binary.LittleEndian.PutUint16(coff[0:], machine)
	binary.LittleEndian.PutUint16(coff[2:], uint16(sections))
	binary.LittleEndian.PutUint32(coff[4:], 1700000000)
	binary.LittleEndian.PutUint16(coff[16:], uint16(optSize))
	binary.LittleEndian.PutUint16(coff[18:], 0x0022)

	opt := data[152 : 152+optSize]
	binary.LittleEndian.PutUint16(opt[0:], optMagic)
	opt[2] = 14
	binary.LittleEndian.PutUint32(opt[16:], 0x1000)
	if is64 {
		binary.LittleEndian.PutUint64(opt[24:], 0x140000000)
	} else {
		binary.LittleEndian.PutUint32(opt[24:], 0x2000)
		binary.LittleEndian.PutUint32(opt[28:], 0x400000)
	}
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], uint32((sections+1)*0x1000))
	binary.LittleEndian.PutUint32(opt[60:], uint32(headerSize))
	binary.LittleEndian.PutUint16(opt[68:], 3)
	binary.LittleEndian.PutUint32(data[dirCountOff:], 16)
	_ = dirOff

	secOffset := 152 + optSize
	for i := range sections {
		sec := data[secOffset+i*40 : secOffset+(i+1)*40]
		name := ".text"
		if i == 1 {
			name = ".data"
		} else if i > 1 {
			name = ".rsrc"
		}
		copy(sec[:8], name)
		binary.LittleEndian.PutUint32(sec[8:], 0x1000)
		binary.LittleEndian.PutUint32(sec[12:], uint32(0x1000*(i+1)))
		binary.LittleEndian.PutUint32(sec[16:], 0x200)
		binary.LittleEndian.PutUint32(sec[20:], uint32(headerSize+512*i))
		binary.LittleEndian.PutUint32(sec[36:], 0x60000020)
	}
	return data
}

// Imports builds a single-section image with standard import descriptors in .idata.
// Symbol names are shared across libraries so callers can scale library and
// symbol counts independently.
func Imports(is64 bool, libraries, symbols int) []byte {
	data := Minimal(is64, 1)
	section, directory, width := 376, 256, 4
	if is64 {
		section, directory, width = 392, 272, 8
	}
	thunks := (512 + (libraries+1)*20 + 7) &^ 7
	dlls := thunks + libraries*(symbols+1)*width
	names := dlls + libraries*16
	size := (names + symbols*16 + 511) &^ 511
	data = append(data[:512], make([]byte, size-512)...)
	copy(data[section:section+8], ".idata\x00\x00")
	binary.LittleEndian.PutUint32(data[section+8:], uint32(size-512))
	binary.LittleEndian.PutUint32(data[section+16:], uint32(size-512))
	binary.LittleEndian.PutUint32(data[directory:], 0x1000)
	binary.LittleEndian.PutUint32(data[directory+4:], uint32((libraries+1)*20))
	for i := range libraries {
		desc := data[512+i*20:]
		rva := uint32(thunks+i*(symbols+1)*width-512) + 0x1000
		binary.LittleEndian.PutUint32(desc, rva)
		binary.LittleEndian.PutUint32(desc[12:], uint32(dlls+i*16-512)+0x1000)
		binary.LittleEndian.PutUint32(desc[16:], rva)
		copy(data[dlls+i*16:], fmt.Sprintf("lib%d.dll", i))
		for j := range symbols {
			PutImportThunk(data[thunks+(i*(symbols+1)+j)*width:], is64, uint64(names+j*16-512)+0x1000)
		}
	}
	for j := range symbols {
		binary.LittleEndian.PutUint16(data[names+j*16:], uint16(j))
		copy(data[names+j*16+2:], fmt.Sprintf("Function%d", j))
	}
	return data
}

// PutImportThunk encodes one ILT/IAT slot for PE32 or PE32+.
func PutImportThunk(data []byte, is64 bool, value uint64) {
	if is64 {
		binary.LittleEndian.PutUint64(data, value)
	} else {
		binary.LittleEndian.PutUint32(data, uint32(value))
	}
}
