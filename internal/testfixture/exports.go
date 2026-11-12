// Package testfixture builds synthetic PE metadata for tests and benchmarks.
package testfixture

import (
	"encoding/binary"
	"fmt"
)

// Exports builds a single-section image with named exports and distinct target
// RVAs outside the export directory. The directory starts at offset 512 (RVA
// 0x1000); the address table follows its 40-byte header. Strings have 16-byte
// slots, followed by 32 spare bytes for a forwarder. Targets aren't file reads.
func Exports(is64 bool, symbols int) []byte {
	pointers := 552 + symbols*4
	ordinals := pointers + symbols*4
	dll := ordinals + symbols*2
	names := dll + 16
	end := names + symbols*16 + 32
	data := make([]byte, (end+511)&^511)
	put16 := func(off int, value uint16) { binary.LittleEndian.PutUint16(data[off:], value) }
	put32 := func(off int, value uint32) { binary.LittleEndian.PutUint32(data[off:], value) }
	rva := func(off int) uint32 { return uint32(off-512) + 0x1000 }
	put16(0, 0x5a4d)
	put32(0x3c, 0x80)
	put32(0x80, 0x4550)
	put16(0x86, 1)
	put16(0x96, 0x2022)
	optional, directory, section := 0x98, 0xf8, 0x178
	put16(0x84, 0x14c)
	put16(0x94, 224)
	put16(optional, 0x10b)
	put32(optional+92, 16)
	if is64 {
		put16(0x84, 0x8664)
		put16(0x94, 240)
		put16(optional, 0x20b)
		put32(optional+92, 0)
		put32(optional+108, 16)
		directory, section = 0x108, 0x188
	}
	put32(optional+32, 0x1000)
	put32(optional+36, 512)
	put32(optional+56, (uint32(len(data))+0x1fff)&^0xfff)
	put32(optional+60, 512)
	put16(optional+68, 3)
	put32(directory, 0x1000)
	put32(directory+4, uint32(end-512))
	copy(data[section:], ".edata")
	put32(section+8, uint32(len(data)-512))
	put32(section+12, 0x1000)
	put32(section+16, uint32(len(data)-512))
	put32(section+20, 512)
	put32(section+36, 0x40000040)
	put32(512+4, 0x12345678)
	put16(512+8, 2)
	put16(512+10, 3)
	put32(512+12, rva(dll))
	put32(512+16, 7)
	put32(512+20, uint32(symbols))
	put32(512+24, uint32(symbols))
	put32(512+28, rva(552))
	put32(512+32, rva(pointers))
	put32(512+36, rva(ordinals))
	copy(data[dll:], "example.dll")
	for i := range symbols {
		put32(552+i*4, 0x10000000+uint32(i)*4)
		put32(pointers+i*4, rva(names+i*16))
		put16(ordinals+i*2, uint16(i))
		copy(data[names+i*16:], fmt.Sprintf("Function%05d", i))
	}
	return data
}
