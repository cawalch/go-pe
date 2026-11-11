package pe

import (
	"math"
	"testing"
)

func FuzzNew(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("MZ"), buildPE32(), buildMinimalPE(0), buildMinimalPE(2), longNamePE(".long_section")} {
		f.Add(data, uint32(0x1000))
	}
	f.Fuzz(func(t *testing.T, data []byte, address uint32) {
		parsed, err := New(data)
		if err != nil {
			if parsed != nil {
				t.Fatal("partial File returned with error")
			}
			return
		}
		if len(parsed.Sections) != int(parsed.FileHeader.NumberOfSections) || len(parsed.Sections) > MaxSections {
			t.Fatal("incomplete or unbounded section table")
		}
		if !parsed.Is32Bit() && !parsed.Is64Bit() {
			t.Fatal("accepted unsupported image")
		}
		for _, rva := range []uint32{0, address, math.MaxUint32, parsed.OptionalHeader.AddressOfEntryPoint} {
			if offset, ok := parsed.RVAToOffset(rva); ok && uint64(offset) >= uint64(len(data)) {
				t.Fatal("RVA mapped beyond input")
			}
			parsed.OffsetToRVA(rva)
		}
		for _, section := range parsed.Sections {
			if offset, ok := parsed.RVAToOffset(section.VirtualAddress); ok && uint64(offset) >= uint64(len(data)) {
				t.Fatal("section mapped beyond input")
			}
			parsed.SectionByName(section.Name)
		}
	})
}

func FuzzSafeReader(f *testing.F) {
	f.Add([]byte("abc\x00"), int64(0), int64(4))
	f.Add([]byte{0}, int64(math.MaxInt64), int64(1))
	f.Add([]byte{}, int64(-1), int64(-1))
	f.Fuzz(func(t *testing.T, data []byte, offset, length int64) {
		r := NewSafeReader(data)
		valid := offset >= 0 && length >= 0 && uint64(offset) <= uint64(len(data)) && uint64(length) <= uint64(len(data))-uint64(offset)
		b, err := r.Slice(offset, length)
		if (err == nil) != valid || r.CheckBounds(offset, length) != valid {
			t.Fatal("bounds decision disagrees with independent subtraction check")
		}
		if err == nil && int64(len(b)) != length {
			t.Fatal("wrong slice length")
		}
		r.ReadUint8(offset)
		r.ReadUint16(offset)
		r.ReadUint32(offset)
		r.ReadUint64(offset)
		r.ReadASCIIZ(offset, length)
	})
}
