package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestExportsBounds(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		for _, tc := range []struct {
			name   string
			change func([]byte)
			want   error
		}{
			{"directory_rva", func(d []byte) { binary.LittleEndian.PutUint32(d[exportDirectoryOffset(is64):], 0) }, ErrInvalidExport},
			{"directory_size", func(d []byte) { binary.LittleEndian.PutUint32(d[exportDirectoryOffset(is64)+4:], 39) }, ErrInvalidExport},
			{"directory_wrap", func(d []byte) { binary.LittleEndian.PutUint32(d[exportDirectoryOffset(is64)+4:], math.MaxUint32) }, ErrIntegerOverflow},
			{"ordinal_wrap", func(d []byte) { binary.LittleEndian.PutUint32(d[528:], math.MaxUint32) }, ErrIntegerOverflow},
			{"function_limit", func(d []byte) { binary.LittleEndian.PutUint32(d[532:], MaxExportSymbols+1) }, ErrExportLimit},
			{"name_limit", func(d []byte) { binary.LittleEndian.PutUint32(d[536:], MaxExportNames+1) }, ErrExportLimit},
			{"ordinal_index", func(d []byte) { binary.LittleEndian.PutUint16(d[exportTableOffset(d, 36):], 2) }, ErrInvalidExport},
			{"names_without_addresses", func(d []byte) { binary.LittleEndian.PutUint32(d[532:], 0) }, ErrInvalidExport},
			{"zero_name_pointer", func(d []byte) { binary.LittleEndian.PutUint32(d[exportTableOffset(d, 32):], 0) }, ErrInvalidExport},
			{"unmapped_name", func(d []byte) { binary.LittleEndian.PutUint32(d[exportTableOffset(d, 32):], 0xffffffff) }, ErrOutOfBounds},
			{"unmapped_dll", func(d []byte) { binary.LittleEndian.PutUint32(d[524:], 0xffffffff) }, ErrOutOfBounds},
			{"dll_past_file", func(d []byte) { binary.LittleEndian.PutUint32(d[524:], exportRVA(len(d))) }, ErrOutOfBounds},
			{"dll_file_bound", func(d []byte) {
				binary.LittleEndian.PutUint32(d[524:], exportRVA(len(d)-1))
				d[len(d)-1] = 'X'
			}, ErrUnterminatedString},
			{"dll_header_bound", func(d []byte) {
				binary.LittleEndian.PutUint32(d[524:], 511)
				d[511] = 'X' // A NUL in the next section must not terminate this name.
			}, ErrUnterminatedString},
			{"dll_section_bound", func(d []byte) {
				binary.LittleEndian.PutUint32(d[524:], exportRVA(len(d)-2))
				binary.LittleEndian.PutUint32(d[exportSectionOffset(is64)+16:], uint32(len(d)-513))
				d[len(d)-2] = 'X' // The final NUL is outside the section's raw data.
			}, ErrUnterminatedString},
			{"virtual_tail", func(d []byte) { binary.LittleEndian.PutUint32(d[exportSectionOffset(is64)+16:], 39) }, ErrOutOfBounds},
			{"forwarder_directory_bound", func(d []byte) {
				end := 512 + int(binary.LittleEndian.Uint32(d[exportDirectoryOffset(is64)+4:]))
				d[end-1] = 'X' // The next file byte is NUL, but outside the directory.
				binary.LittleEndian.PutUint32(d[552:], exportRVA(end-1))
			}, ErrUnterminatedString},
		} {
			t.Run(fmt.Sprintf("%s/PE64=%t", tc.name, is64), func(t *testing.T) {
				d := testfixture.Exports(is64, 2)
				tc.change(d)
				got, err := parseTestExports(t, d)
				if got != nil || !errors.Is(err, tc.want) {
					t.Fatalf("got %+v, %v; want %v", got, err, tc.want)
				}
			})
		}
		for _, field := range []int{28, 32, 36} {
			for _, rva := range []uint32{0, 0xffffffff, exportRVA(1022)} {
				d := testfixture.Exports(is64, 2)
				binary.LittleEndian.PutUint32(d[512+field:], rva)
				if got, err := parseTestExports(t, d); err == nil || got != nil {
					t.Fatalf("field %d rva %#x: %+v %v", field, rva, got, err)
				}
			}
		}
	}
}

func TestExportsTruncation(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Exports(is64, 3)
		pointers := exportTableOffset(data, 32)
		lastName := exportOffset(binary.LittleEndian.Uint32(data[pointers+8:]))
		needed := lastName + len("Function00002") + 1
		f, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		for end := 0; end <= len(data); end++ {
			got, err := f.Exports(data[:end])
			if (err == nil) != (end >= needed) || err != nil && got != nil {
				t.Fatalf("64=%t cut=%d: %+v %v", is64, end, got, err)
			}
		}
		// Supplying bytes later cannot extend the original File's input bounds.
		short, err := New(data[:needed-1])
		if err != nil {
			t.Fatal(err)
		}
		if got, err := short.Exports(data); got != nil || err == nil {
			t.Fatal("accepted bytes past original file")
		}
	}
}

func TestExportsMappingAndTargets(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		d := testfixture.Exports(is64, 2)
		// A table in headers and names outside the directory's declared span.
		copy(d[0x1e0:0x1e8], d[552:560])
		binary.LittleEndian.PutUint32(d[540:], 0x1e0)
		binary.LittleEndian.PutUint32(d[exportDirectoryOffset(is64)+4:], 40)
		// Preserve virtual or unmapped targets; they aren't parser read addresses.
		binary.LittleEndian.PutUint32(d[0x1e0:], 0xffffffff)
		got, err := parseTestExports(t, d)
		if err != nil || got.Symbols[0].RVA != 0xffffffff || got.Symbols[0].Forwarded {
			t.Fatalf("mapped tables: %+v %v", got, err)
		}
		// A table cannot cross the headers boundary even if file bytes follow it.
		binary.LittleEndian.PutUint32(d[540:], 0x1fc)
		if got, err := parseTestExports(t, d); got != nil || !errors.Is(err, ErrOutOfBounds) {
			t.Fatalf("header bound: %+v %v", got, err)
		}
	}
}

func TestExportsRVAEnd(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		d := testfixture.Exports(is64, 2)
		const start = uint32(0xfffffe00)
		pointers := exportTableOffset(d, 32)
		for _, off := range []int{524, 540, 544, 548, pointers, pointers + 4} {
			binary.LittleEndian.PutUint32(d[off:], binary.LittleEndian.Uint32(d[off:])-0x1000+start)
		}
		binary.LittleEndian.PutUint32(d[exportSectionOffset(is64)+12:], start)
		binary.LittleEndian.PutUint32(d[exportDirectoryOffset(is64):], start)
		binary.LittleEndian.PutUint32(d[exportDirectoryOffset(is64)+4:], 512)
		binary.LittleEndian.PutUint32(d[552:], 0xffffffff)
		got, err := parseTestExports(t, d)
		if err != nil || !got.Symbols[0].Forwarded || got.Symbols[0].Forwarder != "" {
			t.Fatalf("final RVA byte: %+v %v", got, err)
		}
		dllRVA := binary.LittleEndian.Uint32(d[524:])
		binary.LittleEndian.PutUint32(d[524:], math.MaxUint32)
		got, err = parseTestExports(t, d)
		if err != nil || got.DLLNameRVA != math.MaxUint32 || got.DLL != "" {
			t.Fatalf("DLL name at final RVA byte: %+v %v", got, err)
		}
		binary.LittleEndian.PutUint32(d[524:], dllRVA)
		d[1023] = 'X'
		if got, err := parseTestExports(t, d); got != nil || !errors.Is(err, ErrUnterminatedString) {
			t.Fatalf("unterminated final RVA: %+v %v", got, err)
		}
		binary.LittleEndian.PutUint32(d[540:], 0xfffffffe)
		if got, err := parseTestExports(t, d); got != nil || !errors.Is(err, ErrOutOfBounds) {
			t.Fatalf("table crosses RVA end: %+v %v", got, err)
		}
	}
}

func TestExportsLimits(t *testing.T) {
	single := testfixture.Exports(true, 1)
	binary.LittleEndian.PutUint32(single[528:], math.MaxUint32)
	if got, err := parseTestExports(t, single); err != nil || got.Symbols[0].Ordinal != math.MaxUint32 {
		t.Fatalf("maximum ordinal: %+v %v", got, err)
	}
	data := testfixture.Exports(true, MaxExportSymbols)
	got, err := parseTestExports(t, data)
	if err != nil || len(got.Symbols) != MaxExportSymbols || got.Symbols[65535].Ordinal != 65542 {
		t.Fatalf("maximum tables: %v", err)
	}
	// All 65,536 names may alias one address slot; names aren't deduplicated.
	binary.LittleEndian.PutUint32(data[532:], 1)
	start := exportTableOffset(data, 36)
	clear(data[start : start+MaxExportNames*2])
	got, err = parseTestExports(t, data)
	if err != nil || len(got.Symbols) != 1 || len(got.Symbols[0].Names) != MaxExportNames {
		t.Fatalf("maximum aliases: %v", err)
	}
	for _, count := range []int{256, 257} {
		data := testfixture.Exports(true, count)
		// Shared pointers still consume the string budget on every reference.
		pos := len(data)
		data = append(data, []byte(strings.Repeat("N", MaxExportNameBytes-1)+"\x00")...)
		section := exportSectionOffset(true)
		binary.LittleEndian.PutUint32(data[section+8:], uint32(len(data)-512))
		binary.LittleEndian.PutUint32(data[section+16:], uint32(len(data)-512))
		dll := binary.LittleEndian.Uint32(data[524:])
		binary.LittleEndian.PutUint32(data[524:], 0)
		pointers := exportTableOffset(data, 32)
		for i := range count {
			binary.LittleEndian.PutUint32(data[pointers+i*4:], exportRVA(pos))
		}
		got, err := parseTestExports(t, data)
		if count == 256 {
			if err != nil || len(got.Symbols) != count {
				t.Fatalf("exact byte budget: %v", err)
			}
			binary.LittleEndian.PutUint32(data[524:], dll)
			if got, err := parseTestExports(t, data); got != nil || !errors.Is(err, ErrExportLimit) {
				t.Fatalf("remaining byte budget: %+v %v", got, err)
			}
			binary.LittleEndian.PutUint32(data[524:], 0)
			data[pos+MaxExportNameBytes-1] = 'N'
			if got, err := parseTestExports(t, data); got != nil || !errors.Is(err, ErrUnterminatedString) {
				t.Fatalf("name bound: %+v %v", got, err)
			}
		} else if got != nil || !errors.Is(err, ErrExportLimit) {
			t.Fatalf("byte budget: %+v %v", got, err)
		}
	}
}

func TestExportsAbsentAndInvalidFile(t *testing.T) {
	for _, f := range []*File{nil, {}, {OptionalHeader: OptionalHeader{Magic: OptionalHeaderMagicROM}}} {
		if got, err := f.Exports(nil); got != nil || !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("invalid file: %+v %v", got, err)
		}
	}
	data := testfixture.Exports(true, 1)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	f.OptionalHeader.DataDirectories[0] = DataDirectory{}
	if got, err := f.Exports(nil); got != nil || err != nil {
		t.Fatalf("absent: %+v %v", got, err)
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = f.Exports(data) }); n != 0 {
		t.Fatalf("absent directory allocated %g times", n)
	}
	f.OptionalHeader.NumberOfRvaAndSizes = 0
	f.OptionalHeader.DataDirectories[0] = DataDirectory{VirtualAddress: 0xffffffff, Size: 40}
	if got, err := f.Exports(nil); got != nil || err != nil {
		t.Fatalf("undeclared directory: %+v %v", got, err)
	}
	f.OptionalHeader.NumberOfRvaAndSizes = 1
	f.OptionalHeader.DataDirectories[0] = DataDirectory{VirtualAddress: 0x1000, Size: 40}
	f.Sections = make([]Section, MaxSections+1)
	if got, err := f.Exports(data); got != nil || !errors.Is(err, ErrSectionLimit) {
		t.Fatalf("section limit: %+v %v", got, err)
	}
}
