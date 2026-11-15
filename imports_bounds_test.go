package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestImportsStringBudget(t *testing.T) {
	// Repeated references consume the budget each time, even in a small input.
	for excess := range 3 {
		data := buildImportsPE(true, 1, 257)
		table := importOffset(binary.LittleEndian.Uint32(data[512:]))
		long := len(data)
		data = append(data, 0, 0)
		data = append(data, strings.Repeat("x", MaxImportNameBytes-1)...)
		data = append(data, 0)
		short := len(data)
		remaining := MaxImportStringBytes - len("lib0.dll") - 1 - 255*MaxImportNameBytes
		if excess == 2 {
			remaining++ // A name must also fit when only part of the budget remains.
		}
		data = append(data, 0, 0)
		data = append(data, strings.Repeat("y", remaining-1)...)
		data = append(data, 0)
		for i := range 255 {
			putImportThunk(data[table+i*8:], true, uint64(long-512)+0x1000)
		}
		putImportThunk(data[table+255*8:], true, uint64(short-512)+0x1000)
		if excess != 1 {
			putImportThunk(data[table+256*8:], true, 0)
		}
		binary.LittleEndian.PutUint32(data[400:], uint32(len(data)-512))
		binary.LittleEndian.PutUint32(data[408:], uint32(len(data)-512))
		got, err := parseTestImports(t, data)
		if excess != 0 {
			if got != nil || !errors.Is(err, ErrImportLimit) {
				t.Fatalf("over budget: %v", err)
			}
		} else if err != nil || len(got[0].Symbols) != 256 {
			t.Fatalf("at budget: %v", err)
		}
	}
}

func TestImportsSeparateMappings(t *testing.T) {
	data := buildImportsPE(true, 1, 1)
	data = append(data, make([]byte, 512)...)
	binary.LittleEndian.PutUint16(data[134:], 2)
	// The descriptor and lookup table are in section 0, the hint/name record is
	// in section 1, and the DLL name is in unused header bytes.
	binary.LittleEndian.PutUint32(data[432+8:], 512)
	binary.LittleEndian.PutUint32(data[432+12:], 0x2000)
	binary.LittleEndian.PutUint32(data[432+16:], 512)
	binary.LittleEndian.PutUint32(data[432+20:], 1024)
	binary.LittleEndian.PutUint32(data[524:], 480)
	copy(data[480:], "Mixed.DLL\x00")
	table := importOffset(binary.LittleEndian.Uint32(data[512:]))
	putImportThunk(data[table:], true, 0x2001) // Unaligned records are valid.
	binary.LittleEndian.PutUint16(data[1025:], 7)
	copy(data[1027:], "Function\xff\x00")
	got, err := parseTestImports(t, data)
	want := []ImportLibrary{{DLL: "Mixed.DLL", Symbols: []ImportSymbol{{Name: "Function\xff", Hint: 7}}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestImportsMappingBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*File, []byte)
		want   error
	}{
		{"descriptor", func(f *File, d []byte) { f.Sections[0].SizeOfRawData = 19 }, ErrOutOfBounds},
		{"lookup", func(f *File, d []byte) {
			table := importOffset(binary.LittleEndian.Uint32(d[512:]))
			// Keep the DLL in headers so it cannot fail before the table check.
			copy(d[480:], "lib.dll\x00")
			binary.LittleEndian.PutUint32(d[524:], 480)
			putImportThunk(d[table:], true, 1<<63|1)
			f.Sections[0].SizeOfRawData = uint32(table + 8 - 512)
		}, ErrInvalidImport},
		{"name", func(f *File, d []byte) {
			name := importOffset(binary.LittleEndian.Uint32(d[524:]))
			f.Sections[0].SizeOfRawData = uint32(name + len("lib0.dll") - 512)
		}, ErrUnterminatedString},
		{"header_name", func(f *File, d []byte) {
			binary.LittleEndian.PutUint32(d[524:], 511)
			d[511] = 'x' // The next byte is mapped by a different region.
		}, ErrUnterminatedString},
		{"earlier_overlap", func(f *File, d []byte) {
			name := binary.LittleEndian.Uint32(d[524:])
			f.Sections = append([]Section{{SectionHeader: SectionHeader{VirtualAddress: name + 1, VirtualSize: 1}}}, f.Sections...)
		}, ErrUnterminatedString},
		{"empty_earlier_section", func(f *File, d []byte) {
			name := binary.LittleEndian.Uint32(d[524:])
			f.Sections = append([]Section{{SectionHeader: SectionHeader{VirtualAddress: name + 1}}}, f.Sections...)
		}, nil},
		{"later_overlap", func(f *File, d []byte) {
			name := binary.LittleEndian.Uint32(d[524:])
			f.Sections = append(f.Sections, Section{SectionHeader: SectionHeader{VirtualAddress: name + 1, VirtualSize: 1}})
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildImportsPE(true, 1, 1)
			f, err := New(data)
			if err != nil {
				t.Fatal(err)
			}
			tc.change(f, data)
			got, err := f.Imports(data)
			if !errors.Is(err, tc.want) || (err != nil && got != nil) {
				t.Fatalf("got %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func buildImportsRVAEnd(is64 bool, remaining int) []byte {
	section, directory := 376, 256
	if is64 {
		section, directory = 392, 272
	}
	data := append(buildImportsPE(is64, 1, 0), make([]byte, 512)...)
	// Raw bytes extend past the 32-bit RVA space. A zero lookup
	// entry may end at 2^32, but must not read across that boundary.
	binary.LittleEndian.PutUint32(data[section+8:], 1024)
	binary.LittleEndian.PutUint32(data[section+12:], math.MaxUint32-511)
	binary.LittleEndian.PutUint32(data[section+16:], 1024)
	binary.LittleEndian.PutUint32(data[directory:], math.MaxUint32-511)
	lookup := uint32(uint64(1)<<32 - uint64(remaining))
	binary.LittleEndian.PutUint32(data[512:], lookup)
	binary.LittleEndian.PutUint32(data[528:], lookup)
	binary.LittleEndian.PutUint32(data[524:], 480)
	copy(data[480:], "end.dll\x00")
	return data
}

func TestImportsRVAEnd(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		width := 4
		if is64 {
			width = 8
		}
		for _, remaining := range []int{width - 1, width} {
			t.Run(fmt.Sprintf("64=%t/remaining=%d", is64, remaining), func(t *testing.T) {
				data := buildImportsRVAEnd(is64, remaining)
				got, err := parseTestImports(t, data)
				if remaining < width {
					if got != nil || !errors.Is(err, ErrInvalidImport) {
						t.Fatalf("lookup crosses RVA boundary: %+v, %v", got, err)
					}
				} else if err != nil || len(got) != 1 || len(got[0].Symbols) != 0 {
					t.Fatalf("lookup ends at RVA boundary: %+v, %v", got, err)
				}
			})
		}
	}
}

func TestImportsOriginalAndSuppliedBounds(t *testing.T) {
	data := buildImportsPE(true, 1, 1)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{0, 512, 531} {
		if got, err := f.Imports(data[:length]); got != nil || !errors.Is(err, ErrOutOfBounds) {
			t.Fatalf("length %d: %v", length, err)
		}
	}
	// Larger replacement data must not make bytes outside the original file readable.
	binary.LittleEndian.PutUint32(data[524:], 0x1200)
	data = append(data, []byte("outside.dll\x00")...)
	f.Sections[0].SizeOfRawData = 1024
	if got, err := f.Imports(data); got != nil || !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("past original file: %v", err)
	}
}

func TestImportsIndependentCalls(t *testing.T) {
	data := buildImportsPE(true, 2, 2)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	want, err := f.Imports(data)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, err := f.Imports(data)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("concurrent parse: %v", err)
				return
			}
			got[0].DLL = "changed"
			got[0].Symbols[0].Name = "changed"
		})
	}
	wg.Wait()
	// A failure in the second library must discard the first library's results.
	binary.LittleEndian.PutUint32(data[544:], 0)
	if got, err := f.Imports(data); got != nil || !errors.Is(err, ErrInvalidImport) {
		t.Fatalf("partial result: %+v, %v", got, err)
	}
}

func TestImportsTruncationAndPE32Limits(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := buildImportsPE(is64, 1, 2)
		table := importOffset(binary.LittleEndian.Uint32(data[512:]))
		lastRVA := binary.LittleEndian.Uint32(data[table+4:])
		if is64 {
			lastRVA = uint32(binary.LittleEndian.Uint64(data[table+8:]))
		}
		needed := importOffset(lastRVA) + 2 + len("Function1") + 1
		f, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		for end := 0; end <= len(data); end++ {
			got, err := f.Imports(data[:end])
			if (err == nil) != (end >= needed) || err != nil && got != nil {
				t.Fatalf("64=%t cut=%d: %+v %v", is64, end, got, err)
			}
		}
		short, err := New(data[:needed-1])
		if err != nil {
			t.Fatal(err)
		}
		if got, err := short.Imports(data); got != nil || !errors.Is(err, ErrUnterminatedString) {
			t.Fatalf("64=%t accepted bytes past original file: %+v %v", is64, got, err)
		}
	}

	// Verify cumulative limits and overflow bounds on PE32 as well as PE32+.
	for _, tc := range []struct {
		name               string
		libraries, symbols int
		fail               bool
	}{
		{"libraries_at", MaxImportLibraries, 0, false},
		{"libraries_over", MaxImportLibraries + 1, 0, true},
		{"symbols_at", 1, MaxImportSymbols, false},
		{"symbols_over", 1, MaxImportSymbols + 1, true},
	} {
		t.Run("PE32/"+tc.name, func(t *testing.T) {
			got, err := parseTestImports(t, buildImportsPE(false, tc.libraries, tc.symbols))
			if tc.fail {
				if got != nil || !errors.Is(err, ErrImportLimit) {
					t.Fatalf("got %d libraries, %v", len(got), err)
				}
			} else if err != nil || len(got) != tc.libraries {
				t.Fatalf("got %d libraries, %v", len(got), err)
			}
		})
	}
}

func TestImportsMaxSectionsAndEmptyDescriptors(t *testing.T) {
	data := buildImportsPE(true, MaxImportLibraries, 0)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	// Expand sections up to MaxSections so rvaSpan exercises the full section table.
	base := f.Sections[0]
	f.Sections = make([]Section, MaxSections)
	for i := range f.Sections {
		f.Sections[i] = base
		if i < MaxSections-1 {
			f.Sections[i].VirtualAddress = uint32(0x10000000 + i*0x1000)
			f.Sections[i].VirtualSize = 0x1000
			f.Sections[i].SizeOfRawData = 0
			f.Sections[i].PointerToRawData = 0
		}
	}
	got, err := f.Imports(data)
	if err != nil || len(got) != MaxImportLibraries {
		t.Fatalf("MaxSections + MaxImportLibraries = (%d, %v)", len(got), err)
	}
}
