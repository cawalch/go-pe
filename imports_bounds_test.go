package pe

import (
	"encoding/binary"
	"errors"
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
