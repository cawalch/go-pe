package pe

import (
	"bytes"
	stdpe "debug/pe"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
)

func buildPE32() []byte {
	data := buildMinimalPE(2)
	// PE32's fixed optional header is 16 bytes shorter than PE32+.
	copy(data[376:456], data[392:472])
	binary.LittleEndian.PutUint16(data[132:], MachineI386)
	binary.LittleEndian.PutUint16(data[148:], 224)
	opt := data[152:376]
	clear(opt)
	binary.LittleEndian.PutUint16(opt, OptionalHeaderMagicPE32)
	binary.LittleEndian.PutUint32(opt[16:], 0x1000)
	binary.LittleEndian.PutUint32(opt[20:], 0x1000)
	binary.LittleEndian.PutUint32(opt[24:], 0x2000)
	binary.LittleEndian.PutUint32(opt[28:], 0x400000)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[60:], 512)
	binary.LittleEndian.PutUint16(opt[68:], SubsystemWindowsCUI)
	binary.LittleEndian.PutUint32(opt[92:], 16)
	return data
}

func TestHeaderParity(t *testing.T) {
	for _, data := range [][]byte{buildPE32(), buildMinimalPE(2)} {
		countOffset := 260
		if binary.LittleEndian.Uint16(data[152:]) == OptionalHeaderMagicPE32 {
			countOffset = 244
		}
		// Exercise every scalar and directory field with nonzero values.
		for i := 154; i < countOffset; i++ {
			data[i] = byte(i * 7)
		}
		for i := 0; i < 16; i++ {
			binary.LittleEndian.PutUint32(data[countOffset+4+i*8:], uint32(i+1)*4096)
			binary.LittleEndian.PutUint32(data[countOffset+8+i*8:], uint32(i+1)*16)
		}
		// Nonzero DOS words catch fields that the initial parser left unpopulated.
		for i := 1; i < 30; i++ {
			binary.LittleEndian.PutUint16(data[i*2:], uint16(i*313))
		}
		f, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := binary.Append(nil, binary.LittleEndian, f.DOSHeader)
		if err != nil || !bytes.Equal(encoded, data[:64]) {
			t.Fatalf("DOS fields did not round-trip: %v", err)
		}
		oracle, err := stdpe.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer oracle.Close()
		compareHeaderFields(t, f.FileHeader, oracle.FileHeader)
		compareHeaderFields(t, f.OptionalHeader, reflect.ValueOf(oracle.OptionalHeader).Elem().Interface())
		if len(f.Sections) != len(oracle.Sections) {
			t.Fatalf("section counts differ: %d, %d", len(f.Sections), len(oracle.Sections))
		}
		for i, s := range f.Sections {
			want := oracle.Sections[i]
			if s.Name != want.Name || s.VirtualSize != want.VirtualSize || s.VirtualAddress != want.VirtualAddress ||
				s.SizeOfRawData != want.Size || s.PointerToRawData != want.Offset || s.Characteristics != want.Characteristics {
				t.Fatalf("section %d differs from debug/pe: %+v, %+v", i, s, want.SectionHeader)
			}
		}
	}
}

func compareHeaderFields(t *testing.T, got, want any) {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := 0; i < w.NumField(); i++ {
		name := w.Type().Field(i).Name
		if name == "DataDirectory" {
			for j := 0; j < w.Field(i).Len(); j++ {
				compareHeaderFields(t, g.FieldByName("DataDirectories").Index(j).Interface(), w.Field(i).Index(j).Interface())
			}
			continue
		}
		if g.FieldByName(name).Uint() != w.Field(i).Uint() {
			t.Errorf("%s = %x, want %x", name, g.FieldByName(name).Uint(), w.Field(i).Uint())
		}
	}
}

func TestTruncatedHeaders(t *testing.T) {
	for _, data := range [][]byte{buildPE32(), buildMinimalPE(2)} {
		headerEnd := 152 + int(binary.LittleEndian.Uint16(data[148:])) + 80
		for end := 0; end < headerEnd; end++ {
			if f, err := New(data[:end]); err == nil || f != nil {
				t.Fatalf("accepted truncated header at byte %d", end)
			}
		}
		f, err := New(data[:headerEnd])
		if err != nil || len(f.Sections) != 2 {
			t.Fatalf("complete headers with absent bodies: %v", err)
		}
		if _, ok := f.RVAToOffset(0x1000); ok {
			t.Fatal("mapped absent section bytes")
		}
	}
}

func TestInvalidHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte)
		want error
	}{
		{"not_pe", func(b []byte) { b[0] = 'X' }, ErrNotPE},
		{"bad_signature", func(b []byte) { b[128] = 'X' }, ErrInvalidMagic},
		{"overlap", func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 32) }, ErrInvalidHeader},
		{"large_lfanew", func(b []byte) { binary.LittleEndian.PutUint32(b[60:], math.MaxUint32) }, ErrOutOfBounds},
		{"missing_optional", func(b []byte) { binary.LittleEndian.PutUint16(b[148:], 0) }, ErrInvalidHeader},
		{"short_optional", func(b []byte) { binary.LittleEndian.PutUint16(b[148:], 111) }, ErrInvalidHeader},
		{"ROM", func(b []byte) { binary.LittleEndian.PutUint16(b[152:], OptionalHeaderMagicROM) }, ErrInvalidHeader},
		{"directory_count", func(b []byte) { binary.LittleEndian.PutUint32(b[260:], math.MaxUint32) }, ErrInvalidHeader},
		{"section_limit", func(b []byte) { binary.LittleEndian.PutUint16(b[134:], MaxSections+1) }, ErrSectionLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildMinimalPE(2)
			tc.edit(data)
			if f, err := New(data); f != nil || !errors.Is(err, tc.want) {
				t.Fatalf("New = (%v, %v), want %v", f, err, tc.want)
			}
		})
	}
	if f, err := New(buildMinimalPE(MaxSections)); err != nil || len(f.Sections) != MaxSections {
		t.Fatalf("limit should be inclusive: %v", err)
	}
}

func TestDataDirectories(t *testing.T) {
	for _, count := range []uint32{0, 1, 16, 17} {
		data := buildMinimalPE(0)
		// A 17th directory fits if the declared optional header is extended.
		binary.LittleEndian.PutUint16(data[148:], 248)
		binary.LittleEndian.PutUint32(data[260:], count)
		for i := 0; i < 17; i++ {
			binary.LittleEndian.PutUint32(data[264+i*8:], uint32(i+1)*4096)
			binary.LittleEndian.PutUint32(data[268+i*8:], uint32(i+1)*16)
		}
		f, err := New(data)
		if err != nil {
			t.Fatal(err)
		}
		if f.OptionalHeader.NumberOfRvaAndSizes != count {
			t.Fatal("lost declared count")
		}
		for i, d := range f.OptionalHeader.DataDirectories {
			want := DataDirectory{}
			if uint32(i) < count {
				want = DataDirectory{VirtualAddress: uint32(i+1) * 4096, Size: uint32(i+1) * 16}
			}
			if d != want {
				t.Fatalf("directory %d = %+v, want %+v", i, d, want)
			}
		}
	}
}

func TestAddressMapping(t *testing.T) {
	data := buildMinimalPE(2)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rva, offset uint32
		ok          bool
	}{
		{0, 0, true}, {511, 511, true}, {512, 0, false},
		{0x1000, 512, true}, {0x11ff, 1023, true}, {0x1200, 0, false},
		{0x1fff, 0, false}, {0x2000, 1024, true}, {0x2200, 0, false},
		{math.MaxUint32, 0, false},
	} {
		got, ok := f.RVAToOffset(tc.rva)
		if ok != tc.ok || ok && got != tc.offset {
			t.Errorf("RVA %#x = (%#x,%v)", tc.rva, got, ok)
		}
		if tc.ok {
			got, ok = f.OffsetToRVA(tc.offset)
			if !ok || got != tc.rva {
				t.Errorf("offset %#x = (%#x,%v)", tc.offset, got, ok)
			}
		}
	}
	for _, off := range []uint32{uint32(len(data)), math.MaxUint32} {
		if _, ok := f.OffsetToRVA(off); ok {
			t.Fatalf("mapped nonexistent offset %#x", off)
		}
	}
	f.Sections[0].VirtualSize = 1 // raw alignment padding remains addressable
	if off, ok := f.RVAToOffset(0x11ff); !ok || off != 1023 {
		t.Fatal("lost raw padding")
	}
	f.Sections[0].VirtualSize = 0
	if off, ok := f.RVAToOffset(0x1000); !ok || off != 512 {
		t.Fatal("lost raw-only section")
	}
	f.Sections[0].VirtualAddress = math.MaxUint32 - 15
	f.Sections[0].VirtualSize = 32
	if off, ok := f.RVAToOffset(math.MaxUint32); !ok || off != 527 {
		t.Fatal("wrapped RVA range")
	}
	if _, ok := f.OffsetToRVA(528); ok {
		t.Fatal("wrapped RVA result")
	}
	f.Sections[0].VirtualAddress = 0x1000
	f.Sections[0].PointerToRawData = math.MaxUint32 - 15
	if _, ok := f.RVAToOffset(0x1020); ok {
		t.Fatal("wrapped file offset")
	}
}

func TestOverlapsAndOverlay(t *testing.T) {
	data := append(buildMinimalPE(2), make([]byte, 100)...)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	f.Sections[1].VirtualAddress = 0x1000
	if off, ok := f.RVAToOffset(0x1000); !ok || off != 512 {
		t.Fatal("section order changed")
	}
	f.Sections[0].SizeOfRawData = 0
	if _, ok := f.RVAToOffset(0x1000); ok {
		t.Fatal("fell through zero-fill into overlapping section")
	}
	if _, ok := f.OffsetToRVA(1536); ok {
		t.Fatal("mapped overlay")
	}
	f.OptionalHeader.SizeOfHeaders = math.MaxUint32
	if _, ok := f.RVAToOffset(uint32(len(data))); ok {
		t.Fatal("header maps outside input")
	}
}

func TestConcurrentReads(t *testing.T) {
	f, err := New(buildMinimalPE(2))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if off, ok := f.RVAToOffset(0x1000); !ok || off != 512 || f.SectionByName(".text") == nil {
					t.Error("inconsistent read")
				}
			}
		})
	}
	wg.Wait()
}

func TestMetadataSurvivesInputReuse(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		name string
	}{{buildMinimalPE(1), ".text"}, {longNamePE(".long_section"), ".long_section"}} {
		f, err := New(tc.data)
		if err != nil {
			t.Fatal(err)
		}
		clear(tc.data) // A consumer may recycle its scan buffer immediately.
		if !f.Is64Bit() || f.FileHeader.Machine != MachineAMD64 || f.Sections[0].Name != tc.name {
			t.Fatal("metadata changed after input reuse")
		}
		if offset, ok := f.RVAToOffset(0x1000); !ok || offset != 512 {
			t.Fatal("mapping changed after input reuse")
		}
	}
}

func TestTruncatedSectionBody(t *testing.T) {
	data := buildMinimalPE(1)[:600]
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	if offset, ok := f.RVAToOffset(0x1057); !ok || offset != 599 {
		t.Fatal("last existing body byte was lost")
	}
	if _, ok := f.RVAToOffset(0x1058); ok {
		t.Fatal("mapped first missing body byte")
	}
	if rva, ok := f.OffsetToRVA(599); !ok || rva != 0x1057 {
		t.Fatal("last existing body byte has no reverse mapping")
	}
	if _, ok := f.OffsetToRVA(600); ok {
		t.Fatal("reverse-mapped first missing body byte")
	}
}
