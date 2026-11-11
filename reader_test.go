package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestSafeReaderBounds(t *testing.T) {
	r := NewSafeReader([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	for _, tc := range []struct {
		offset, length int64
		want           error
	}{
		{0, 8, nil}, {8, 0, nil}, {7, 1, nil},
		{-1, 0, ErrOutOfBounds}, {0, -1, ErrOutOfBounds}, {9, 0, ErrOutOfBounds},
		{7, 2, ErrOutOfBounds}, {math.MaxInt64, 1, ErrIntegerOverflow},
		{1, math.MaxInt64, ErrIntegerOverflow}, {0, math.MaxInt64, ErrOutOfBounds},
	} {
		b, err := r.Slice(tc.offset, tc.length)
		if !errors.Is(err, tc.want) || r.CheckBounds(tc.offset, tc.length) != (tc.want == nil) {
			t.Errorf("Slice(%d,%d) = %x, %v", tc.offset, tc.length, b, err)
		}
	}
	if v, err := r.ReadUint8(7); v != 8 || err != nil {
		t.Fatal(v, err)
	}
	if v, err := r.ReadUint16(6); v != 0x0807 || err != nil {
		t.Fatal(v, err)
	}
	if v, err := r.ReadUint32(4); v != 0x08070605 || err != nil {
		t.Fatal(v, err)
	}
	if v, err := r.ReadUint64(0); v != 0x0807060504030201 || err != nil {
		t.Fatal(v, err)
	}
	if _, err := r.ReadUint8(8); !errors.Is(err, ErrOutOfBounds) {
		t.Fatal(err)
	}
	if _, err := r.ReadUint16(7); !errors.Is(err, ErrOutOfBounds) {
		t.Fatal(err)
	}
	if _, err := r.ReadUint32(5); !errors.Is(err, ErrOutOfBounds) {
		t.Fatal(err)
	}
	if _, err := r.ReadUint64(1); !errors.Is(err, ErrOutOfBounds) {
		t.Fatal(err)
	}
	var empty SafeReader
	if b, err := empty.Slice(0, 0); len(b) != 0 || err != nil {
		t.Fatal(b, err)
	}
}

func TestASCIIZ(t *testing.T) {
	r := NewSafeReader([]byte("hello\x00tail"))
	for _, tc := range []struct {
		offset, max int64
		text        string
		err         error
	}{
		{0, 6, "hello", nil}, {0, math.MaxInt64, "hello", nil}, {5, 1, "", nil},
		{0, 5, "", ErrUnterminatedString}, {6, 99, "", ErrUnterminatedString},
		{0, 0, "", ErrOutOfBounds}, {0, -1, "", ErrOutOfBounds},
		{-1, 6, "", ErrOutOfBounds}, {10, 1, "", ErrOutOfBounds},
	} {
		got, err := r.ReadASCIIZ(tc.offset, tc.max)
		if got != tc.text || !errors.Is(err, tc.err) {
			t.Errorf("ReadASCIIZ(%d,%d) = %q,%v", tc.offset, tc.max, got, err)
		}
	}
}

func longNamePE(name string) []byte {
	data := buildMinimalPE(1)
	// Some toolchains retain COFF long names in PE images. Resolve them only
	// within the declared string table, including its four-byte length prefix.
	binary.LittleEndian.PutUint32(data[140:], 512)
	copy(data[392:400], []byte{'/', '4', 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint32(data[512:], uint32(4+len(name)+1))
	copy(data[516:], name)
	return data
}

func TestCOFFLongNames(t *testing.T) {
	for _, name := range []string{".long_section", string(bytes.Repeat([]byte{'x'}, MaxSectionNameBytes-1))} {
		f, err := New(longNamePE(name))
		if err != nil || f.Sections[0].Name != name {
			t.Fatalf("long name: %v", err)
		}
	}
	for _, tc := range []struct {
		name string
		edit func([]byte)
		want error
	}{
		{"negative", func(b []byte) { copy(b[392:400], []byte{'/', '-', '1', 0, 0, 0, 0, 0}) }, ErrInvalidHeader},
		{"prefix", func(b []byte) { b[393] = '3' }, ErrInvalidHeader},
		{"past_table", func(b []byte) { copy(b[392:400], []byte{'/', '9', '9', 0, 0, 0, 0, 0}) }, ErrInvalidHeader},
		{"table_size", func(b []byte) { binary.LittleEndian.PutUint32(b[512:], math.MaxUint32) }, ErrOutOfBounds},
		{"count_overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[144:], 0x80000000) }, ErrOutOfBounds},
		{"pointer_overflow", func(b []byte) {
			binary.LittleEndian.PutUint32(b[140:], math.MaxUint32)
			binary.LittleEndian.PutUint32(b[144:], 2)
		}, ErrOutOfBounds},
		{"outside_terminator", func(b []byte) { binary.LittleEndian.PutUint32(b[512:], 4+uint32(len(".long_section"))) }, ErrUnterminatedString},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := longNamePE(".long_section")
			tc.edit(data)
			if f, err := New(data); f != nil || !errors.Is(err, tc.want) {
				t.Fatalf("New = %v, %v; want %v", f, err, tc.want)
			}
		})
	}
	if _, err := New(longNamePE(string(bytes.Repeat([]byte{'x'}, MaxSectionNameBytes)))); !errors.Is(err, ErrUnterminatedString) {
		t.Fatalf("name bound: %v", err)
	}
}

func TestEightByteSectionName(t *testing.T) {
	data := buildMinimalPE(1)
	copy(data[392:400], "12345678")
	f, err := New(data)
	if err != nil || f.Sections[0].Name != "12345678" {
		t.Fatalf("full-width section name: %v, %v", f, err)
	}
}
