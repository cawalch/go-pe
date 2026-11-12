package pe

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/cawalch/go-pe/internal/testfixture"
)

func exportOffset(rva uint32) int { return int(rva) - 0x1000 + 512 }
func exportRVA(offset int) uint32 { return uint32(offset-512) + 0x1000 }
func exportDirectoryOffset(is64 bool) int {
	if is64 {
		return 0x108
	}
	return 0xf8
}
func exportSectionOffset(is64 bool) int {
	if is64 {
		return 0x188
	}
	return 0x178
}
func exportTableOffset(data []byte, field int) int {
	return exportOffset(binary.LittleEndian.Uint32(data[512+field:]))
}
func parseTestExports(t testing.TB, data []byte) (*ExportDirectory, error) {
	t.Helper()
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	return f.Exports(data)
}

func TestExports(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprint(is64), func(t *testing.T) {
			data := testfixture.Exports(is64, 4)
			// Preserve duplicate aliases, an empty name, an ordinal-only entry,
			// and a hole. All names point to the first slot, in pointer-table order.
			ordinals := exportTableOffset(data, 36)
			clear(data[ordinals : ordinals+8])
			pointers := exportTableOffset(data, 32)
			binary.LittleEndian.PutUint32(data[pointers+4:], binary.LittleEndian.Uint32(data[pointers:]))
			data[exportOffset(binary.LittleEndian.Uint32(data[pointers+8:]))] = 0
			binary.LittleEndian.PutUint32(data[552+8:], 0)
			forwarder := exportOffset(binary.LittleEndian.Uint32(data[pointers+12:])) + 16
			copy(data[forwarder:], "other.#123\x00")
			binary.LittleEndian.PutUint32(data[552+12:], exportRVA(forwarder))
			got, err := parseTestExports(t, data)
			want := &ExportDirectory{DLL: "example.dll", TimeDateStamp: 0x12345678, MajorVersion: 2, MinorVersion: 3, OrdinalBase: 7,
				Symbols: []ExportSymbol{
					{Ordinal: 7, RVA: 0x10000000, Names: []string{"Function00000", "Function00000", "", "Function00003"}},
					{Ordinal: 8, RVA: 0x10000004}, {Ordinal: 9},
					{Ordinal: 10, RVA: exportRVA(forwarder), Forwarder: "other.#123", Forwarded: true},
				}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("Exports = %+v, %v; want %+v", got, err, want)
			}
			clear(data)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("exports retain input")
			}
		})
	}
}

func TestExportsNameAndForwarderPolicy(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Exports(is64, 2)
		first := exportOffset(binary.LittleEndian.Uint32(data[exportTableOffset(data, 32):]))
		copy(data[first:], "\xffodd-name\x00")
		binary.LittleEndian.PutUint32(data[524:], 0) // The DLL name is optional.
		// An empty forwarder is still distinguishable from an ordinary target.
		binary.LittleEndian.PutUint32(data[556:], exportRVA(len(data)-1))
		binary.LittleEndian.PutUint32(data[exportDirectoryOffset(is64)+4:], uint32(len(data)-512))
		got, err := parseTestExports(t, data)
		if err != nil {
			t.Fatal(err)
		}
		if got.DLL != "" || got.Symbols[0].Names[0] != "\xffodd-name" ||
			!got.Symbols[1].Forwarded || got.Symbols[1].Forwarder != "" {
			t.Fatalf("raw metadata: %+v", got)
		}
		// Empty tables don't dereference their unused pointers.
		clear(data[532:540])
		binary.LittleEndian.PutUint32(data[540:], 0xffffffff)
		got, err = parseTestExports(t, data)
		if err != nil || len(got.Symbols) != 0 {
			t.Fatalf("empty directory: %+v %v", got, err)
		}
	}
}

func TestExportsConcurrentAndRepeated(t *testing.T) {
	data := testfixture.Exports(true, 16)
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			first, err := f.Exports(data)
			if err != nil {
				t.Fatal(err)
			}
			first.Symbols[0].Names[0] = "changed"
			first.Symbols[0].Names = append(first.Symbols[0].Names, "extra")
			if first.Symbols[1].Names[0] != "Function00001" {
				t.Fatal("alias slices share append capacity")
			}
			second, err := f.Exports(data)
			if err != nil || second.Symbols[0].Names[0] != "Function00000" {
				t.Fatal("results share mutable state", err)
			}
		})
	}
}

func TestExportsCrossSectionTable(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Exports(is64, 2)
		want, err := parseTestExports(t, data)
		if err != nil {
			t.Fatal(err)
		}
		// Move the address table and one name to a second raw section. The DLL
		// name lives in headers; all remain outside the export directory range.
		secondRaw := len(data)
		data = append(data, make([]byte, 512)...)
		binary.LittleEndian.PutUint16(data[0x86:], 2)
		section := exportSectionOffset(is64) + 40
		copy(data[section:], ".other\x00\x00")
		binary.LittleEndian.PutUint32(data[section+8:], 512)
		binary.LittleEndian.PutUint32(data[section+12:], 0x20000000)
		binary.LittleEndian.PutUint32(data[section+16:], 512)
		binary.LittleEndian.PutUint32(data[section+20:], uint32(secondRaw))
		copy(data[secondRaw:], data[552:560])
		binary.LittleEndian.PutUint32(data[540:], 0x20000000)
		copy(data[secondRaw+16:], "Function00001\x00")
		pointers := exportTableOffset(data, 32)
		binary.LittleEndian.PutUint32(data[pointers+4:], 0x20000010)
		copy(data[0x1f0:], "example.dll\x00")
		binary.LittleEndian.PutUint32(data[524:], 0x1f0)
		got, err := parseTestExports(t, data)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("cross-section tables: %+v, %v; want %+v", got, err, want)
		}
	}
}
