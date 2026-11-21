package pe

import (
	"bytes"
	stdpe "debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// All RVAs in this fixture map to one .idata section. Names are shared across
// DLLs so limits also exercise repeated references to a small input.
func buildImportsPE(is64 bool, libraries, symbols int) []byte {
	data := buildMinimalPE(1)
	section, directory, width := 392, 272, 8
	if !is64 {
		data = buildPE32()
		binary.LittleEndian.PutUint16(data[134:], 1)
		section, directory, width = 376, 256, 4
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
			putImportThunk(data[thunks+(i*(symbols+1)+j)*width:], is64, uint64(names+j*16-512)+0x1000)
		}
	}
	for j := range symbols {
		binary.LittleEndian.PutUint16(data[names+j*16:], uint16(j))
		copy(data[names+j*16+2:], fmt.Sprintf("Function%d", j))
	}
	return data
}

func putImportThunk(data []byte, is64 bool, value uint64) {
	if is64 {
		binary.LittleEndian.PutUint64(data, value)
	} else {
		binary.LittleEndian.PutUint32(data, uint32(value))
	}
}

func importOffset(rva uint32) int { return int(rva) - 0x1000 + 512 }

func parseTestImports(t *testing.T, data []byte) ([]ImportLibrary, error) {
	t.Helper()
	f, err := New(data)
	if err != nil {
		t.Fatal(err)
	}
	return f.Imports(data)
}

func TestImports(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprint(is64), func(t *testing.T) {
			data := buildImportsPE(is64, 2, 3)
			width, flag := 4, uint64(1)<<31
			if is64 {
				width, flag = 8, uint64(1)<<63
			}
			for i := range 2 {
				offset := importOffset(binary.LittleEndian.Uint32(data[512+i*20:]))
				putImportThunk(data[offset+width:], is64, flag|0xffff)
				putImportThunk(data[offset+2*width:], is64, flag) // Ordinal zero is not a terminator.
			}
			slot0 := binary.LittleEndian.Uint32(data[512+16:])
			slot1 := binary.LittleEndian.Uint32(data[512+20+16:])
			w32 := uint32(width)
			got, err := parseTestImports(t, data)
			want := []ImportLibrary{
				{DLL: "lib0.dll", Symbols: []ImportSymbol{
					{Name: "Function0", IATSlotRVA: slot0, HasIATSlot: true},
					{Ordinal: 65535, ByOrdinal: true, IATSlotRVA: slot0 + w32, HasIATSlot: true},
					{ByOrdinal: true, IATSlotRVA: slot0 + 2*w32, HasIATSlot: true},
				}},
				{DLL: "lib1.dll", Symbols: []ImportSymbol{
					{Name: "Function0", IATSlotRVA: slot1, HasIATSlot: true},
					{Ordinal: 65535, ByOrdinal: true, IATSlotRVA: slot1 + w32, HasIATSlot: true},
					{ByOrdinal: true, IATSlotRVA: slot1 + 2*w32, HasIATSlot: true},
				}},
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("Imports = %+v, %v; want %+v", got, err, want)
			}
			clear(data)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("imports retain input")
			}
		})
	}
}

func TestImportsStandardLibrary(t *testing.T) {
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatalf("locate Go toolchain fixtures: %v", err)
	}
	goroot := strings.TrimSpace(string(root))
	inputs := map[string][]byte{
		"synthetic32": buildImportsPE(false, 3, 16),
		"synthetic64": buildImportsPE(true, 3, 16),
		"lookahead32": buildImportsPE(false, 2, 256),
		"lookahead64": buildImportsPE(true, 2, 256),
		"long32":      buildImportsPE(false, 2, 257),
		"long64":      buildImportsPE(true, 2, 257),
	}
	for _, name := range []string{"gcc-386-mingw-exec", "gcc-amd64-mingw-exec", "gcc-386-mingw-no-symbols-exec"} {
		data, err := os.ReadFile(filepath.Join(goroot, "src", "debug", "pe", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		inputs[name] = data
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			got, err := parseTestImports(t, data)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, library := range got {
				for _, symbol := range library.Symbols {
					if !symbol.ByOrdinal {
						names = append(names, symbol.Name+":"+library.DLL)
					}
				}
			}
			oracle, err := stdpe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = oracle.Close() }()
			want, err := oracle.ImportedSymbols()
			if err != nil || len(want) == 0 || !reflect.DeepEqual(names, want) {
				t.Fatalf("got %v; debug/pe returned %v, %v", names, want, err)
			}
		})
	}
}

func TestImportsLookupPolicy(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		for _, fallback := range []bool{false, true} {
			data := buildImportsPE(is64, 1, 2)
			if fallback {
				binary.LittleEndian.PutUint32(data[512:], 0)
			} else {
				// A bound image still has names in its ILT. The IAT isn't read.
				binary.LittleEndian.PutUint32(data[516:], math.MaxUint32)
				binary.LittleEndian.PutUint32(data[528:], math.MaxUint32)
			}
			got, err := parseTestImports(t, data)
			if err != nil || len(got) != 1 || len(got[0].Symbols) != 2 || got[0].Symbols[1].Hint != 1 {
				t.Fatalf("64=%t fallback=%t: %v, %v", is64, fallback, got, err)
			}
		}
	}
}

func TestImportsRejectMalformed(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		directory, section, width, flag := 256, 376, 4, uint64(1)<<31
		if is64 {
			directory, section, width, flag = 272, 392, 8, uint64(1)<<63
		}
		for _, tc := range []struct {
			name   string
			change func([]byte) []byte
			want   error
		}{
			{"zero_rva", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[directory:], 0); return d }, ErrInvalidImport},
			{"zero_size", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[directory+4:], 0); return d }, ErrInvalidImport},
			{"directory_wrap", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[directory:], math.MaxUint32-10); return d }, ErrIntegerOverflow},
			{"directory_unmapped", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[directory:], 0x80000000); return d }, ErrOutOfBounds},
			{"directory_terminator", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[directory+4:], 20); return d }, ErrInvalidImport},
			{"short_descriptor", func(d []byte) []byte { return d[:531] }, ErrOutOfBounds},
			{"zero_dll", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[524:], 0); return d }, ErrInvalidImport},
			{"empty_dll", func(d []byte) []byte { d[importOffset(binary.LittleEndian.Uint32(d[524:]))] = 0; return d }, ErrInvalidImport},
			{"unmapped_dll", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[524:], 0xffff0000); return d }, ErrOutOfBounds},
			{"no_lookup", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[512:], 0)
				binary.LittleEndian.PutUint32(d[528:], 0)
				return d
			}, ErrInvalidImport},
			{"bound_without_lookup", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[512:], 0)
				binary.LittleEndian.PutUint32(d[516:], 1)
				return d
			}, ErrInvalidImport},
			{"unmapped_lookup", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[512:], 0xffff0000); return d }, ErrOutOfBounds},
			{"ordinal_reserved_bits", func(d []byte) []byte {
				putImportThunk(d[importOffset(binary.LittleEndian.Uint32(d[512:])):], is64, flag|0x10000)
				return d
			}, ErrInvalidImport},
			{"name_rva_unmapped", func(d []byte) []byte {
				putImportThunk(d[importOffset(binary.LittleEndian.Uint32(d[512:])):], is64, 0x7fffffff)
				return d
			}, ErrOutOfBounds},
			{"truncated_hint", func(d []byte) []byte {
				putImportThunk(d[importOffset(binary.LittleEndian.Uint32(d[512:])):], is64, uint64(len(d)-512)+0xfff)
				return d
			}, ErrOutOfBounds},
			{"empty_symbol", func(d []byte) []byte {
				off := importOffset(binary.LittleEndian.Uint32(d[512:]))
				name := importOffset(binary.LittleEndian.Uint32(d[off:]))
				d[name+2] = 0
				return d
			}, ErrInvalidImport},
			{"unterminated_symbol", func(d []byte) []byte {
				off := importOffset(binary.LittleEndian.Uint32(d[512:]))
				name := importOffset(binary.LittleEndian.Uint32(d[off:]))
				for i := name + 2; i < len(d); i++ {
					d[i] = 'x'
				}
				return d
			}, ErrUnterminatedString},
			{"unterminated_lookup", func(d []byte) []byte {
				off := importOffset(binary.LittleEndian.Uint32(d[512:]))
				for i := off; i+width <= len(d); i += width {
					putImportThunk(d[i:], is64, flag|1)
				}
				return d
			}, ErrInvalidImport},
			{"virtual_tail", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[section+8:], 0x1000)
				binary.LittleEndian.PutUint32(d[524:], 0x1800)
				return d
			}, ErrOutOfBounds},
		} {
			t.Run(fmt.Sprintf("64=%t/%s", is64, tc.name), func(t *testing.T) {
				got, err := parseTestImports(t, tc.change(buildImportsPE(is64, 1, 2)))
				if got != nil || !errors.Is(err, tc.want) {
					t.Fatalf("got %+v, %v; want nil, %v", got, err, tc.want)
				}
			})
		}
	}
	data := buildImportsPE(true, 1, 1)
	putImportThunk(data[importOffset(binary.LittleEndian.Uint32(data[512:])):], true, 1<<32|0x1000)
	if got, err := parseTestImports(t, data); got != nil || !errors.Is(err, ErrInvalidImport) {
		t.Fatalf("high name RVA bits: %+v, %v", got, err)
	}
}

func TestImportsLimits(t *testing.T) {
	for _, tc := range []struct {
		name               string
		libraries, symbols int
		fail               bool
	}{
		{"libraries_at", MaxImportLibraries, 0, false},
		{"libraries_over", MaxImportLibraries + 1, 0, true},
		{"symbols_at", 1, MaxImportSymbols, false},
		{"symbols_over", 1, MaxImportSymbols + 1, true},
		{"symbols_across_dlls", 2, MaxImportSymbols/2 + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTestImports(t, buildImportsPE(true, tc.libraries, tc.symbols))
			if tc.fail {
				if got != nil || !errors.Is(err, ErrImportLimit) {
					t.Fatalf("got %d libraries, %v", len(got), err)
				}
			} else if err != nil || len(got) != tc.libraries {
				t.Fatalf("got %d libraries, %v", len(got), err)
			}
		})
	}
	for _, length := range []int{MaxImportNameBytes - 1, MaxImportNameBytes} {
		data := buildImportsPE(true, 1, 1)
		off := len(data)
		data = append(data, []byte(strings.Repeat("x", length)+"\x00")...)
		binary.LittleEndian.PutUint32(data[392+8:], uint32(len(data)-512))
		binary.LittleEndian.PutUint32(data[392+16:], uint32(len(data)-512))
		binary.LittleEndian.PutUint32(data[524:], uint32(off-512)+0x1000)
		got, err := parseTestImports(t, data)
		if length == MaxImportNameBytes-1 {
			if err != nil || len(got[0].DLL) != length {
				t.Fatalf("max name: %v", err)
			}
		} else if got != nil || !errors.Is(err, ErrUnterminatedString) {
			t.Fatalf("overlong name: %v", err)
		}
	}
}

func TestImportsEmptyAndNoDirectory(t *testing.T) {
	f, err := New(buildMinimalPE(1))
	if err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		got, err := f.Imports(nil)
		if got != nil || err != nil {
			t.Fatal(got, err)
		}
	}); allocations != 0 {
		t.Fatalf("absent imports allocated %g times", allocations)
	}
	f.OptionalHeader.NumberOfRvaAndSizes = 1
	f.OptionalHeader.DataDirectories[DataDirectoryImport] = DataDirectory{VirtualAddress: math.MaxUint32, Size: 40}
	if got, err := f.Imports(nil); got != nil || err != nil {
		t.Fatal(got, err)
	}
	data := buildImportsPE(false, 0, 0)
	if got, err := parseTestImports(t, data); got != nil || err != nil {
		t.Fatal(got, err)
	}
	for _, f := range []*File{nil, {}} {
		if got, err := f.Imports(nil); got != nil || !errors.Is(err, ErrInvalidHeader) {
			t.Fatal(got, err)
		}
	}
}

func TestImportIATSlotRVAs(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		width, flag := uint32(4), uint64(1)<<31
		if is64 {
			width, flag = 8, uint64(1)<<63
		}
		name := fmt.Sprintf("PE64=%t", is64)
		t.Run(name, func(t *testing.T) {
			t.Run("ZeroFirstThunk", func(t *testing.T) {
				data := buildImportsPE(is64, 1, 2)
				binary.LittleEndian.PutUint32(data[512+16:], 0)
				got, err := parseTestImports(t, data)
				if err != nil || len(got) != 1 || len(got[0].Symbols) != 2 {
					t.Fatalf("got (%+v, %v)", got, err)
				}
				for i, s := range got[0].Symbols {
					if s.HasIATSlot || s.IATSlotRVA != 0 {
						t.Fatalf("sym[%d] = %+v, want absent IAT slot", i, s)
					}
				}
			})

			t.Run("HighRVAAndOverflowBeforeNarrowing", func(t *testing.T) {
				data := buildImportsPE(is64, 1, 3)
				ilt := importOffset(binary.LittleEndian.Uint32(data[512:]))
				putImportThunk(data[ilt+int(width):], is64, flag|42)

				// High RVA with MSB set succeeds for all slots without signed wrap.
				binary.LittleEndian.PutUint32(data[512+16:], 0x80001000)
				got, err := parseTestImports(t, data)
				if err != nil || len(got[0].Symbols) != 3 {
					t.Fatalf("high RVA got (%+v, %v)", got, err)
				}
				for i, s := range got[0].Symbols {
					want := uint32(0x80001000) + uint32(i)*width
					if !s.HasIATSlot || s.IATSlotRVA != want {
						t.Fatalf("sym[%d] = (%#x, %t), want (%#x, true)", i, s.IATSlotRVA, s.HasIATSlot, want)
					}
				}

				// Slot 0 fits in uint32 while slots 1..2 overflow uint32 before narrowing.
				nearEnd := math.MaxUint32 - width + 1
				if nearEnd == 0 {
					nearEnd = math.MaxUint32
				}
				binary.LittleEndian.PutUint32(data[512+16:], nearEnd)
				got, err = parseTestImports(t, data)
				if err != nil || len(got[0].Symbols) != 3 {
					t.Fatalf("overflow RVA got (%+v, %v)", got, err)
				}
				if !got[0].Symbols[0].HasIATSlot || got[0].Symbols[0].IATSlotRVA != nearEnd {
					t.Fatalf("sym[0] = %+v, want %#x", got[0].Symbols[0], nearEnd)
				}
				for i := 1; i < 3; i++ {
					if got[0].Symbols[i].HasIATSlot || got[0].Symbols[i].IATSlotRVA != 0 {
						t.Fatalf("sym[%d] = %+v, want absent on uint32 overflow", i, got[0].Symbols[i])
					}
				}
			})

			t.Run("MismatchedUnmappedIATNotEagerlyReadAndBound", func(t *testing.T) {
				// Use separate unmapped FirstThunk in a bound descriptor; IAT bytes are never read.
				data := buildImportsPE(is64, 1, 2)
				binary.LittleEndian.PutUint32(data[512+4:], 1700000000) // Timestamp != 0 (bound)
				binary.LittleEndian.PutUint32(data[512+16:], 0x5000000) // Unmapped IAT base
				got, err := parseTestImports(t, data)
				if err != nil || len(got[0].Symbols) != 2 {
					t.Fatalf("bound separate IAT got (%+v, %v)", got, err)
				}
				if got[0].Symbols[0].IATSlotRVA != 0x5000000 || !got[0].Symbols[0].HasIATSlot ||
					got[0].Symbols[1].IATSlotRVA != 0x5000000+width || !got[0].Symbols[1].HasIATSlot {
					t.Fatalf("bound IAT slots = %+v", got[0].Symbols)
				}
			})

			t.Run("FallbackUnboundAndDuplicateDescriptors", func(t *testing.T) {
				data := buildImportsPE(is64, 2, 2)
				// Descriptor 0 falls back to FirstThunk (OriginalFirstThunk == 0, Timestamp == 0).
				binary.LittleEndian.PutUint32(data[512:], 0)
				ft0 := binary.LittleEndian.Uint32(data[512+16:])
				// Duplicate descriptor 1 points to the same DLL name and distinct FirstThunk.
				copy(data[532+12:532+16], data[512+12:512+16])
				ft1 := binary.LittleEndian.Uint32(data[532+16:])
				got, err := parseTestImports(t, data)
				if err != nil || len(got) != 2 || got[0].DLL != got[1].DLL {
					t.Fatalf("duplicate got (%+v, %v)", got, err)
				}
				if got[0].Symbols[1].IATSlotRVA != ft0+width || got[1].Symbols[1].IATSlotRVA != ft1+width {
					t.Fatalf("slots mismatch: %+v vs %+v", got[0].Symbols, got[1].Symbols)
				}
			})
		})
	}
}
