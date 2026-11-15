package pe_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestDelayImportsAbsentAndHeaderUntouched(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Minimal(is64, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		if allocs := testing.AllocsPerRun(50, func() {
			got, err := f.DelayImports(nil)
			if err != nil || got != nil {
				t.Fatalf("DelayImports() = (%+v, %v), want (nil, nil)", got, err)
			}
		}); allocs != 0 {
			t.Fatalf("absent DelayImports allocated %g times", allocs)
		}
	}

	// Fewer than 14 directories -> absent delay import directory even if bytes exist.
	data := testfixture.DelayImports(true, 1, 1)
	binary.LittleEndian.PutUint32(data[260:], 13)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.DelayImports(data); err != nil || got != nil {
		t.Fatalf("short directory table = (%+v, %v), want (nil, nil)", got, err)
	}
}

func TestDelayImportsRVAModeAndOrdinals(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		width, flag := uint32(4), uint64(1)<<31
		if is64 {
			width, flag = 8, uint64(1)<<63
		}
		data := testfixture.DelayImports(is64, 2, 3)

		// Put an ordinal (42) and ordinal 0 in the second/third slots of lib 0, plus non-UTF8 DLL byte.
		int0 := int(binary.LittleEndian.Uint32(data[512+16:])-0x1000) + 512
		iat0 := binary.LittleEndian.Uint32(data[512+12:])
		if is64 {
			binary.LittleEndian.PutUint64(data[int0+int(width):], flag|42)
			binary.LittleEndian.PutUint64(data[int0+2*int(width):], flag)
		} else {
			binary.LittleEndian.PutUint32(data[int0+int(width):], uint32(flag|42))
			binary.LittleEndian.PutUint32(data[int0+2*int(width):], uint32(flag))
		}
		// Add metadata RVAs on descriptor 0 to ensure preservation.
		binary.LittleEndian.PutUint32(data[512+8:], 0x1088)
		binary.LittleEndian.PutUint32(data[512+20:], 0x1090)
		binary.LittleEndian.PutUint32(data[512+24:], 0x1098)
		binary.LittleEndian.PutUint32(data[512+28:], 1700000123)

		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		orig := bytes.Clone(data)
		got, err := f.DelayImports(data)
		if err != nil {
			t.Fatalf("PE64=%t DelayImports failed: %v", is64, err)
		}
		// Mutate input buffer to prove slices/strings are owned.
		clear(data)

		if len(got) != 2 {
			t.Fatalf("got %d libs, want 2", len(got))
		}
		wantSyms0 := []pe.ImportSymbol{
			{Name: "Delay000", Hint: 0, IATSlotRVA: iat0, HasIATSlot: true},
			{Ordinal: 42, ByOrdinal: true, IATSlotRVA: iat0 + width, HasIATSlot: true},
			{Ordinal: 0, ByOrdinal: true, IATSlotRVA: iat0 + 2*width, HasIATSlot: true},
		}
		if got[0].Attributes != pe.DelayImportAttrRVA ||
			got[0].DLL != "a00.dll" ||
			got[0].ModuleHandleRVA != 0x1088 ||
			got[0].BoundImportAddressTableRVA != 0x1090 ||
			got[0].UnloadInformationTableRVA != 0x1098 ||
			got[0].TimeDateStamp != 1700000123 ||
			!reflect.DeepEqual(got[0].Symbols, wantSyms0) {
			t.Fatalf("lib[0] = %+v, want syms %+v", got[0], wantSyms0)
		}

		// Standard Imports remain untouched when DelayImports exist.
		std, err := f.Imports(orig)
		if err != nil || std != nil {
			t.Fatalf("Imports on delay-only PE = (%+v, %v), want (nil, nil)", std, err)
		}
	}
}

func TestDelayImportsLegacyVAMode(t *testing.T) {
	data := testfixture.DelayImportsWithAttributes(false, 0, 1, 2)
	const imageBase = uint32(0x400000)

	// Make symbol 1 an ordinal import (bit 31 set -> not VA-subtracted).
	intRVA := binary.LittleEndian.Uint32(data[512+16:]) - imageBase
	iatRVA := binary.LittleEndian.Uint32(data[512+12:]) - imageBase
	binary.LittleEndian.PutUint32(data[512+intRVA-0x1000+4:], (1<<31)|77)

	// Set non-zero VA for ModuleHandle, BoundIAT, UnloadIAT.
	binary.LittleEndian.PutUint32(data[512+8:], imageBase+0x1200)
	binary.LittleEndian.PutUint32(data[512+20:], imageBase+0x1300)
	binary.LittleEndian.PutUint32(data[512+24:], imageBase+0x1400)

	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.DelayImports(data)
	if err != nil {
		t.Fatalf("legacy VA DelayImports failed: %v", err)
	}
	if len(got) != 1 || got[0].Attributes != 0 || got[0].DLL != "a00.dll" ||
		got[0].ImportAddressTableRVA != iatRVA ||
		got[0].ImportNameTableRVA != intRVA ||
		got[0].ModuleHandleRVA != 0x1200 ||
		got[0].BoundImportAddressTableRVA != 0x1300 ||
		got[0].UnloadInformationTableRVA != 0x1400 {
		t.Fatalf("legacy VA lib = %+v", got)
	}
	want := []pe.ImportSymbol{
		{Name: "Delay000", Hint: 0, IATSlotRVA: iatRVA, HasIATSlot: true},
		{Ordinal: 77, ByOrdinal: true, IATSlotRVA: iatRVA + 4, HasIATSlot: true},
	}
	if !reflect.DeepEqual(got[0].Symbols, want) {
		t.Fatalf("legacy VA syms = %+v, want %+v", got[0].Symbols, want)
	}
}

func TestDelayImportsFallbacksZeroHighOverflowAndDuplicates(t *testing.T) {
	// Test INT==0 fallback to IAT (unbound), unused IAT with bound INT, zero/high/overflow IAT, and duplicate DLLs.
	data := testfixture.DelayImports(true, 3, 2)
	// Descriptor 0: unbound fallback (INT = 0, TimeDateStamp = 0 -> read IAT as lookup).
	binary.LittleEndian.PutUint32(data[512+16:], 0)
	iat0 := binary.LittleEndian.Uint32(data[512+12:])

	// Descriptor 1: bound image (TimeDateStamp != 0), unmapped overflowing IAT near MaxUint32.
	binary.LittleEndian.PutUint32(data[512+32+28:], 1700000000)
	binary.LittleEndian.PutUint32(data[512+32+12:], math.MaxUint32-7) // slot 0 fits, slot 1 overflows uint32

	// Descriptor 2: duplicate of lib 1 DLL name with IAT = 0 (zero IAT slot).
	copy(data[512+64+4:512+64+8], data[512+32+4:512+32+8])
	binary.LittleEndian.PutUint32(data[512+64+12:], 0)

	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.DelayImports(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d libs, want 3", len(got))
	}
	if got[0].Symbols[0].IATSlotRVA != iat0 || got[0].Symbols[1].IATSlotRVA != iat0+8 {
		t.Fatalf("fallback slots = %+v", got[0].Symbols)
	}
	if !got[1].Symbols[0].HasIATSlot || got[1].Symbols[0].IATSlotRVA != math.MaxUint32-7 ||
		got[1].Symbols[1].HasIATSlot || got[1].Symbols[1].IATSlotRVA != 0 {
		t.Fatalf("overflow slots = %+v", got[1].Symbols)
	}
	if got[2].DLL != got[1].DLL || got[2].Symbols[0].HasIATSlot || got[2].Symbols[1].HasIATSlot {
		t.Fatalf("duplicate/zero-IAT lib = %+v", got[2])
	}
}
