package pe_test

import (
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzDelayImports(f *testing.F) {
	for _, count := range []int{16, 17, 18, 255, 256, 257} {
		f.Add(testfixture.DelayImports(false, 2, count))
		f.Add(testfixture.DelayImports(true, 2, count))
		f.Add(testfixture.DelayImportsWithAttributes(false, 0, 2, count))
	}
	f.Add(testfixture.Minimal(false, 1))
	f.Add(testfixture.Minimal(true, 1))
	f.Add(testfixture.DelayImports(false, 2, 3))
	f.Add(testfixture.DelayImports(true, 2, 3))
	f.Add(testfixture.DelayImportsWithAttributes(false, 0, 1, 2))
	f.Add(testfixture.DelayImports(true, 1, 1)[:530])

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := pe.New(data)
		if err != nil {
			return
		}
		libs, err := parsed.DelayImports(data)
		if err != nil {
			if libs != nil {
				t.Fatal("partial delayed imports returned with error")
			}
			return
		}
		if len(libs) > pe.MaxDelayImportLibraries {
			t.Fatalf("library count %d exceeds MaxDelayImportLibraries", len(libs))
		}
		symbols, nameBytes := 0, 0
		checkName := func(s string) {
			if len(s) == 0 || len(s) >= pe.MaxDelayImportNameBytes {
				t.Fatalf("invalid name length %d", len(s))
			}
			nameBytes += len(s) + 1
		}
		for _, lib := range libs {
			if lib.Attributes&^pe.DelayImportAttrRVA != 0 {
				t.Fatalf("unsupported attributes %#x passed", lib.Attributes)
			}
			checkName(lib.DLL)
			symbols += len(lib.Symbols)
			for i, sym := range lib.Symbols {
				if !sym.HasIATSlot && sym.IATSlotRVA != 0 {
					t.Fatal("absent IAT slot has nonzero RVA")
				}
				if sym.HasIATSlot && i > 0 && lib.Symbols[i-1].HasIATSlot && sym.IATSlotRVA <= lib.Symbols[i-1].IATSlotRVA {
					t.Fatal("non-monotonic IAT slot RVA")
				}
				if sym.ByOrdinal {
					if sym.Name != "" || sym.Hint != 0 {
						t.Fatal("ordinal import has name metadata")
					}
				} else {
					checkName(sym.Name)
					if sym.Ordinal != 0 {
						t.Fatal("named import has ordinal metadata")
					}
				}
			}
		}
		if symbols > pe.MaxDelayImportSymbols || nameBytes > pe.MaxDelayImportStringBytes {
			t.Fatalf("unbounded delay import output: symbols=%d nameBytes=%d", symbols, nameBytes)
		}
	})
}
