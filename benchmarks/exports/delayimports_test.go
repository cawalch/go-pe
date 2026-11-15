package exports_test

import (
	"fmt"
	"testing"

	gope "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func delayImportOptions() *saferwall.Options {
	return &saferwall.Options{
		OmitExportDirectory:        true,
		OmitImportDirectory:        true,
		OmitResourceDirectory:      true,
		OmitExceptionDirectory:     true,
		OmitSecurityDirectory:      true,
		OmitRelocDirectory:         true,
		OmitDebugDirectory:         true,
		OmitArchitectureDirectory:  true,
		OmitGlobalPtrDirectory:     true,
		OmitTLSDirectory:           true,
		OmitLoadConfigDirectory:    true,
		OmitBoundImportDirectory:   true,
		OmitIATDirectory:           true,
		OmitDelayImportDirectory:   false,
		OmitCLRHeaderDirectory:     true,
		DisableCertValidation:      true,
		DisableSignatureValidation: true,
		Logger:                     discardLogger{},
	}
}

func TestCommonDelayImports(t *testing.T) {
	// Scope excludes PE32+ VA-based descriptors and saferwall's optional
	// IsValidDosFilename filter on DLL names; covers well-formed RVA-based PE32+
	// and legacy VA-based PE32 delayed imports with matching INT/IAT tables.
	cases := []struct {
		name  string
		is64  bool
		attrs uint32
	}{
		{"PE32_VA", false, 0},
		{"PE32_RVA", false, gope.DelayImportAttrRVA},
		{"PE64_RVA", true, gope.DelayImportAttrRVA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := testfixture.DelayImportsWithAttributes(tc.is64, tc.attrs, 2, 4)

			f, err := gope.New(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.DelayImports(data)
			if err != nil {
				t.Fatal(err)
			}

			safe, err := saferwall.NewBytes(data, delayImportOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer safe.Close()
			if err := safe.Parse(); err != nil {
				t.Fatal(err)
			}

			if len(got) != len(safe.DelayImports) {
				t.Fatalf("library count mismatch: go-pe=%d saferwall=%d", len(got), len(safe.DelayImports))
			}
			for i, sl := range safe.DelayImports {
				gl := got[i]
				if gl.DLL != sl.Name || len(gl.Symbols) != len(sl.Functions) {
					t.Fatalf("lib[%d] mismatch: go-pe=(%q,%d) saferwall=(%q,%d)", i, gl.DLL, len(gl.Symbols), sl.Name, len(sl.Functions))
				}
				for j, sf := range sl.Functions {
					gf := gl.Symbols[j]
					// saferwall leaves ThunkRVA populated with raw VA in PE32 Attributes=0 mode
					// vs normalized RVA in go-pe; compare after normalizing when attrs==0.
					wantSlot := sf.ThunkRVA
					if tc.attrs == 0 {
						wantSlot -= uint32(f.OptionalHeader.ImageBase)
					}
					if gf.Name != sf.Name || gf.Hint != sf.Hint || gf.ByOrdinal != sf.ByOrdinal ||
						!gf.HasIATSlot || gf.IATSlotRVA != wantSlot {
						t.Fatalf("lib[%d].sym[%d] mismatch: go-pe=%+v saferwall=%+v (wantSlot=%#x)", i, j, gf, sf, wantSlot)
					}
				}
			}
		})
	}
}

func BenchmarkParseDelayImports(b *testing.B) {
	for _, count := range []int{16, 256} {
		data := testfixture.DelayImports(true, 1, count)
		b.Run(fmt.Sprintf("Symbols%d/go-pe", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := gope.New(data)
				if err != nil {
					b.Fatal(err)
				}
				libs, err := f.DelayImports(data)
				if err != nil || len(libs) != 1 || len(libs[0].Symbols) != count {
					b.Fatalf("DelayImports = (%+v, %v)", libs, err)
				}
			}
		})

		b.Run(fmt.Sprintf("Symbols%d/saferwall", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				safe, err := saferwall.NewBytes(data, delayImportOptions())
				if err != nil {
					b.Fatal(err)
				}
				err = safe.Parse()
				safe.Close()
				if err != nil || len(safe.DelayImports) != 1 || len(safe.DelayImports[0].Functions) != count {
					b.Fatalf("saferwall DelayImports = (%+v, %v)", safe.DelayImports, err)
				}
			}
		})
	}
}
