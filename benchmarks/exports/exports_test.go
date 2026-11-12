package exports_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"sort"
	"testing"

	binject "github.com/Binject/debug/pe"
	pe "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

// The fixtures contain only an export directory. Omit unrelated directory
// parsers explicitly; saferwall still parses its ordinary header metadata.
func exportOptions() *saferwall.Options {
	return &saferwall.Options{
		OmitImportDirectory: true, OmitExceptionDirectory: true, OmitResourceDirectory: true,
		OmitSecurityDirectory: true, OmitRelocDirectory: true, OmitDebugDirectory: true,
		OmitArchitectureDirectory: true, OmitGlobalPtrDirectory: true, OmitTLSDirectory: true,
		OmitLoadConfigDirectory: true, OmitBoundImportDirectory: true, OmitIATDirectory: true,
		OmitDelayImportDirectory: true, OmitCLRHeaderDirectory: true, OmitCLRMetadata: true,
	}
}

type record struct {
	ordinal, rva    uint32
	name, forwarder string
}

func TestCommonExportRecords(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("PE64=%t/Mixed=%t", is64, mixed), func(t *testing.T) {
				data := testfixture.Exports(is64, 16)
				if mixed {
					binary.LittleEndian.PutUint32(data[536:], 8) // Eight ordinal-only exports.
					pointers := int(binary.LittleEndian.Uint32(data[544:])) - 0x1000 + 512
					forwarder := binary.LittleEndian.Uint32(data[pointers+15*4:]) + 16
					copy(data[int(forwarder)-0x1000+512:], "other.Target\x00")
					binary.LittleEndian.PutUint32(data[552+15*4:], forwarder)
				}
				local, err := pe.New(data)
				if err != nil {
					t.Fatal(err)
				}
				out, err := local.Exports(data)
				if err != nil {
					t.Fatal(err)
				}
				var want []record
				for _, s := range out.Symbols {
					name := ""
					if len(s.Names) > 0 {
						name = s.Names[0]
					}
					want = append(want, record{s.Ordinal, s.RVA, name, s.Forwarder})
				}
				other, err := binject.NewFile(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				exports, err := other.Exports()
				if err != nil {
					t.Fatal(err)
				}
				var got []record
				for _, s := range exports {
					got = append(got, record{s.Ordinal, s.VirtualAddress, s.Name, s.Forward})
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("Binject: %+v; want %+v", got, want)
				}
				safe, err := saferwall.NewBytes(data, exportOptions())
				if err != nil {
					t.Fatal(err)
				}
				defer safe.Close()
				if err := safe.Parse(); err != nil {
					t.Fatal(err)
				}
				if safe.Export.Struct.Name != out.DLLNameRVA || safe.Export.Name != out.DLL {
					t.Fatalf("saferwall DLL: %#x %q; want %#x %q", safe.Export.Struct.Name, safe.Export.Name, out.DLLNameRVA, out.DLL)
				}
				got = nil
				for _, s := range safe.Export.Functions {
					got = append(got, record{s.Ordinal, s.FunctionRVA, s.Name, s.Forwarder})
				}
				sort.Slice(got, func(i, j int) bool { return got[i].ordinal < got[j].ordinal })
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("saferwall: %+v; want %+v", got, want)
				}
			})
		}
	}
}

// Each timed iteration parses headers and exports from the same bytes. These
// libraries return different representations and validate different contracts.
func BenchmarkParseExports(b *testing.B) {
	for _, count := range []int{16, 256} {
		data := testfixture.Exports(true, count)
		b.Run(fmt.Sprintf("Symbols%d/go-pe", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := pe.New(data)
				if err != nil {
					b.Fatal(err)
				}
				out, err := f.Exports(data)
				if err != nil || len(out.Symbols) != count {
					b.Fatalf("exports: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("Symbols%d/Binject", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := binject.NewFile(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				out, err := f.Exports()
				f.Close()
				if err != nil || len(out) != count {
					b.Fatalf("exports: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("Symbols%d/saferwall", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := saferwall.NewBytes(data, exportOptions())
				if err != nil {
					b.Fatal(err)
				}
				err = f.Parse()
				f.Close()
				if err != nil || len(f.Export.Functions) != count {
					b.Fatalf("exports: %v", err)
				}
			}
		})
	}
}
