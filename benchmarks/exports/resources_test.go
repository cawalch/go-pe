package exports_test

import (
	"fmt"
	"reflect"
	"testing"

	pe "github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
	saferwall "github.com/saferwall/pe"
)

func resourceOptions() *saferwall.Options {
	opts := exportOptions()
	opts.OmitResourceDirectory = false
	opts.Logger = discardLogger{}
	return opts
}

type commonResourceLeaf struct {
	path     []string
	dataRVA  uint32
	size     uint32
	codePage uint32
	reserved uint32
}

func flattenSaferwallResources(dir saferwall.ResourceDirectory, prefix []string, out *[]commonResourceLeaf) {
	for _, entry := range dir.Entries {
		step := fmt.Sprintf("id:%d", entry.ID)
		if entry.Struct.Name&0x80000000 != 0 {
			step = "name:" + entry.Name
		}
		path := append(append([]string(nil), prefix...), step)
		if entry.IsResourceDir {
			flattenSaferwallResources(entry.Directory, path, out)
			continue
		}
		*out = append(*out, commonResourceLeaf{
			path:     path,
			dataRVA:  entry.Data.Struct.OffsetToData,
			size:     entry.Data.Struct.Size,
			codePage: entry.Data.Struct.CodePage,
			reserved: entry.Data.Struct.Reserved,
		})
	}
}

func TestCommonResourceRecords(t *testing.T) {
	// Scope excludes non-ASCII UTF-16 names, cycles, and large shared-DAG budgets:
	// saferwall/pe truncates each UTF-16 code unit to its low byte and does not
	// bound cumulative visited entries across repeated/shared DAG nodes.
	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("PE64=%t", is64), func(t *testing.T) {
			sharedLang := &testfixture.ResourceNodeSpec{
				Entries: []testfixture.ResourceEntrySpec{
					{
						ID: 1033,
						Leaf: &testfixture.ResourceLeafSpec{
							Payload:  []byte("ascii-payload"),
							CodePage: 1200,
							Reserved: 3,
						},
					},
				},
			}
			root := &testfixture.ResourceNodeSpec{
				Characteristics: 1,
				TimeDateStamp:   0x12345678,
				MajorVersion:    2,
				MinorVersion:    5,
				Entries: []testfixture.ResourceEntrySpec{
					{
						Named: true,
						Name:  "CONFIG",
						Subdir: &testfixture.ResourceNodeSpec{
							Entries: []testfixture.ResourceEntrySpec{
								{Named: true, Name: "MAIN", Subdir: sharedLang},
								{ID: 42, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("two-level"), CodePage: 65001}},
							},
						},
					},
					{
						ID: 10,
						Subdir: &testfixture.ResourceNodeSpec{
							Entries: []testfixture.ResourceEntrySpec{
								{ID: 7, Subdir: sharedLang},
							},
						},
					},
				},
			}
			data := testfixture.Resources(is64, root)

			local, err := pe.New(data)
			if err != nil {
				t.Fatal(err)
			}
			dir, err := local.Resources(data)
			if err != nil {
				t.Fatal(err)
			}

			var want []commonResourceLeaf
			for _, r := range dir.Records {
				var path []string
				for _, c := range r.Path {
					if c.Named {
						path = append(path, "name:"+c.Name)
					} else {
						path = append(path, fmt.Sprintf("id:%d", c.ID))
					}
				}
				want = append(want, commonResourceLeaf{
					path:     path,
					dataRVA:  r.DataRVA,
					size:     r.Size,
					codePage: r.CodePage,
					reserved: r.Reserved,
				})
			}

			safe, err := saferwall.NewBytes(data, resourceOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = safe.Close() }()
			if err := safe.Parse(); err != nil {
				t.Fatal(err)
			}
			if !safe.HasResource ||
				safe.Resources.Struct.TimeDateStamp != dir.TimeDateStamp ||
				safe.Resources.Struct.MajorVersion != dir.MajorVersion ||
				safe.Resources.Struct.MinorVersion != dir.MinorVersion ||
				safe.Resources.Struct.NumberOfNamedEntries != dir.NumberOfNamedEntries ||
				safe.Resources.Struct.NumberOfIDEntries != dir.NumberOfIDEntries {
				t.Fatalf("root header mismatch: saferwall=%+v, go-pe=%+v", safe.Resources.Struct, dir)
			}
			var got []commonResourceLeaf
			flattenSaferwallResources(safe.Resources, nil, &got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("saferwall leaves = %+v, want %+v", got, want)
			}
		})
	}
}

func BenchmarkParseResources(b *testing.B) {
	for _, count := range []int{16, 256} {
		data := testfixture.ResourcesSimple(true, count)
		b.Run(fmt.Sprintf("Leaves%d/go-pe", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := pe.New(data)
				if err != nil {
					b.Fatal(err)
				}
				dir, err := f.Resources(data)
				if err != nil || len(dir.Records) != count {
					b.Fatalf("resources: %v", err)
				}
			}
		})
		b.Run(fmt.Sprintf("Leaves%d/saferwall", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				f, err := saferwall.NewBytes(data, resourceOptions())
				if err != nil {
					b.Fatal(err)
				}
				err = f.Parse()
				_ = f.Close()
				if err != nil || !f.HasResource || len(f.Resources.Entries) == 0 || len(f.Resources.Entries[0].Directory.Entries) != count {
					b.Fatalf("saferwall resources: %v", err)
				}
			}
		})
	}
}
