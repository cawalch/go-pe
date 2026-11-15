package pe_test

import (
	"encoding/binary"
	"testing"
	"unicode/utf8"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzResources(f *testing.F) {
	shared := &testfixture.ResourceNodeSpec{
		Entries: []testfixture.ResourceEntrySpec{
			{ID: 1033, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("en"), CodePage: 1200}},
		},
	}
	for _, is64 := range []bool{false, true} {
		simple := testfixture.ResourcesSimple(is64, 3)
		f.Add(is64, false, simple)
		f.Add(is64, true, simple[512:])

		complexGraph := testfixture.Resources(is64, &testfixture.ResourceNodeSpec{
			TimeDateStamp: 1,
			Entries: []testfixture.ResourceEntrySpec{
				{Named: true, Name: "Icon-\U0001F680", Subdir: shared},
				{Named: true, RawNameUnits: []uint16{'X', 0xD800, 0xDC01}, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("x")}},
				{ID: 1, Subdir: shared},
				{ID: 16, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("one-level")}},
			},
		})
		f.Add(is64, false, complexGraph)
		f.Add(is64, true, complexGraph[512:])

		cycle := append([]byte(nil), simple...)
		binary.LittleEndian.PutUint32(cycle[512+16+4:], 0x80000000)
		f.Add(is64, true, cycle[512:])
	}
	f.Add(false, false, []byte("MZ"))
	f.Add(true, false, testfixture.Minimal(true, 1))
	f.Add(true, true, []byte{})

	f.Fuzz(func(t *testing.T, is64, payloadOnly bool, data []byte) {
		if payloadOnly {
			if uint64(len(data)) > 1<<32-1 {
				return
			}
			header := testfixture.Resources(is64, &testfixture.ResourceNodeSpec{})[:512]
			sec0 := testfixture.ResourceSectionOffset(is64, 0)
			dirOff := testfixture.ResourceDirOffset(is64)
			binary.LittleEndian.PutUint32(header[sec0+8:], uint32(len(data)))
			binary.LittleEndian.PutUint32(header[sec0+16:], uint32(len(data)))
			binary.LittleEndian.PutUint32(header[dirOff:], 0x1000)
			binary.LittleEndian.PutUint32(header[dirOff+4:], uint32(len(data)))
			data = append(header[:512:512], data...)
		}
		file, err := pe.New(data)
		if err != nil {
			return
		}
		dir, err := file.Resources(data)
		if err != nil {
			if dir != nil {
				t.Fatal("partial resource directory returned with error")
			}
			return
		}
		if dir == nil {
			return
		}
		if len(dir.Records) > pe.MaxResourceRecords {
			t.Fatalf("records %d exceed MaxResourceRecords", len(dir.Records))
		}
		outputBytes := 0
		for i, rec := range dir.Records {
			if len(rec.Path) == 0 || len(rec.Path) > pe.MaxResourceDepth {
				t.Fatalf("record %d path len %d out of range", i, len(rec.Path))
			}
			outputBytes += 48 + len(rec.Path)*24
			for j, comp := range rec.Path {
				if comp.Named {
					if comp.ID != 0 {
						t.Fatalf("record %d path %d named entry has ID %d", i, j, comp.ID)
					}
					if !utf8.ValidString(comp.Name) {
						t.Fatalf("record %d path %d decoded invalid UTF-8", i, j)
					}
					outputBytes += len(comp.Name)
				} else {
					if comp.Name != "" {
						t.Fatalf("record %d path %d numeric entry has Name %q", i, j, comp.Name)
					}
					if comp.ID&0x80000000 != 0 {
						t.Fatalf("record %d path %d ID %#x has high bit set", i, j, comp.ID)
					}
				}
			}
			if i == 0 || i == len(dir.Records)-1 {
				payload, err := file.ResourcePayload(data, rec)
				if err == nil && uint64(len(payload)) != uint64(rec.Size) {
					t.Fatalf("payload len %d != record Size %d", len(payload), rec.Size)
				}
			}
		}
		if outputBytes > pe.MaxResourceOutputBytes {
			t.Fatalf("outputBytes %d exceeds MaxResourceOutputBytes", outputBytes)
		}
	})
}
