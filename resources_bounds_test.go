package pe_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestResourcesTruncationSweep(t *testing.T) {
	for _, tc := range []struct {
		name string
		is64 bool
	}{
		{name: "PE32", is64: false},
		{name: "PE32Plus", is64: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &testfixture.ResourceNodeSpec{
				Entries: []testfixture.ResourceEntrySpec{
					{
						Named: true,
						Name:  "TYPE_A",
						Subdir: &testfixture.ResourceNodeSpec{
							Entries: []testfixture.ResourceEntrySpec{
								{
									ID: 1,
									Leaf: &testfixture.ResourceLeafSpec{
										Payload: []byte("hello-world-payload"),
									},
								},
							},
						},
					},
				},
			}
			data := testfixture.Resources(tc.is64, root)
			full, err := pe.New(data)
			if err != nil {
				t.Fatalf("New(full) error = %v", err)
			}
			fullDir, err := full.Resources(data)
			if err != nil || len(fullDir.Records) != 1 {
				t.Fatalf("full.Resources() = (%+v, %v)", fullDir, err)
			}

			// New(short) must fail Resources(full) when the resource table extends past short's fileSize.
			rsrcStart := int(full.Sections[0].PointerToRawData)
			short, err := pe.New(data[:rsrcStart+8])
			if err != nil {
				t.Fatalf("New(short) error = %v", err)
			}
			if got, err := short.Resources(data); !errors.Is(err, pe.ErrOutOfBounds) || got != nil {
				t.Fatalf("short.Resources(full) = (%v, %v), want (nil, ErrOutOfBounds)", got, err)
			}

			metaEnd := rsrcStart + int(full.OptionalHeader.DataDirectories[pe.DataDirectoryResource].Size) - len("hello-world-payload")
			for n := range len(data) {
				prefix := data[:n]
				if n < metaEnd {
					if parsed, err := pe.New(prefix); err == nil {
						if got, err := parsed.Resources(prefix); !errors.Is(err, pe.ErrOutOfBounds) || got != nil {
							t.Fatalf("truncate %d/%d: parsed.Resources() = (%v, %v), want (nil, ErrOutOfBounds)", n, len(data), got, err)
						}
					}
					if got, err := full.Resources(prefix); !errors.Is(err, pe.ErrOutOfBounds) || got != nil {
						t.Fatalf("truncate %d/%d: full.Resources() = (%v, %v), want (nil, ErrOutOfBounds)", n, len(data), got, err)
					}
				}
				// Truncation anywhere before payload end fails ResourcePayload.
				payloadEnd := metaEnd + len("hello-world-payload")
				if n < payloadEnd {
					if buf, err := full.ResourcePayload(prefix, fullDir.Records[0]); !errors.Is(err, pe.ErrOutOfBounds) || buf != nil {
						t.Fatalf("truncate %d/%d: full.ResourcePayload() = (%v, %v), want (nil, ErrOutOfBounds)", n, len(data), buf, err)
					}
				}
			}
		})
	}
}

func TestResourcesMalformedAndOverflow(t *testing.T) {
	t.Run("IncompleteDirectory", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			rva  uint32
			size uint32
		}{
			{name: "ZeroRVANonZeroSize", rva: 0, size: 32},
			{name: "NonZeroRVAZeroSize", rva: 0x1000, size: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				data := testfixture.Minimal(true, 1)
				dirOff := testfixture.ResourceDirOffset(true)
				binary.LittleEndian.PutUint32(data[dirOff:], tc.rva)
				binary.LittleEndian.PutUint32(data[dirOff+4:], tc.size)
				f, err := pe.New(data)
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				if got, err := f.Resources(data); !errors.Is(err, pe.ErrInvalidResource) || got != nil {
					t.Fatalf("Resources() = (%v, %v), want (nil, ErrInvalidResource)", got, err)
				}
			})
		}
	})

	t.Run("DirectorySmallerThanHeader", func(t *testing.T) {
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{})
		dirOff := testfixture.ResourceDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 15)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrInvalidResource) || got != nil {
			t.Fatalf("Resources() = (%v, %v), want (nil, ErrInvalidResource)", got, err)
		}
	})

	t.Run("DirectoryExtentOverflow", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		dirOff := testfixture.ResourceDirOffset(true)
		binary.LittleEndian.PutUint32(data[dirOff:], 0xfffffff0)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 0x20)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrIntegerOverflow) || got != nil {
			t.Fatalf("Resources() = (%v, %v), want (nil, ErrIntegerOverflow)", got, err)
		}
	})

	t.Run("RootRelativeOverflow", func(t *testing.T) {
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{ID: 1, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("ok")}},
			},
		})
		// Place root directory near top of 32-bit RVA space so high-offset entry wraps.
		sec0 := testfixture.ResourceSectionOffset(true, 0)
		dirOff := testfixture.ResourceDirOffset(true)
		binary.LittleEndian.PutUint32(data[sec0+12:], 0xfffff000)
		binary.LittleEndian.PutUint32(data[dirOff:], 0xfffff000)
		binary.LittleEndian.PutUint32(data[dirOff+4:], 0x100)
		// Entry 0 OffsetToData -> root-relative offset 0x00020000 (overflows 0xfffff000 + 0x20000).
		binary.LittleEndian.PutUint32(data[512+16+4:], 0x00020000)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrIntegerOverflow) || got != nil {
			t.Fatalf("Resources() = (%v, %v), want (nil, ErrIntegerOverflow)", got, err)
		}
	})

	t.Run("RootRelativeOutsideDirSize", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			edit func([]byte)
		}{
			{
				name: "EntryTableExceedsDirSize",
				edit: func(d []byte) {
					dirOff := testfixture.ResourceDirOffset(true)
					binary.LittleEndian.PutUint32(d[dirOff+4:], 20) // room for header + half of 1st entry
				},
			},
			{
				name: "SubdirOutsideDirSize",
				edit: func(d []byte) {
					binary.LittleEndian.PutUint32(d[512+16+4:], 0x80000400)
				},
			},
			{
				name: "NameOffsetOutsideDirSize",
				edit: func(d []byte) {
					binary.LittleEndian.PutUint32(d[512+16:], 0x80000400)
				},
			},
			{
				name: "DataEntryOutsideDirSize",
				edit: func(d []byte) {
					binary.LittleEndian.PutUint32(d[512+16+4:], 0x00000400)
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{
					Entries: []testfixture.ResourceEntrySpec{
						{Named: true, Name: "X", Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("p")}},
					},
				})
				tc.edit(data)
				f, err := pe.New(data)
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				if got, err := f.Resources(data); !errors.Is(err, pe.ErrInvalidResource) || got != nil {
					t.Fatalf("Resources() = (%v, %v), want (nil, ErrInvalidResource)", got, err)
				}
			})
		}
	})

	t.Run("PayloadRVAAithmeticOverflow", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		rec := pe.ResourceRecord{
			DataRVA: 0xfffffffe,
			Size:    8,
		}
		if buf, err := f.ResourcePayload(data, rec); !errors.Is(err, pe.ErrIntegerOverflow) || buf != nil {
			t.Fatalf("ResourcePayload() = (%v, %v), want (nil, ErrIntegerOverflow)", buf, err)
		}
	})
}

func TestResourcesCyclesAndSharedSubtrees(t *testing.T) {
	t.Run("RootSelfCycle", func(t *testing.T) {
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{ID: 1, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("x")}},
			},
		})
		// Point root entry 0 back to root (directory bit set, offset 0).
		binary.LittleEndian.PutUint32(data[512+16+4:], 0x80000000)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrInvalidResource) || got != nil {
			t.Fatalf("Resources() = (%v, %v), want (nil, ErrInvalidResource)", got, err)
		}
	})

	t.Run("DeepCycle", func(t *testing.T) {
		// Root (0) -> Child1 (0x18) -> Child2 (0x30) -> back to Child1 (0x18).
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{
					ID: 1,
					Subdir: &testfixture.ResourceNodeSpec{
						Entries: []testfixture.ResourceEntrySpec{
							{
								ID: 2,
								Subdir: &testfixture.ResourceNodeSpec{
									Entries: []testfixture.ResourceEntrySpec{
										{ID: 3, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("ok")}},
									},
								},
							},
						},
					},
				},
			},
		})
		child1Offset := binary.LittleEndian.Uint32(data[512+16+4:]) & 0x7fffffff
		child2Offset := binary.LittleEndian.Uint32(data[512+int(child1Offset)+16+4:]) & 0x7fffffff
		// Repoint Child2's entry 0 back to Child1.
		binary.LittleEndian.PutUint32(data[512+int(child2Offset)+16+4:], 0x80000000|child1Offset)

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrInvalidResource) || got != nil {
			t.Fatalf("Resources() = (%v, %v), want (nil, ErrInvalidResource)", got, err)
		}
	})

	t.Run("SharedSubtreeDAG", func(t *testing.T) {
		sharedLang := &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{ID: 1033, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("shared-en")}},
			},
		}
		root := &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{ID: 1, Subdir: sharedLang},
				{ID: 2, Subdir: sharedLang},
			},
		}
		data := testfixture.Resources(true, root)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		dir, err := f.Resources(data)
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(dir.Records) != 2 {
			t.Fatalf("len(Records) = %d, want 2", len(dir.Records))
		}
		if dir.Records[0].Path[0].ID != 1 || dir.Records[1].Path[0].ID != 2 {
			t.Fatalf("unexpected shared paths: %+v", dir.Records)
		}
		if dir.Records[0].DataRVA != dir.Records[1].DataRVA {
			t.Fatalf("shared leaf DataRVA mismatch: %#x vs %#x", dir.Records[0].DataRVA, dir.Records[1].DataRVA)
		}
	})

	t.Run("DiamondDAGBombRejected", func(t *testing.T) {
		// 15 levels of 2-edge diamonds = 2^15 = 32768 logical paths, exceeding
		// MaxResourceNodes and MaxResourceRecords cleanly in <1MB of PE data.
		leaf := &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{ID: 1033, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("x")}},
			},
		}
		cur := leaf
		for range 14 {
			cur = &testfixture.ResourceNodeSpec{
				Entries: []testfixture.ResourceEntrySpec{
					{ID: 1, Subdir: cur},
					{ID: 2, Subdir: cur},
				},
			}
		}
		data := testfixture.Resources(true, cur)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("Resources() = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})
}

func TestResourcesLimits(t *testing.T) {
	t.Run("MaxDepthExactAndExceeded", func(t *testing.T) {
		buildChain := func(depth int) []byte {
			cur := &testfixture.ResourceNodeSpec{
				Entries: []testfixture.ResourceEntrySpec{
					{ID: uint32(depth), Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("ok")}},
				},
			}
			for d := depth - 1; d >= 1; d-- {
				cur = &testfixture.ResourceNodeSpec{
					Entries: []testfixture.ResourceEntrySpec{
						{ID: uint32(d), Subdir: cur},
					},
				}
			}
			return testfixture.Resources(true, cur)
		}

		atLimit := buildChain(pe.MaxResourceDepth)
		f, err := pe.New(atLimit)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		dir, err := f.Resources(atLimit)
		if err != nil || len(dir.Records) != 1 || len(dir.Records[0].Path) != pe.MaxResourceDepth {
			t.Fatalf("at max depth: (%+v, %v)", dir, err)
		}

		overLimit := buildChain(pe.MaxResourceDepth + 1)
		f2, err := pe.New(overLimit)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f2.Resources(overLimit); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over max depth: (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxEntriesExceeded", func(t *testing.T) {
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{})
		// Set NumberOfIDEntries = MaxResourceEntries + 1 in root header.
		binary.LittleEndian.PutUint16(data[512+14:], pe.MaxResourceEntries+1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourceEntries = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxNodesExceeded", func(t *testing.T) {
		// One shared empty subdirectory referenced MaxResourceNodes times from root -> 1 root + 8192 = 8193 nodes.
		emptyChild := &testfixture.ResourceNodeSpec{}
		entries := make([]testfixture.ResourceEntrySpec, pe.MaxResourceNodes)
		for i := range entries {
			entries[i] = testfixture.ResourceEntrySpec{ID: uint32(i + 1), Subdir: emptyChild}
		}
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{Entries: entries})
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourceNodes = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxRecordsExceeded", func(t *testing.T) {
		sharedSubdir := &testfixture.ResourceNodeSpec{
			Entries: make([]testfixture.ResourceEntrySpec, 256),
		}
		for i := range sharedSubdir.Entries {
			sharedSubdir.Entries[i] = testfixture.ResourceEntrySpec{
				ID:   uint32(i + 1),
				Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("a")},
			}
		}
		// 65 * 256 = 16640 > MaxResourceRecords (16384), while total entries = 65 + 65*256 = 16705 <= MaxResourceEntries.
		rootEntries := make([]testfixture.ResourceEntrySpec, 65)
		for i := range rootEntries {
			rootEntries[i] = testfixture.ResourceEntrySpec{ID: uint32(i + 1), Subdir: sharedSubdir}
		}
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{Entries: rootEntries})
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourceRecords = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxNameUnitsExceeded", func(t *testing.T) {
		longName := strings.Repeat("A", pe.MaxResourceNameUnits+1)
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{Named: true, Name: longName, Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("x")}},
			},
		})
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourceNameUnits = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxStringUnitsExceededViaSharedName", func(t *testing.T) {
		// Repeat a 2048-unit named entry 65 times -> 133120 > MaxResourceStringUnits (131072).
		name := strings.Repeat("Z", pe.MaxResourceNameUnits)
		entries := make([]testfixture.ResourceEntrySpec, (pe.MaxResourceStringUnits/pe.MaxResourceNameUnits)+1)
		for i := range entries {
			entries[i] = testfixture.ResourceEntrySpec{
				Named: true,
				Name:  name,
				Leaf:  &testfixture.ResourceLeafSpec{Payload: []byte("x")},
			}
		}
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{Entries: entries})
		// Point all entry name offsets to entry 0's name so PE file stays tiny while string reads accumulate.
		firstName := binary.LittleEndian.Uint32(data[512+16:])
		for i := range entries {
			binary.LittleEndian.PutUint32(data[512+16+i*8:], firstName)
		}
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourceStringUnits = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxOutputBytesExceeded", func(t *testing.T) {
		// Parent named entry with 2048 3-byte UTF-8 runes (6144 UTF-8 bytes) repeated across
		// 700 numeric children = > 4 MiB output bytes, while only decoding the 2048-unit name once.
		units := make([]uint16, pe.MaxResourceNameUnits)
		for i := range units {
			units[i] = 0x4e2d // CJK rune -> 3 UTF-8 bytes
		}
		children := make([]testfixture.ResourceEntrySpec, 700)
		for i := range children {
			children[i] = testfixture.ResourceEntrySpec{
				ID:   uint32(i + 1),
				Leaf: &testfixture.ResourceLeafSpec{Payload: []byte("x")},
			}
		}
		data := testfixture.Resources(true, &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{
					Named:        true,
					RawNameUnits: units,
					Subdir:       &testfixture.ResourceNodeSpec{Entries: children},
				},
			},
		})
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if got, err := f.Resources(data); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourceOutputBytes = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})

	t.Run("MaxPayloadBytesExceeded", func(t *testing.T) {
		data := testfixture.Minimal(true, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		rec := pe.ResourceRecord{
			DataRVA: 0x1000,
			Size:    pe.MaxResourcePayloadBytes + 1,
		}
		if got, err := f.ResourcePayload(data, rec); !errors.Is(err, pe.ErrResourceLimit) || got != nil {
			t.Fatalf("over MaxResourcePayloadBytes = (%v, %v), want (nil, ErrResourceLimit)", got, err)
		}
	})
}
