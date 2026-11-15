package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestResourcesAbsentAndEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		is64 bool
	}{
		{name: "PE32", is64: false},
		{name: "PE32Plus", is64: true},
	} {
		t.Run(tc.name+"/Absent", func(t *testing.T) {
			data := testfixture.Minimal(tc.is64, 1)
			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			got, err := f.Resources(data)
			if err != nil || got != nil {
				t.Fatalf("Resources() = (%+v, %v), want (nil, nil)", got, err)
			}
		})

		t.Run(tc.name+"/TooFewDataDirectories", func(t *testing.T) {
			data := testfixture.Minimal(tc.is64, 1)
			dirCountOff := 244
			if tc.is64 {
				dirCountOff = 260
			}
			binary.LittleEndian.PutUint32(data[dirCountOff:], pe.DataDirectoryResource)
			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			got, err := f.Resources(data)
			if err != nil || got != nil {
				t.Fatalf("Resources() = (%+v, %v), want (nil, nil)", got, err)
			}
		})

		t.Run(tc.name+"/EmptyRoot", func(t *testing.T) {
			data := testfixture.Resources(tc.is64, &testfixture.ResourceNodeSpec{
				Characteristics: 0x01020304,
				TimeDateStamp:   0x55667788,
				MajorVersion:    3,
				MinorVersion:    1,
			})
			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			got, err := f.Resources(data)
			if err != nil {
				t.Fatalf("Resources() error = %v", err)
			}
			want := &pe.ResourceDirectory{
				Characteristics: 0x01020304,
				TimeDateStamp:   0x55667788,
				MajorVersion:    3,
				MinorVersion:    1,
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Resources() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestResourcesPathsUTF16AndOwnership(t *testing.T) {
	for _, tc := range []struct {
		name string
		is64 bool
	}{
		{name: "PE32", is64: false},
		{name: "PE32Plus", is64: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &testfixture.ResourceNodeSpec{
				TimeDateStamp: 0x11223344,
				MajorVersion:  4,
				MinorVersion:  2,
				Entries: []testfixture.ResourceEntrySpec{
					// Depth 1: named root entry with UTF-16 BMP + supplementary plane (emoji).
					{
						Named: true,
						Name:  "Icon-\U0001F680",
						Subdir: &testfixture.ResourceNodeSpec{
							Entries: []testfixture.ResourceEntrySpec{
								// Empty named entry distinct from ID 0.
								{
									Named: true,
									Name:  "",
									Subdir: &testfixture.ResourceNodeSpec{
										Entries: []testfixture.ResourceEntrySpec{
											{
												ID: 1033,
												Leaf: &testfixture.ResourceLeafSpec{
													Payload:  []byte("icon-en"),
													CodePage: 1200,
													Reserved: 7,
												},
											},
										},
									},
								},
								// Incomplete 2-level path (depth 2 leaf).
								{
									ID: 0,
									Leaf: &testfixture.ResourceLeafSpec{
										Payload:  []byte("direct-depth2"),
										CodePage: 65001,
									},
								},
							},
						},
					},
					// Invalid UTF-16 surrogates replaced with U+FFFD (ordered before ID entries).
					{
						Named:        true,
						RawNameUnits: []uint16{'A', 0xD800, 'B', 0xDC00, 0xDC01, 0xD801},
						Leaf: &testfixture.ResourceLeafSpec{
							Payload: []byte("bad-utf16"),
						},
					},
					// Incomplete 1-level path (depth 1 leaf).
					{
						ID: 16,
						Leaf: &testfixture.ResourceLeafSpec{
							Payload:  []byte("direct-depth1"),
							CodePage: 1252,
						},
					},
					// Deeper 4-level path.
					{
						ID: 24,
						Subdir: &testfixture.ResourceNodeSpec{
							Entries: []testfixture.ResourceEntrySpec{
								{
									ID: 1,
									Subdir: &testfixture.ResourceNodeSpec{
										Entries: []testfixture.ResourceEntrySpec{
											{
												ID: 1033,
												Subdir: &testfixture.ResourceNodeSpec{
													Entries: []testfixture.ResourceEntrySpec{
														{
															ID: 99,
															Leaf: &testfixture.ResourceLeafSpec{
																Payload: []byte("deep-4"),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}

			orig := testfixture.Resources(tc.is64, root)
			data := append([]byte(nil), orig...)
			f, err := pe.New(data)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			dir, err := f.Resources(data)
			if err != nil {
				t.Fatalf("Resources() error = %v", err)
			}
			if dir.NumberOfNamedEntries != 2 || dir.NumberOfIDEntries != 2 {
				t.Fatalf("counts = (%d, %d), want (2, 2)", dir.NumberOfNamedEntries, dir.NumberOfIDEntries)
			}
			if len(dir.Records) != 5 {
				t.Fatalf("len(Records) = %d, want 5", len(dir.Records))
			}

			wantPaths := [][]pe.ResourceComponent{
				{
					{Named: true, Name: "Icon-\U0001F680"},
					{Named: true, Name: ""},
					{ID: 1033},
				},
				{
					{Named: true, Name: "Icon-\U0001F680"},
					{ID: 0},
				},
				{
					{Named: true, Name: "A\ufffdB\ufffd\ufffd\ufffd"},
				},
				{
					{ID: 16},
				},
				{
					{ID: 24},
					{ID: 1},
					{ID: 1033},
					{ID: 99},
				},
			}
			wantPayloads := [][]byte{
				[]byte("icon-en"),
				[]byte("direct-depth2"),
				[]byte("bad-utf16"),
				[]byte("direct-depth1"),
				[]byte("deep-4"),
			}

			for i, rec := range dir.Records {
				if !reflect.DeepEqual(rec.Path, wantPaths[i]) {
					t.Fatalf("record[%d].Path = %+v, want %+v", i, rec.Path, wantPaths[i])
				}
				payload, err := f.ResourcePayload(data, rec)
				if err != nil {
					t.Fatalf("ResourcePayload(%d) error = %v", i, err)
				}
				if !bytes.Equal(payload, wantPayloads[i]) {
					t.Fatalf("payload[%d] = %q, want %q", i, payload, wantPayloads[i])
				}
				// Verify returned slice does not alias caller input buffer.
				payload[0] ^= 0xff
				payload2, err := f.ResourcePayload(data, rec)
				if err != nil || !bytes.Equal(payload2, wantPayloads[i]) {
					t.Fatalf("payload aliasing detected: got %q (%v)", payload2, err)
				}
			}

			if dir.Records[0].CodePage != 1200 || dir.Records[0].Reserved != 7 {
				t.Fatalf("record[0] CodePage/Reserved = (%d, %d), want (1200, 7)", dir.Records[0].CodePage, dir.Records[0].Reserved)
			}

			// Mutating caller buffer after parsing leaves previously returned records intact.
			clear(data)
			if dir.Records[0].Path[0].Name != "Icon-\U0001F680" {
				t.Fatalf("decoded name mutated after clearing data: %q", dir.Records[0].Path[0].Name)
			}

			// Second parse with restored bytes succeeds independently without caching.
			second, err := f.Resources(orig)
			if err != nil || !reflect.DeepEqual(second, dir) {
				t.Fatalf("second Resources() = (%+v, %v), want (%+v, nil)", second, err, dir)
			}
		})
	}
}

func TestResourcesCrossSectionPayloads(t *testing.T) {
	extra := append(bytes.Repeat([]byte{0xaa}, 16), []byte("cross-section-payload")...)
	root := &testfixture.ResourceNodeSpec{
		Entries: []testfixture.ResourceEntrySpec{
			{
				ID: 10,
				Leaf: &testfixture.ResourceLeafSpec{
					HasDataSectionOffset: true,
					DataSectionOffset:    16,
					HasCustomSize:        true,
					CustomSize:           uint32(len("cross-section-payload")),
					CodePage:             65001,
				},
			},
			// Raw DataRVA beyond any mapped section must still return metadata from
			// Resources(), failing only when ResourcePayload() is requested.
			{
				ID: 11,
				Leaf: &testfixture.ResourceLeafSpec{
					HasCustomRVA:    true,
					ExternalDataRVA: 0x99990000,
					HasCustomSize:   true,
					CustomSize:      32,
				},
			},
			// Empty size at mapped address returns non-nil empty payload.
			{
				ID: 12,
				Leaf: &testfixture.ResourceLeafSpec{
					HasDataSectionOffset: true,
					DataSectionOffset:    0,
					HasCustomSize:        true,
					CustomSize:           0,
				},
			},
		},
	}

	data := testfixture.ResourcesWithDataSection(true, root, extra)
	f, err := pe.New(data)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	dir, err := f.Resources(data)
	if err != nil {
		t.Fatalf("Resources() error = %v", err)
	}
	if len(dir.Records) != 3 {
		t.Fatalf("len(Records) = %d, want 3", len(dir.Records))
	}

	got, err := f.ResourcePayload(data, dir.Records[0])
	if err != nil || string(got) != "cross-section-payload" {
		t.Fatalf("ResourcePayload(cross-section) = (%q, %v)", got, err)
	}

	if bad, err := f.ResourcePayload(data, dir.Records[1]); !errors.Is(err, pe.ErrOutOfBounds) || bad != nil {
		t.Fatalf("ResourcePayload(unmapped) = (%v, %v), want (nil, ErrOutOfBounds)", bad, err)
	}

	empty, err := f.ResourcePayload(data, dir.Records[2])
	if err != nil || len(empty) != 0 {
		t.Fatalf("ResourcePayload(empty) = (%v, %v), want ([], nil)", empty, err)
	}

	// Extending CustomSize past the end of .data raw size fails with ErrOutOfBounds.
	over := dir.Records[0]
	over.Size = uint32(len(f.Sections[1].Name) + int(f.Sections[1].SizeOfRawData))
	if got, err := f.ResourcePayload(data, over); !errors.Is(err, pe.ErrOutOfBounds) || got != nil {
		t.Fatalf("ResourcePayload(past section) = (%v, %v), want (nil, ErrOutOfBounds)", got, err)
	}
}

func TestResourcesInvalidFileState(t *testing.T) {
	var nilFile *pe.File
	if dir, err := nilFile.Resources(nil); !errors.Is(err, pe.ErrInvalidHeader) || dir != nil {
		t.Fatalf("nil.Resources = (%v, %v), want (nil, ErrInvalidHeader)", dir, err)
	}
	if buf, err := nilFile.ResourcePayload(nil, pe.ResourceRecord{}); !errors.Is(err, pe.ErrInvalidHeader) || buf != nil {
		t.Fatalf("nil.ResourcePayload = (%v, %v), want (nil, ErrInvalidHeader)", buf, err)
	}

	zero := &pe.File{}
	if dir, err := zero.Resources(nil); !errors.Is(err, pe.ErrInvalidHeader) || dir != nil {
		t.Fatalf("zero.Resources = (%v, %v), want (nil, ErrInvalidHeader)", dir, err)
	}

	tooManySecs, err := pe.New(testfixture.Minimal(false, 1))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tooManySecs.Sections = make([]pe.Section, pe.MaxSections+1)
	if dir, err := tooManySecs.Resources(nil); !errors.Is(err, pe.ErrSectionLimit) || dir != nil {
		t.Fatalf("tooManySecs.Resources = (%v, %v), want (nil, ErrSectionLimit)", dir, err)
	}
	if buf, err := tooManySecs.ResourcePayload(nil, pe.ResourceRecord{}); !errors.Is(err, pe.ErrSectionLimit) || buf != nil {
		t.Fatalf("tooManySecs.ResourcePayload = (%v, %v), want (nil, ErrSectionLimit)", buf, err)
	}
}
