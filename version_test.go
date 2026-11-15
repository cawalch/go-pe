package pe_test

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestParseVersionInfoEndToEndAndOrder(t *testing.T) {
	ffi := make([]byte, 52)
	binary.LittleEndian.PutUint32(ffi[0:4], pe.VersionFixedInfoSignature)
	binary.LittleEndian.PutUint32(ffi[4:8], 0x00010000)
	binary.LittleEndian.PutUint32(ffi[8:12], 0x00010002)
	binary.LittleEndian.PutUint32(ffi[12:16], 0x00030004)
	binary.LittleEndian.PutUint32(ffi[16:20], 0x00050006)
	binary.LittleEndian.PutUint32(ffi[20:24], 0x00070008)
	binary.LittleEndian.PutUint32(ffi[24:28], 0x0000003f)
	binary.LittleEndian.PutUint32(ffi[28:32], 0x00000001)
	binary.LittleEndian.PutUint32(ffi[32:36], 0x00040004)
	binary.LittleEndian.PutUint32(ffi[36:40], 0x00000001)
	binary.LittleEndian.PutUint32(ffi[40:44], 0x00000002)
	binary.LittleEndian.PutUint32(ffi[44:48], 0x11112222)
	binary.LittleEndian.PutUint32(ffi[48:52], 0x33334444)

	payload := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
		Key:        "VS_VERSION_INFO",
		Type:       0,
		ValueBytes: ffi,
		Children: []testfixture.VersionNodeSpec{
			{
				Key:  "StringFileInfo",
				Type: 1,
				Children: []testfixture.VersionNodeSpec{
					{
						Key:  "040904B0",
						Type: 1,
						Children: []testfixture.VersionNodeSpec{
							{Key: "CompanyName", Type: 1, TextValue: "Example Corp", HasTextValue: true},
							{Key: "CompanyName", Type: 1, TextValue: "Duplicate Corp", HasTextValue: true},
							{Key: "EmptyOmitted", Type: 1},
							{Key: "EmptyPadded", Type: 1, PadInsideNode: true},
							{Key: "EmptyNUL", Type: 1, TextValue: "", HasTextValue: true},
							{Key: "UntermValue", Type: 1, TextValue: "no-nul", HasTextValue: true, OmitTextNUL: true},
							{Key: "Ünicode🔑", Type: 1, TextValue: "Café 🚀", HasTextValue: true},
							{Key: "UnpairedSurrogate", Type: 1, ValueBytes: []byte{0x00, 0xd8, 'A', 0x00, 0x00, 0x00}, HasCustomValLn: true, CustomValLn: 3},
						},
					},
					{
						Key:  "040C04B0",
						Type: 1,
						Children: []testfixture.VersionNodeSpec{
							{Key: "FileDescription", Type: 1, TextValue: "Outil français", HasTextValue: true},
						},
					},
				},
			},
			{
				Key:  "StringFileInfo",
				Type: 1,
				Children: []testfixture.VersionNodeSpec{
					{
						Key:  "040704E4",
						Type: 1,
						Children: []testfixture.VersionNodeSpec{
							{Key: "ProductName", Type: 1, TextValue: "SecondBlock", HasTextValue: true},
						},
					},
				},
			},
			{
				Key:  "VarFileInfo",
				Type: 1,
				Children: []testfixture.VersionNodeSpec{
					{
						Key:        "Translation",
						Type:       0,
						ValueBytes: []byte{0x09, 0x04, 0xb0, 0x04, 0x0c, 0x04, 0xb0, 0x04},
					},
					{
						Key:        "Translation",
						Type:       0,
						ValueBytes: []byte{0x07, 0x04, 0xe4, 0x04},
					},
					{
						Key:        "CustomVar",
						Type:       0,
						ValueBytes: []byte{0xde, 0xad, 0xbe, 0xef},
					},
				},
			},
			{
				Key:        "CustomExtension",
				Type:       0,
				ValueBytes: []byte{1, 2, 3},
			},
		},
	})
	// Append alignment zero padding after root wLength, matching resource sections.
	padded := append(append([]byte(nil), payload...), make([]byte, 8)...)

	for _, is64 := range []bool{false, true} {
		image := testfixture.Resources(is64, &testfixture.ResourceNodeSpec{
			Entries: []testfixture.ResourceEntrySpec{
				{
					ID: 16,
					Subdir: &testfixture.ResourceNodeSpec{
						Entries: []testfixture.ResourceEntrySpec{
							{
								ID: 1,
								Subdir: &testfixture.ResourceNodeSpec{
									Entries: []testfixture.ResourceEntrySpec{
										{ID: 1033, Leaf: &testfixture.ResourceLeafSpec{Payload: padded}},
									},
								},
							},
						},
					},
				},
			},
		})

		f, err := pe.New(image)
		if err != nil {
			t.Fatalf("pe.New(%t): %v", is64, err)
		}
		dir, err := f.Resources(image)
		if err != nil || len(dir.Records) != 1 {
			t.Fatalf("Resources(%t): (%+v, %v)", is64, dir, err)
		}
		extracted, err := f.ResourcePayload(image, dir.Records[0])
		if err != nil {
			t.Fatalf("ResourcePayload(%t): %v", is64, err)
		}
		backup := slices.Clone(extracted)

		vi, err := pe.ParseVersionInfo(extracted)
		if err != nil {
			t.Fatalf("ParseVersionInfo(%t): %v", is64, err)
		}
		clear(extracted)

		if !vi.HasFixedInfo {
			t.Fatalf("expected HasFixedInfo=true")
		}
		wantFFI := pe.FixedFileInfo{
			Signature:        pe.VersionFixedInfoSignature,
			StrucVersion:     0x00010000,
			FileVersionMS:    0x00010002,
			FileVersionLS:    0x00030004,
			ProductVersionMS: 0x00050006,
			ProductVersionLS: 0x00070008,
			FileFlagsMask:    0x0000003f,
			FileFlags:        0x00000001,
			FileOS:           0x00040004,
			FileType:         0x00000001,
			FileSubtype:      0x00000002,
			FileDateMS:       0x11112222,
			FileDateLS:       0x33334444,
		}
		if vi.FixedInfo != wantFFI {
			t.Fatalf("FixedInfo = %+v, want %+v", vi.FixedInfo, wantFFI)
		}

		wantTables := []pe.VersionStringTable{
			{
				Key: "040904B0",
				Entries: []pe.VersionString{
					{Key: "CompanyName", Value: "Example Corp"},
					{Key: "CompanyName", Value: "Duplicate Corp"},
					{Key: "EmptyOmitted", Value: ""},
					{Key: "EmptyPadded", Value: ""},
					{Key: "EmptyNUL", Value: ""},
					{Key: "UntermValue", Value: "no-nul"},
					{Key: "Ünicode🔑", Value: "Café 🚀"},
					{Key: "UnpairedSurrogate", Value: "\ufffdA"},
				},
			},
			{
				Key: "040C04B0",
				Entries: []pe.VersionString{
					{Key: "FileDescription", Value: "Outil français"},
				},
			},
			{
				Key: "040704E4",
				Entries: []pe.VersionString{
					{Key: "ProductName", Value: "SecondBlock"},
				},
			},
		}
		if !slices.EqualFunc(vi.StringTables, wantTables, func(a, b pe.VersionStringTable) bool {
			return a.Key == b.Key && slices.Equal(a.Entries, b.Entries)
		}) {
			t.Fatalf("StringTables = %+v, want %+v", vi.StringTables, wantTables)
		}

		wantTrans := []pe.VersionTranslation{
			{LanguageID: 0x0409, CodePage: 0x04b0},
			{LanguageID: 0x040c, CodePage: 0x04b0},
			{LanguageID: 0x0407, CodePage: 0x04e4},
		}
		if !slices.Equal(vi.Translations, wantTrans) {
			t.Fatalf("Translations = %+v, want %+v", vi.Translations, wantTrans)
		}

		if len(vi.Vars) != 3 || vi.Vars[2].Key != "CustomVar" || !bytes.Equal(vi.Vars[2].RawValue, []byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Fatalf("Vars = %+v", vi.Vars)
		}
		if len(vi.UnknownBlocks) != 1 || vi.UnknownBlocks[0].Key != "CustomExtension" || !bytes.Equal(vi.UnknownBlocks[0].RawValue, []byte{1, 2, 3}) {
			t.Fatalf("UnknownBlocks = %+v", vi.UnknownBlocks)
		}

		// Re-parse unpadded input to ensure caller clears didn't corrupt backup.
		vi2, err := pe.ParseVersionInfo(backup[:len(payload)])
		if err != nil || len(vi2.StringTables) != 3 {
			t.Fatalf("re-parse unpadded = (%+v, %v)", vi2, err)
		}
	}
}

func TestParseVersionInfoWithoutFixedInfoOrChildren(t *testing.T) {
	bare := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
		Key:  "VS_VERSION_INFO",
		Type: 1,
	})
	vi, err := pe.ParseVersionInfo(bare)
	if err != nil {
		t.Fatalf("bare VS_VERSION_INFO: %v", err)
	}
	if vi.HasFixedInfo || len(vi.StringTables) != 0 || len(vi.Translations) != 0 || len(vi.Vars) != 0 || len(vi.UnknownBlocks) != 0 {
		t.Fatalf("unexpected bare result: %+v", vi)
	}

	emptyContainers := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
		Key:  "VS_VERSION_INFO",
		Type: 0,
		Children: []testfixture.VersionNodeSpec{
			{Key: "StringFileInfo", Type: 1, Children: []testfixture.VersionNodeSpec{{Key: "040904B0", Type: 1}}},
			{Key: "VarFileInfo", Type: 1},
		},
	})
	vi, err = pe.ParseVersionInfo(emptyContainers)
	if err != nil {
		t.Fatalf("empty containers: %v", err)
	}
	if len(vi.StringTables) != 1 || vi.StringTables[0].Key != "040904B0" || len(vi.StringTables[0].Entries) != 0 {
		t.Fatalf("StringTables = %+v", vi.StringTables)
	}
}
