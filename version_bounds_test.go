package pe_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestParseVersionInfoValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		wantErr error
	}{
		{name: "nil", payload: nil, wantErr: pe.ErrInvalidVersionInfo},
		{name: "short_header", payload: make([]byte, 5), wantErr: pe.ErrInvalidVersionInfo},
		{
			name: "root_length_too_small",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key:          "VS_VERSION_INFO",
				HasCustomLen: true,
				CustomLength: 4,
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "root_truncated",
			payload: func() []byte {
				b := testfixture.StandardVersionPayload(1)
				return b[:len(b)-1]
			}(),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "wrong_root_key",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key:  "NOT_VERSION_INFO",
				Type: 1,
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "unterminated_root_key",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key:        "VS_VERSION_INFO",
				OmitKeyNUL: true,
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "odd_byte_unterminated_key",
			payload: func() []byte {
				b := make([]byte, 15)
				binary.LittleEndian.PutUint16(b[0:2], 15)
				return b
			}(),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "fixed_info_bad_type",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key:        "VS_VERSION_INFO",
				Type:       pe.VersionValueText,
				ValueBytes: make([]byte, 26), // 26 * 2 = 52 bytes if treated as units
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "fixed_info_too_short",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key:        "VS_VERSION_INFO",
				Type:       pe.VersionValueBinary,
				ValueBytes: make([]byte, 51),
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "fixed_info_bad_signature",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key:        "VS_VERSION_INFO",
				Type:       pe.VersionValueBinary,
				ValueBytes: make([]byte, 52),
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "unsupported_wtype",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{Key: "StringFileInfo", Type: 2},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "string_file_info_with_value",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{Key: "StringFileInfo", Type: 0, ValueBytes: []byte{1, 2, 3, 4}},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "string_table_with_value",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{
						Key: "StringFileInfo",
						Children: []testfixture.VersionNodeSpec{
							{Key: "040904B0", Type: 0, ValueBytes: []byte{1, 2}},
						},
					},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "string_value_units_overrun",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{
						Key: "StringFileInfo",
						Children: []testfixture.VersionNodeSpec{
							{
								Key: "040904B0",
								Children: []testfixture.VersionNodeSpec{
									// 4 bytes present, wValueLength=4 units (8 bytes required).
									{Key: "FileVersion", Type: 1, ValueBytes: []byte{'1', 0, 0, 0}, HasCustomValLn: true, CustomValLn: 4},
								},
							},
						},
					},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "string_unexpected_trailing_bytes",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{
						Key: "StringFileInfo",
						Children: []testfixture.VersionNodeSpec{
							{
								Key: "040904B0",
								Children: []testfixture.VersionNodeSpec{
									{Key: "Nested", Type: 1, TextValue: "ok", HasTextValue: true, Children: []testfixture.VersionNodeSpec{{Key: "Child", Type: 1}}},
								},
							},
						},
					},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "child_extends_past_parent",
			payload: func() []byte {
				b := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
					Key: "VS_VERSION_INFO",
					Children: []testfixture.VersionNodeSpec{
						{Key: "VarFileInfo", Type: 1, HasCustomLen: true, CustomLength: 100},
					},
				})
				return b
			}(),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "truncated_child_gap_inside_container",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{Key: "VarFileInfo", Type: 1, ValueBytes: nil, HasCustomLen: true, CustomLength: 34}, // header(6) + key(24) = 30 -> 4 bytes left (< 6)
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "var_file_info_with_value",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{Key: "VarFileInfo", Type: 0, ValueBytes: []byte{1, 2}},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "malformed_translation_non_multiple_of_4",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{
						Key: "VarFileInfo",
						Children: []testfixture.VersionNodeSpec{
							{Key: "Translation", Type: 0, ValueBytes: []byte{0x09, 0x04}},
						},
					},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
		{
			name: "malformed_translation_text_type",
			payload: testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
				Key: "VS_VERSION_INFO",
				Children: []testfixture.VersionNodeSpec{
					{
						Key: "VarFileInfo",
						Children: []testfixture.VersionNodeSpec{
							{Key: "Translation", Type: 1, TextValue: "1234", HasTextValue: true},
						},
					},
				},
			}),
			wantErr: pe.ErrInvalidVersionInfo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vi, err := pe.ParseVersionInfo(tc.payload)
			if !errors.Is(err, tc.wantErr) || vi != nil {
				t.Fatalf("ParseVersionInfo() = (%+v, %v), want (%v)", vi, err, tc.wantErr)
			}
		})
	}
}

func TestParseVersionInfoLimits(t *testing.T) {
	t.Run("MaxVersionPayloadBytes", func(t *testing.T) {
		huge := make([]byte, pe.MaxVersionPayloadBytes+1)
		if _, err := pe.ParseVersionInfo(huge); !errors.Is(err, pe.ErrVersionInfoLimit) {
			t.Fatalf("expected ErrVersionInfoLimit, got %v", err)
		}
	})

	t.Run("MaxVersionNameUnits", func(t *testing.T) {
		longKey := strings.Repeat("K", pe.MaxVersionNameUnits+1)
		p := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
			Key: "VS_VERSION_INFO",
			Children: []testfixture.VersionNodeSpec{
				{Key: longKey, Type: 0},
			},
		})
		if _, err := pe.ParseVersionInfo(p); !errors.Is(err, pe.ErrVersionInfoLimit) {
			t.Fatalf("expected ErrVersionInfoLimit, got %v", err)
		}
	})

	t.Run("MaxVersionValueUnits", func(t *testing.T) {
		p := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
			Key: "VS_VERSION_INFO",
			Children: []testfixture.VersionNodeSpec{
				{
					Key: "StringFileInfo",
					Children: []testfixture.VersionNodeSpec{
						{
							Key: "040904B0",
							Children: []testfixture.VersionNodeSpec{
								{Key: "Big", Type: 1, HasCustomValLn: true, CustomValLn: pe.MaxVersionValueUnits + 1},
							},
						},
					},
				},
			},
		})
		if _, err := pe.ParseVersionInfo(p); !errors.Is(err, pe.ErrVersionInfoLimit) {
			t.Fatalf("expected ErrVersionInfoLimit, got %v", err)
		}
	})

	t.Run("MaxVersionTables", func(t *testing.T) {
		var sfiChildren []testfixture.VersionNodeSpec
		for range pe.MaxVersionTables + 1 {
			sfiChildren = append(sfiChildren, testfixture.VersionNodeSpec{Key: "040904B0", Type: 1})
		}
		p := buildUnboundedVersionTree("StringFileInfo", sfiChildren)
		if _, err := pe.ParseVersionInfo(p); !errors.Is(err, pe.ErrVersionInfoLimit) {
			t.Fatalf("expected ErrVersionInfoLimit, got %v", err)
		}
	})

	t.Run("MaxVersionStrings", func(t *testing.T) {
		entries := make([]testfixture.VersionNodeSpec, pe.MaxVersionStrings+1)
		for i := range entries {
			entries[i] = testfixture.VersionNodeSpec{Key: "A", Type: 1}
		}
		p := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
			Key: "VS_VERSION_INFO",
			Children: []testfixture.VersionNodeSpec{
				{
					Key: "StringFileInfo",
					Children: []testfixture.VersionNodeSpec{
						{Key: "040904B0", Type: 1, Children: entries},
					},
				},
			},
		})
		if _, err := pe.ParseVersionInfo(p); !errors.Is(err, pe.ErrVersionInfoLimit) {
			t.Fatalf("expected ErrVersionInfoLimit, got %v", err)
		}
	})

	t.Run("MaxVersionTranslations", func(t *testing.T) {
		pairs := make([]byte, (pe.MaxVersionTranslations+1)*4)
		p := buildUnboundedVersionTree("VarFileInfo", []testfixture.VersionNodeSpec{
			{Key: "Translation", Type: 0, ValueBytes: pairs},
		})
		if _, err := pe.ParseVersionInfo(p); !errors.Is(err, pe.ErrVersionInfoLimit) {
			t.Fatalf("expected ErrVersionInfoLimit, got %v", err)
		}
	})
}

// buildUnboundedVersionTree emits a VS_VERSION_INFO payload whose root length can
// stay within uint16 by keeping child counts below 64 KiB, or exercises multi-table limits.
func buildUnboundedVersionTree(containerKey string, children []testfixture.VersionNodeSpec) []byte {
	return testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
		Key: "VS_VERSION_INFO",
		Children: []testfixture.VersionNodeSpec{
			{Key: containerKey, Type: 1, Children: children},
		},
	})
}
