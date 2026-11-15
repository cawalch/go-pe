package pe_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestDelayImportsValidationAndMalformed(t *testing.T) {
	var nilFile *pe.File
	if got, err := nilFile.DelayImports(nil); got != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil.DelayImports() = (%+v, %v), want ErrInvalidHeader", got, err)
	}
	zero := &pe.File{}
	if got, err := zero.DelayImports(nil); got != nil || !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("zero.DelayImports() = (%+v, %v), want ErrInvalidHeader", got, err)
	}

	dirOff64 := 264 + 13*8
	cases := []struct {
		name  string
		build func() []byte
		want  error
	}{
		{
			name: "IncompleteDirZeroVA",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[dirOff64:], 0)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "IncompleteDirZeroSize",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[dirOff64+4:], 0)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "DirectoryArithmeticOverflow",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[dirOff64:], 0xfffffff0)
				binary.LittleEndian.PutUint32(d[dirOff64+4:], 32)
				return d
			},
			want: pe.ErrIntegerOverflow,
		},
		{
			name: "MissingDirectoryTerminator",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[dirOff64+4:], 32)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "UnsupportedAttributeBits",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[512:], 2)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "VAModeUnsupportedOnPE64",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[512:], 0)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "DescriptorVABelowImageBase",
			build: func() []byte {
				d := testfixture.DelayImportsWithAttributes(false, 0, 1, 1)
				binary.LittleEndian.PutUint32(d[512+4:], 0x1000) // < 0x400000 ImageBase
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "ThunkVABelowImageBase",
			build: func() []byte {
				d := testfixture.DelayImportsWithAttributes(false, 0, 1, 1)
				intRVA := binary.LittleEndian.Uint32(d[512+16:]) - 0x400000
				binary.LittleEndian.PutUint32(d[512+intRVA-0x1000:], 0x2000)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "BoundWithoutNameTable",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[512+16:], 0)
				binary.LittleEndian.PutUint32(d[512+28:], 1)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "MissingDLLAndLookup",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				binary.LittleEndian.PutUint32(d[512+4:], 0)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "ReservedOrdinalBits",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				intRVA := binary.LittleEndian.Uint32(d[512+16:])
				binary.LittleEndian.PutUint64(d[512+intRVA-0x1000:], (1<<63)|0x10000)
				return d
			},
			want: pe.ErrInvalidDelayImport,
		},
		{
			name: "UnterminatedSymbolName",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				intRVA := binary.LittleEndian.Uint32(d[512+16:])
				hintNameOff := 512 + int(binary.LittleEndian.Uint64(d[512+intRVA-0x1000:])-0x1000)
				long := len(d)
				d = append(d, 0, 0)
				d = append(d, strings.Repeat("z", pe.MaxDelayImportNameBytes)...)
				binary.LittleEndian.PutUint32(d[400:], uint32(len(d)-512))
				binary.LittleEndian.PutUint32(d[408:], uint32(len(d)-512))
				_ = hintNameOff
				binary.LittleEndian.PutUint64(d[512+intRVA-0x1000:], uint64(long-512)+0x1000)
				return d
			},
			want: pe.ErrUnterminatedString,
		},
		{
			name: "MissingRawBytesTruncatedTable",
			build: func() []byte {
				d := testfixture.DelayImports(true, 1, 1)
				// Truncate mid-way through the 32-byte terminator descriptor.
				return d[:512+60]
			},
			want: pe.ErrOutOfBounds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build()
			f, err := pe.New(data)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.DelayImports(data)
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("DelayImports() = (%+v, %v), want %v", got, err, tc.want)
			}
		})
	}

	// Prefix length shorter than last symbol's hint/name record triggers ErrOutOfBounds cleanly.
	full := testfixture.DelayImports(true, 1, 2)
	int0 := int(binary.LittleEndian.Uint32(full[512+16:])-0x1000) + 512
	name1RVA := uint32(binary.LittleEndian.Uint64(full[int0+8:]))
	name1Off := int(name1RVA-0x1000) + 512
	trunc := full[:name1Off+4]
	tf, err := pe.NewWithLength(trunc, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tf.DelayImports(trunc); got != nil || !errors.Is(err, pe.ErrOutOfBounds) && !errors.Is(err, pe.ErrUnterminatedString) {
		t.Fatalf("truncated DelayImports() = (%+v, %v), want ErrOutOfBounds/ErrUnterminatedString", got, err)
	}
}

func TestDelayImportsLimits(t *testing.T) {
	// Library count limit: exact succeeds, +1 fails with ErrDelayImportLimit.
	atLib := testfixture.DelayImports(true, pe.MaxDelayImportLibraries, 0)
	f, err := pe.New(atLib)
	if err != nil {
		t.Fatal(err)
	}
	libs, err := f.DelayImports(atLib)
	if err != nil || len(libs) != pe.MaxDelayImportLibraries {
		t.Fatalf("exact MaxDelayImportLibraries = (%d, %v)", len(libs), err)
	}

	overLib := testfixture.DelayImports(true, pe.MaxDelayImportLibraries+1, 0)
	f, err = pe.New(overLib)
	if err != nil {
		t.Fatal(err)
	}
	if libs, err := f.DelayImports(overLib); libs != nil || !errors.Is(err, pe.ErrDelayImportLimit) {
		t.Fatalf("over MaxDelayImportLibraries = (%+v, %v), want ErrDelayImportLimit", libs, err)
	}

	// Cumulative symbol limit across 2 libraries.
	overSyms := testfixture.DelayImports(true, 2, pe.MaxDelayImportSymbols/2+1)
	f, err = pe.New(overSyms)
	if err != nil {
		t.Fatal(err)
	}
	if libs, err := f.DelayImports(overSyms); libs != nil || !errors.Is(err, pe.ErrDelayImportLimit) {
		t.Fatalf("over MaxDelayImportSymbols = (%+v, %v), want ErrDelayImportLimit", libs, err)
	}

	// Cumulative string byte budget across repeated references.
	big := testfixture.DelayImports(true, 1, 257)
	int0 := int(binary.LittleEndian.Uint32(big[512+16:])-0x1000) + 512
	long := len(big)
	big = append(big, 0, 0)
	big = append(big, strings.Repeat("x", pe.MaxDelayImportNameBytes-1)...)
	big = append(big, 0)
	remaining := pe.MaxDelayImportStringBytes - len("a00.dll") - 1 - 255*pe.MaxDelayImportNameBytes + 1
	short := len(big)
	big = append(big, 0, 0)
	big = append(big, strings.Repeat("y", remaining-1)...)
	big = append(big, 0)
	for i := range 255 {
		binary.LittleEndian.PutUint64(big[int0+i*8:], uint64(long-512)+0x1000)
	}
	binary.LittleEndian.PutUint64(big[int0+255*8:], uint64(short-512)+0x1000)
	binary.LittleEndian.PutUint64(big[int0+256*8:], 0)
	binary.LittleEndian.PutUint32(big[400:], uint32(len(big)-512))
	binary.LittleEndian.PutUint32(big[408:], uint32(len(big)-512))

	f, err = pe.New(big)
	if err != nil {
		t.Fatal(err)
	}
	if libs, err := f.DelayImports(big); libs != nil || !errors.Is(err, pe.ErrDelayImportLimit) {
		t.Fatalf("over string budget = (%+v, %v), want ErrDelayImportLimit", libs, err)
	}
}
