package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

type chunkedReaderAt struct {
	data      []byte
	maxChunk  int
	eofOnLast bool
}

func (c *chunkedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(c.data)) {
		return 0, io.EOF
	}
	n := len(p)
	if c.maxChunk > 0 && n > c.maxChunk {
		n = c.maxChunk
	}
	avail := int64(len(c.data)) - off
	if int64(n) > avail {
		n = int(avail)
	}
	copy(p[:n], c.data[off:off+int64(n)])
	if c.eofOnLast && off+int64(n) == int64(len(c.data)) {
		return n, io.EOF
	}
	return n, nil
}

type stalledReaderAt struct{}

func (stalledReaderAt) ReadAt([]byte, int64) (int, error) {
	return 0, nil
}

func TestNewFromReaderAtEquivalence(t *testing.T) {
	gorootOut, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	goroot := strings.TrimSpace(string(gorootOut))
	files := []string{
		filepath.Join(goroot, "src", "debug", "pe", "testdata", "gcc-386-mingw-exec"),
		filepath.Join(goroot, "src", "debug", "pe", "testdata", "gcc-amd64-mingw-exec"),
		filepath.Join(goroot, "src", "debug", "pe", "testdata", "gcc-386-mingw-no-symbols-exec"),
		filepath.Join(goroot, "src", "debug", "pe", "testdata", "vmlinuz-4.15.0-47-generic"),
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want, err := pe.New(data)
			if err != nil {
				t.Fatal(err)
			}

			got, err := pe.NewFromReaderAt(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("NewFromReaderAt: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("NewFromReaderAt != New:\ngot:  %+v\nwant: %+v", got, want)
			}
		})
	}

	// Sparse 128 MiB file on disk.
	base := testfixture.Minimal(true, 2)
	largePath := filepath.Join(t.TempDir(), "large.exe")
	fh, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.Write(base); err != nil {
		t.Fatal(err)
	}
	const largeSize = 128 << 20
	if err := fh.Truncate(largeSize); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}

	rf, err := os.Open(largePath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pe.NewFromReaderAt(rf, largeSize)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("NewFromReaderAt(128MiB): %v", err)
	}
	if got.FileSize() != largeSize || got.NumberOfSections() != 2 {
		t.Fatalf("got FileSize=%d Sections=%d", got.FileSize(), got.NumberOfSections())
	}
}

func TestNewFromReaderAtShortReadsErrorsAndLimits(t *testing.T) {
	if _, err := pe.NewFromReaderAt(nil, 100); !errors.Is(err, pe.ErrInvalidHeader) {
		t.Fatalf("nil ReaderAt err = %v, want ErrInvalidHeader", err)
	}
	if _, err := pe.NewFromReaderAt(bytes.NewReader(make([]byte, 63)), 63); !errors.Is(err, pe.ErrShortDOS) {
		t.Fatalf("short size err = %v, want ErrShortDOS", err)
	}
	if _, err := pe.NewFromReaderAt(stalledReaderAt{}, 128); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("stalled reader err = %v, want io.ErrUnexpectedEOF", err)
	}

	data := testfixture.Minimal(true, 2)
	// Chunked short reads (16 bytes at a time, plus io.EOF on last byte).
	got, err := pe.NewFromReaderAt(&chunkedReaderAt{data: data, maxChunk: 16, eofOnLast: true}, int64(len(data)))
	if err != nil {
		t.Fatalf("chunked short reads failed: %v", err)
	}
	want, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chunked NewFromReaderAt != New")
	}

	// 1-byte chunks exceed MaxReaderAtReads (1024) on a >1 KiB header.
	bigHeader := append(append([]byte(nil), data...), make([]byte, 2048)...)
	eLfanew := int(binary.LittleEndian.Uint32(bigHeader[60:64]))
	binary.LittleEndian.PutUint16(bigHeader[eLfanew+20:], 2048) // large SizeOfOptionalHeader
	if _, err := pe.NewFromReaderAt(&chunkedReaderAt{data: bigHeader, maxChunk: 1}, int64(len(bigHeader))); !errors.Is(err, pe.ErrReaderAtLimit) {
		t.Fatalf("1-byte chunk read budget err = %v, want ErrReaderAtLimit", err)
	}
}
