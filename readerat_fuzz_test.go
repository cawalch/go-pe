package pe_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzNewFromReaderAt(f *testing.F) {
	f.Add(testfixture.Minimal(false, 2), uint8(16))
	f.Add(testfixture.Minimal(true, 2), uint8(32))
	f.Add([]byte("MZ\x00\x00"), uint8(1))

	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		if len(data) > pe.MaxReaderAtHeaderBytes {
			return
		}
		maxChunk := int(chunk)
		if maxChunk == 0 {
			maxChunk = 64
		}

		// Compare against New([]byte) when headers fit within MaxReaderAtReads.
		byteFile, byteErr := pe.New(data)
		rFile, rErr := pe.NewFromReaderAt(&chunkedReaderAt{
			data:      data,
			maxChunk:  maxChunk,
			eofOnLast: chunk%2 == 0,
		}, int64(len(data)))

		if byteErr == nil && rErr == nil {
			if !reflect.DeepEqual(rFile, byteFile) {
				t.Fatalf("NewFromReaderAt != New")
			}
		}

		// Also verify standard bytes.Reader agrees with New([]byte) on valid PEs.
		if byteErr == nil {
			directFile, directErr := pe.NewFromReaderAt(bytes.NewReader(data), int64(len(data)))
			if directErr != nil {
				t.Fatalf("New succeeded but NewFromReaderAt(bytes.Reader) failed: %v", directErr)
			}
			if !reflect.DeepEqual(directFile, byteFile) {
				t.Fatalf("NewFromReaderAt(bytes.Reader) != New")
			}
		}
	})
}
