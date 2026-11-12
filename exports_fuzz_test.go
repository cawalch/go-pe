package pe

import (
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe/internal/testfixture"
)

func FuzzExports(f *testing.F) {
	for _, is64 := range []bool{false, true} {
		data := testfixture.Exports(is64, 3)
		f.Add(is64, false, data)
		f.Add(is64, true, data[512:])
		// Alias and forwarder seeds reach branches ordinary names don't exercise.
		binary.LittleEndian.PutUint16(data[exportTableOffset(data, 36)+2:], 0)
		binary.LittleEndian.PutUint32(data[552:], binary.LittleEndian.Uint32(data[exportTableOffset(data, 32):]))
		f.Add(is64, true, data[512:])
	}
	f.Add(false, false, []byte("MZ"))
	f.Add(true, false, buildMinimalPE(1))
	f.Add(true, true, []byte{})
	f.Fuzz(func(t *testing.T, is64, payloadOnly bool, data []byte) {
		if payloadOnly {
			if uint64(len(data)) > 1<<32-1 {
				return
			}
			header := testfixture.Exports(is64, 1)[:512]
			section, directory := exportSectionOffset(is64), exportDirectoryOffset(is64)
			binary.LittleEndian.PutUint32(header[section+8:], uint32(len(data)))
			binary.LittleEndian.PutUint32(header[section+16:], uint32(len(data)))
			binary.LittleEndian.PutUint32(header[directory+4:], uint32(len(data)))
			data = append(header[:512:512], data...)
		}
		file, err := New(data)
		if err != nil {
			return
		}
		exports, err := file.Exports(data)
		if err != nil {
			if exports != nil {
				t.Fatal("partial exports returned with error")
			}
			return
		}
		if exports == nil {
			return
		}
		if len(exports.Symbols) > MaxExportSymbols {
			t.Fatal("unbounded address table")
		}
		names, strings := 0, 0
		checkString := func(s string) {
			if len(s) >= MaxExportNameBytes {
				t.Fatal("unbounded string")
			}
			strings += len(s) + 1
		}
		if exports.DLL != "" {
			checkString(exports.DLL)
		}
		dir := file.OptionalHeader.DataDirectories[0]
		for i, s := range exports.Symbols {
			if uint64(s.Ordinal) != uint64(exports.OrdinalBase)+uint64(i) {
				t.Fatal("ordinal wrapped")
			}
			forwarded := uint64(s.RVA) >= uint64(dir.VirtualAddress) && uint64(s.RVA) < uint64(dir.VirtualAddress)+uint64(dir.Size)
			if s.Forwarded != forwarded || !s.Forwarded && s.Forwarder != "" {
				t.Fatal("invalid forwarder classification")
			}
			if s.Forwarded {
				checkString(s.Forwarder)
			}
			names += len(s.Names)
			for _, name := range s.Names {
				checkString(name)
			}
		}
		if names > MaxExportNames || strings > MaxExportStringBytes {
			t.Fatal("unbounded export output")
		}
	})
}
