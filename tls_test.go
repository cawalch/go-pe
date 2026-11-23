package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestTLSDirectoryPE32AndPE64(t *testing.T) {
	// Missing TLS directory returns nil, nil.
	minData := testfixture.Minimal(true, 1)
	fMin, err := pe.New(minData)
	if err != nil {
		t.Fatal(err)
	}
	if tls, err := fMin.TLS(minData); err != nil || tls != nil {
		t.Fatalf("missing TLS = (%+v, %v), want (nil, nil)", tls, err)
	}

	for _, is64 := range []bool{false, true} {
		data := testfixture.Minimal(is64, 1)
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		secOff := int(f.Sections[0].PointerToRawData)
		secRVA := f.Sections[0].VirtualAddress
		base := f.OptionalHeader.ImageBase

		// Place TLS directory at secRVA+0, callback array at secRVA+64.
		dirOff := 152 + 96 + pe.DataDirectoryTLS*8
		if is64 {
			dirOff = 152 + 112 + pe.DataDirectoryTLS*8
		}
		cbArrayVA := base + uint64(secRVA+64)
		cb1VA := base + uint64(secRVA+0x100)
		cb2VA := base + uint64(secRVA+0x140)

		if is64 {
			binary.LittleEndian.PutUint32(data[dirOff:], secRVA)
			binary.LittleEndian.PutUint32(data[dirOff+4:], 40)
			binary.LittleEndian.PutUint64(data[secOff+24:], cbArrayVA)
			binary.LittleEndian.PutUint64(data[secOff+64:], cb1VA)
			binary.LittleEndian.PutUint64(data[secOff+72:], cb2VA)
			binary.LittleEndian.PutUint64(data[secOff+80:], 0)
		} else {
			binary.LittleEndian.PutUint32(data[dirOff:], secRVA)
			binary.LittleEndian.PutUint32(data[dirOff+4:], 24)
			binary.LittleEndian.PutUint32(data[secOff+12:], uint32(cbArrayVA))
			binary.LittleEndian.PutUint32(data[secOff+64:], uint32(cb1VA))
			binary.LittleEndian.PutUint32(data[secOff+68:], uint32(cb2VA))
			binary.LittleEndian.PutUint32(data[secOff+72:], 0)
		}

		f2, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		tls, err := f2.TLS(data)
		if err != nil {
			t.Fatalf("PE64=%t TLS err=%v", is64, err)
		}
		if len(tls.Callbacks) != 2 || tls.Callbacks[0] != cb1VA || tls.Callbacks[1] != cb2VA {
			t.Fatalf("PE64=%t Callbacks = %v, want [%#x %#x]", is64, tls.Callbacks, cb1VA, cb2VA)
		}
		if len(tls.CallbackRVAs) != 2 || tls.CallbackRVAs[0] != secRVA+0x100 || tls.CallbackRVAs[1] != secRVA+0x140 {
			t.Fatalf("PE64=%t CallbackRVAs = %v", is64, tls.CallbackRVAs)
		}

		// Short TLS directory returns ErrInvalidTLS.
		binary.LittleEndian.PutUint32(data[dirOff+4:], 8)
		fBad, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fBad.TLS(data); !errors.Is(err, pe.ErrInvalidTLS) {
			t.Fatalf("PE64=%t short TLS err = %v, want ErrInvalidTLS", is64, err)
		}
	}
}
