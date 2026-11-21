package pe_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"sync"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRichHeaderPE32AndPE64(t *testing.T) {
	entries := []testfixture.RichEntrySpec{
		{ToolID: 0x0001, Version: 0x0000, Count: 0},
		{ToolID: 0x00ff, Version: 0x766f, Count: 1},
		{ToolID: 0x0104, Version: 0x725d, Count: 31},
		{ToolID: 0x0104, Version: 0x725d, Count: 32},
		{ToolID: 0xffff, Version: 0xffff, Count: math.MaxUint32},
	}

	for _, is64 := range []bool{false, true} {
		data, wantChecksum := testfixture.RichPE(is64, testfixture.RichOptions{
			Entries: entries,
		})
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}

		snapshot := append([]byte(nil), data...)
		rh, err := f.RichHeader(data)
		if err != nil {
			t.Fatalf("PE64=%t RichHeader err=%v", is64, err)
		}
		if rh == nil {
			t.Fatalf("PE64=%t RichHeader returned nil", is64)
		}
		if rh.Offset != 0x80 || rh.RichOffset != int64(0x80+16+len(entries)*8) || rh.Length != int64(16+len(entries)*8) {
			t.Fatalf("PE64=%t unexpected offsets: %+v", is64, rh)
		}
		if rh.Key != wantChecksum || rh.ComputedChecksum != wantChecksum || !rh.ChecksumValid {
			t.Fatalf("PE64=%t checksum mismatch: key=%#x computed=%#x valid=%t want=%#x", is64, rh.Key, rh.ComputedChecksum, rh.ChecksumValid, wantChecksum)
		}
		if !bytes.Equal(rh.RawData, data[rh.Offset:rh.RichOffset]) {
			t.Fatalf("PE64=%t RawData mismatch", is64)
		}
		if len(rh.ClearData) != int(rh.Length) || binary.LittleEndian.Uint32(rh.ClearData[:4]) != pe.DanSMarker {
			t.Fatalf("PE64=%t ClearData invalid", is64)
		}
		if len(rh.Entries) != len(entries) {
			t.Fatalf("PE64=%t got %d entries, want %d", is64, len(rh.Entries), len(entries))
		}
		for i, want := range entries {
			got := rh.Entries[i]
			if got.ToolID != want.ToolID || got.Version != want.Version || got.Count != want.Count {
				t.Fatalf("PE64=%t entry[%d] = %+v, want %+v", is64, i, got, want)
			}
		}

		// Returned buffers must own their bytes independently of input mutations.
		rawCopy := append([]byte(nil), rh.RawData...)
		clearCopy := append([]byte(nil), rh.ClearData...)
		data[rh.Offset] ^= 0xff
		if !bytes.Equal(rh.RawData, rawCopy) || !bytes.Equal(rh.ClearData, clearCopy) {
			t.Fatalf("PE64=%t returned slices alias caller buffer", is64)
		}
		data = snapshot

		// Zero entries (DanS + 3 zero padding DWORDs only) is valid.
		zeroData, zeroChecksum := testfixture.RichPE(is64, testfixture.RichOptions{})
		zf, err := pe.New(zeroData)
		if err != nil {
			t.Fatal(err)
		}
		zrh, err := zf.RichHeader(zeroData)
		if err != nil || zrh == nil || !zrh.ChecksumValid || zrh.ComputedChecksum != zeroChecksum || len(zrh.Entries) != 0 || zrh.Length != 16 {
			t.Fatalf("PE64=%t zero entries = (%+v, %v)", is64, zrh, err)
		}
		_ = data
	}
}

func TestRichHeaderAbsentAndChecksumMismatch(t *testing.T) {
	// Absent markers return (nil, nil).
	for _, is64 := range []bool{false, true} {
		minimal := testfixture.Minimal(is64, 1)
		f, err := pe.New(minimal)
		if err != nil {
			t.Fatal(err)
		}
		if rh, err := f.RichHeader(minimal); err != nil || rh != nil {
			t.Fatalf("minimal PE64=%t got (%+v, %v), want (nil, nil)", is64, rh, err)
		}
	}

	// Compact PE with e_lfanew == 64 (zero-byte DOS stub) and e_lfanew == 66 (2-byte DOS stub).
	for _, stub := range [][]byte{{}, {0x90, 0x90}} {
		compact := testfixture.WithDOSStub(false, nil, stub)
		f, err := pe.New(compact)
		if err != nil {
			t.Fatal(err)
		}
		if rh, err := f.RichHeader(compact); err != nil || rh != nil {
			t.Fatalf("compact stub len=%d got (%+v, %v), want (nil, nil)", len(stub), rh, err)
		}
	}

	// Custom XOR key != computed checksum returns ChecksumValid=false without error.
	entries := []testfixture.RichEntrySpec{{ToolID: 0x0093, Version: 0x520d, Count: 7}}
	mismatched, expectedChecksum := testfixture.RichPE(true, testfixture.RichOptions{
		Entries:      entries,
		UseCustomKey: true,
		CustomKey:    0xdeadbeef,
	})
	mf, err := pe.New(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := mf.RichHeader(mismatched)
	if err != nil || rh == nil {
		t.Fatalf("checksum mismatch returned (%+v, %v)", rh, err)
	}
	if rh.ChecksumValid || rh.Key != 0xdeadbeef || rh.ComputedChecksum != expectedChecksum {
		t.Fatalf("got Key=%#x Computed=%#x Valid=%t, want Valid=false Computed=%#x", rh.Key, rh.ComputedChecksum, rh.ChecksumValid, expectedChecksum)
	}

	// Modifying a pre-DanS DOS byte invalidates the checksum.
	good, goodSum := testfixture.RichPE(false, testfixture.RichOptions{Entries: entries})
	good[0x10] ^= 0x01
	gf, err := pe.New(good)
	if err != nil {
		t.Fatal(err)
	}
	grh, err := gf.RichHeader(good)
	if err != nil || grh == nil || grh.ChecksumValid || grh.Key != goodSum || grh.ComputedChecksum == goodSum {
		t.Fatalf("tampered DOS header gave (%+v, %v)", grh, err)
	}
}

func TestRichHeaderMultipleMarkersAndConcurrency(t *testing.T) {
	// Multiple "Rich" blocks in DOS stub: last "Rich" nearest e_lfanew wins,
	// matching libyara/YARA-X backward scan semantics.
	prefix1 := []byte("PRE1")
	firstBlock, _ := testfixture.EncodeRichBlock(append(make([]byte, 0x40), prefix1...), testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{{ToolID: 1, Version: 1, Count: 1}},
	})
	gap := []byte("GAP!")
	secondPrefix := append(append(append([]byte(nil), prefix1...), firstBlock...), gap...)
	dos := make([]byte, 0x40)
	dos[0], dos[1] = 'M', 'Z'
	dosAndPrefix2 := append(append([]byte(nil), dos...), secondPrefix...)
	secondBlock, secondChecksum := testfixture.EncodeRichBlock(dosAndPrefix2, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{{ToolID: 2, Version: 3, Count: 4}},
	})
	data := testfixture.WithDOSStub(true, dos, append(append([]byte(nil), secondPrefix...), secondBlock...))
	// Recompute checksum check against exact DOS bytes copied into WithDOSStub:
	// copy e_lfanew-less 0x3c..0x40 zeros aren't used, and first 0x3c bytes came from Minimal,
	// so verify offset/key/entries cleanly using RichHeader and a second manual check:
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	_ = secondChecksum

	// Also verify nested DanS ^ key earlier inside the same block selects nearest backward DanS.
	key := uint32(0x11223344)
	nestedStub := make([]byte, 0, 64)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, pe.DanSMarker^key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	// Inner DanS ^ key at +16 followed by 3 zero DWORDs and 1 entry.
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, pe.DanSMarker^key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, (uint32(9)<<16|uint32(5))^key)
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, 12^key)
	nestedStub = append(nestedStub, 'R', 'i', 'c', 'h')
	nestedStub = binary.LittleEndian.AppendUint32(nestedStub, key)
	nestedPE := testfixture.WithDOSStub(false, nil, nestedStub)
	nf, err := pe.New(nestedPE)
	if err != nil {
		t.Fatal(err)
	}
	nrh, err := nf.RichHeader(nestedPE)
	if err != nil || nrh == nil || nrh.Offset != 0x40+16 || len(nrh.Entries) != 1 || nrh.Entries[0].ToolID != 9 {
		t.Fatalf("nearest DanS = (%+v, %v)", nrh, err)
	}

	// Verify multi-Rich picks the last "Rich" block (starting right after secondPrefix).
	rh, err := f.RichHeader(data)
	if err != nil || rh == nil {
		t.Fatalf("multi-Rich = (%+v, %v)", rh, err)
	}
	wantOff := int64(0x40 + len(secondPrefix))
	if rh.Offset != wantOff || len(rh.Entries) != 1 || rh.Entries[0].ToolID != 2 || rh.Entries[0].Version != 3 || rh.Entries[0].Count != 4 {
		t.Fatalf("multi-Rich selected wrong block: %+v (want offset %d)", rh, wantOff)
	}

	// Verify concurrent reads remain race-free without mutating File.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, err := f.RichHeader(data)
			if err != nil || got == nil || got.Offset != wantOff || len(got.Entries) != 1 {
				t.Errorf("concurrent RichHeader = (%+v, %v)", got, err)
			}
		})
	}
	wg.Wait()
}

func TestRichHeaderNonZeroPadding(t *testing.T) {
	// Per erocarrera/pefile#394 and VirusTotal/yara@4793b49, real Microsoft
	// binaries can have non-zero uninitialized bytes in the 12-byte padding
	// after "DanS".
	for _, pad := range [][3]uint32{{1, 0, 0}, {0, 0, 0xdead}} {
		data, wantChecksum := testfixture.RichPE(true, testfixture.RichOptions{
			Padding: pad,
			Entries: []testfixture.RichEntrySpec{{ToolID: 0x0104, Version: 0x725d, Count: 5}},
		})
		f, err := pe.New(data)
		if err != nil {
			t.Fatal(err)
		}
		rh, err := f.RichHeader(data)
		if err != nil {
			t.Fatalf("pad=%v RichHeader err = %v", pad, err)
		}
		if !rh.PaddingNonZero || len(rh.Entries) != 1 || rh.Entries[0].Count != 5 {
			t.Fatalf("pad=%v got %+v", pad, rh)
		}
		if rh.ComputedChecksum != wantChecksum || !rh.ChecksumValid {
			t.Fatalf("pad=%v checksum mismatch: got (%#x, %t), want %#x", pad, rh.ComputedChecksum, rh.ChecksumValid, wantChecksum)
		}
	}
}
