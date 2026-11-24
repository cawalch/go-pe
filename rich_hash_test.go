package pe_test

import (
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRichHeaderMD5(t *testing.T) {
	var nilRich *pe.RichHeader
	if nilRich.MD5() != "" {
		t.Fatalf("nil RichHeader MD5 should be empty")
	}

	empty := &pe.RichHeader{}
	if empty.MD5() != "" {
		t.Fatalf("empty RichHeader MD5 should be empty")
	}

	data, _ := testfixture.RichPE(true, testfixture.RichOptions{
		Entries: []testfixture.RichEntrySpec{
			{ToolID: 0x0104, Version: 0x725d, Count: 3},
		},
	})
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := f.RichHeader(data)
	if err != nil {
		t.Fatal(err)
	}

	wantMD5 := md5.Sum(rh.ClearData)
	if got := rh.MD5(); got != hex.EncodeToString(wantMD5[:]) {
		t.Fatalf("MD5() = %q, want %q", got, hex.EncodeToString(wantMD5[:]))
	}
}
