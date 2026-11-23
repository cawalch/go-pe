package pe_test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func TestRichHeaderHashes(t *testing.T) {
	var nilRich *pe.RichHeader
	if nilRich.MD5() != "" || nilRich.SHA256() != "" {
		t.Fatalf("nil RichHeader hashes should be empty")
	}

	empty := &pe.RichHeader{}
	if empty.MD5() != "" || empty.SHA256() != "" {
		t.Fatalf("empty RichHeader hashes should be empty")
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
	wantSHA := sha256.Sum256(rh.ClearData)
	if got := rh.MD5(); got != hex.EncodeToString(wantMD5[:]) {
		t.Fatalf("MD5() = %q, want %q", got, hex.EncodeToString(wantMD5[:]))
	}
	if got := rh.SHA256(); got != hex.EncodeToString(wantSHA[:]) {
		t.Fatalf("SHA256() = %q, want %q", got, hex.EncodeToString(wantSHA[:]))
	}
}
