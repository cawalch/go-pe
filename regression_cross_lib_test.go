package pe_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

// Regression for golang/go#81219: PE32 import lookup table ending with a
// 4-byte terminal thunk at the exact end of the section/file must succeed.
func TestRegressionPE32ExactTerminalImportThunk(t *testing.T) {
	data := testfixture.Imports(false, 1, 1)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	dir := f.OptionalHeader.DataDirectories[pe.DataDirectoryImport]
	descOff, ok := f.RVAToOffset(dir.VirtualAddress)
	if !ok {
		t.Fatal("missing import directory offset")
	}
	iltRVA := binary.LittleEndian.Uint32(data[descOff:])
	iltOff, ok := f.RVAToOffset(iltRVA)
	if !ok {
		t.Fatal("missing ILT offset")
	}
	// Copy the 8-byte ILT (1 entry + 4-byte 0 terminator) to the exact end of
	// the file/section so the 4-byte terminal thunk sits at the exact section/file boundary.
	eLfanew := int(f.DOSHeader.AddressOfNewEXEHeader)
	secOff := eLfanew + 24 + int(f.FileHeader.SizeOfOptionalHeader)
	lastIdx := f.NumberOfSections() - 1
	lastSec := f.Sections[lastIdx]
	newILTRVA := lastSec.VirtualAddress + lastSec.SizeOfRawData
	extended := make([]byte, len(data)+8)
	copy(extended, data)
	copy(extended[len(data):], data[iltOff:iltOff+8])
	binary.LittleEndian.PutUint32(extended[descOff:], newILTRVA)
	newSize := lastSec.SizeOfRawData + 8
	binary.LittleEndian.PutUint32(extended[secOff+lastIdx*40+8:], newSize)
	binary.LittleEndian.PutUint32(extended[secOff+lastIdx*40+16:], newSize)

	tf, err := pe.New(extended)
	if err != nil {
		t.Fatal(err)
	}
	libs, err := tf.Imports(extended)
	if err != nil {
		t.Fatalf("Imports with exact 4-byte terminal thunk failed: %v", err)
	}
	if len(libs) != 1 || len(libs[0].Symbols) != 1 {
		t.Fatalf("got %+v, want 1 library with 1 symbol", libs)
	}
}

// Regression for VirusTotal/yara#2242: empty or NULL EncapContentInfo in
// Authenticode SignedData must not panic during parsing or verification.
func TestRegressionEmptyEncapContentInfo(t *testing.T) {
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	type signedData struct {
		Version          int
		DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
		EncapContentInfo contentInfo
		SignerInfos      asn1.RawValue `asn1:"set"`
	}

	sdBytes, err := asn1.Marshal(signedData{
		Version: 1,
		EncapContentInfo: contentInfo{
			ContentType: pe.OIDSpcIndirectDataContent,
		},
		SignerInfos: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkcs7DER, err := asn1.Marshal(contentInfo{
		ContentType: pe.OIDSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdBytes},
	})
	if err != nil {
		t.Fatal(err)
	}

	sigs, err := pe.ParseAuthenticodeSignatures(pkcs7DER)
	if err != nil {
		t.Fatalf("ParseAuthenticodeSignatures: %v", err)
	}
	if len(sigs) != 1 || sigs[0].IndirectData != nil {
		t.Fatalf("unexpected sigs: %+v", sigs)
	}

	base := testfixture.MinimalAligned(true)
	f, err := pe.New(base)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := f.VerifyAuthenticodeSignatures(base, sigs, pe.AuthenticodeVerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyAuthenticodeSignatures: %v", err)
	}
	if len(ver.Signatures) != 1 || ver.Signatures[0].Digest.Status != pe.AuthenticodeStatusInvalid {
		t.Fatalf("expected invalid digest for missing SpcIndirectDataContent, got %+v", ver)
	}
}

// Regression for erocarrera/pefile#435: 4-byte UTF-16 surrogate pairs in
// VS_VERSION_INFO keys and values must decode cleanly.
func TestRegressionVersionInfoUTF16SurrogatePairs(t *testing.T) {
	const emoji = "App \U0001F600 v1"
	payload := testfixture.BuildVersionNode(testfixture.VersionNodeSpec{
		Key:        "VS_VERSION_INFO",
		Type:       pe.VersionValueBinary,
		ValueBytes: make([]byte, 52),
		Children: []testfixture.VersionNodeSpec{
			{
				Key:  "StringFileInfo",
				Type: pe.VersionValueText,
				Children: []testfixture.VersionNodeSpec{
					{
						Key:  "040904b0",
						Type: pe.VersionValueText,
						Children: []testfixture.VersionNodeSpec{
							{
								Key:          "FileDescription",
								Type:         pe.VersionValueText,
								TextValue:    emoji,
								HasTextValue: true,
							},
						},
					},
				},
			},
		},
	})
	// Patch VS_FIXEDFILEINFO dwSignature (0xFEEF04BD) after the 6-byte header + UTF-16Z "VS_VERSION_INFO\0" (32 bytes) aligned to 4 -> offset 40.
	binary.LittleEndian.PutUint32(payload[40:], pe.VersionFixedInfoSignature)

	vi, err := pe.ParseVersionInfo(payload)
	if err != nil {
		t.Fatalf("ParseVersionInfo: %v", err)
	}
	if len(vi.StringTables) != 1 || len(vi.StringTables[0].Entries) != 1 {
		t.Fatalf("unexpected StringTables: %+v", vi.StringTables)
	}
	if got := vi.StringTables[0].Entries[0].Value; got != emoji {
		t.Fatalf("FileDescription = %q, want %q", got, emoji)
	}
}

// Regression for erocarrera/pefile#465: resource-only PE DLLs (no code,
// AddressOfEntryPoint == 0, no imports) must parse resources cleanly.
func TestRegressionResourceOnlyPE(t *testing.T) {
	data := testfixture.ResourcesSimple(true, 2)
	f, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	optOff := int(f.DOSHeader.AddressOfNewEXEHeader) + 24
	// Zero out SizeOfCode and AddressOfEntryPoint to model a resource-only DLL.
	binary.LittleEndian.PutUint32(data[optOff+4:], 0)
	binary.LittleEndian.PutUint32(data[optOff+16:], 0)

	rf, err := pe.New(data)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rf.Resources(data)
	if err != nil {
		t.Fatalf("Resources on resource-only PE: %v", err)
	}
	if res == nil || len(res.Records) != 2 {
		t.Fatalf("got %+v, want 2 resource records", res)
	}
	if imps, err := rf.Imports(data); err != nil || imps != nil {
		t.Fatalf("Imports = (%+v, %v), want (nil, nil)", imps, err)
	}
}
