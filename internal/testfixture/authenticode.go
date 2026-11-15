package testfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

var (
	oidSignedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256                = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidContentType           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidCountersignature      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidTSTInfo               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSpcIndirectData       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcOpusInfo           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidSpcPEImageData        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidNestedSignature       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidAuthenticodeTimestamp = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo cmsContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type cmsSpcIndirectData struct {
	Data struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"optional"`
	}
	MessageDigest struct {
		DigestAlgorithm pkix.AlgorithmIdentifier
		Digest          []byte
	}
}

type cmsTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      time.Time `asn1:"generalized"`
}

// AuthenticodeOptions customizes synthetic signed CMS blobs built by [AuthenticodeBlob].
type AuthenticodeOptions struct {
	CommonName           string
	Serial               *big.Int
	DigestAlgorithmOID   asn1.ObjectIdentifier
	SigAlgorithmOID      asn1.ObjectIdentifier
	SigningTime          time.Time
	ProgramName          string
	MoreInfoURL          string
	IncludeCertificate   bool
	SecondSigner         bool
	DuplicateSigningTime bool
	UnknownAttrOID       asn1.ObjectIdentifier
	PKCS9CountersignAt   time.Time
	RFC3161TimestampAt   time.Time
	NestedBlobs          [][]byte
	ExtraCertificates    int
}

// AuthenticodeBlob builds a realistic DER-encoded PKCS#7 SignedData payload
// containing SpcIndirectDataContent, SignerInfo, optional certificates,
// authenticated/unauthenticated attributes, timestamps, and nested signatures.
func AuthenticodeBlob(opts AuthenticodeOptions) ([]byte, *x509.Certificate) {
	cn := opts.CommonName
	if cn == "" {
		cn = "Test Authenticode Signer"
	}
	serial := opts.Serial
	if serial == nil {
		serial = big.NewInt(0x123456)
	}
	digestOID := opts.DigestAlgorithmOID
	if len(digestOID) == 0 {
		digestOID = oidSHA256
	}
	sigOID := opts.SigAlgorithmOID
	if len(sigOID) == 0 {
		sigOID = oidECDSAWithSHA256
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Example Corp"}},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}

	imageDigest := sha256.Sum256([]byte("synthetic-pe-image"))
	indirect := cmsSpcIndirectData{}
	indirect.Data.Type = oidSpcPEImageData
	indirect.MessageDigest.DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: digestOID}
	indirect.MessageDigest.Digest = imageDigest[:]
	indirectDER, err := asn1.Marshal(indirect)
	if err != nil {
		panic(err)
	}

	signerInfosBytes := marshalSignerInfo(key, cert, imageDigest[:], digestOID, sigOID, opts)
	if opts.SecondSigner {
		second := AuthenticodeOptions{
			SigningTime: opts.SigningTime.Add(time.Hour),
		}
		signerInfosBytes = append(signerInfosBytes, marshalSignerInfo(key, cert, imageDigest[:], digestOID, sigOID, second)...)
	}

	var certBytes []byte
	if opts.IncludeCertificate {
		certBytes = append(certBytes, certDER...)
	}
	for range opts.ExtraCertificates {
		certBytes = append(certBytes, certDER...)
	}

	sd := cmsSignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestOID}},
		EncapContentInfo: cmsContentInfo{
			ContentType: oidSpcIndirectData,
			Content:     mustExplicitTag0(indirectDER),
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      signerInfosBytes,
		},
	}
	if len(certBytes) > 0 {
		sd.Certificates = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		}
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		panic(err)
	}
	ciDER, err := asn1.Marshal(cmsContentInfo{
		ContentType: oidSignedData,
		Content:     mustExplicitTag0(sdDER),
	})
	if err != nil {
		panic(err)
	}
	return ciDER, cert
}

func marshalSignerInfo(key *ecdsa.PrivateKey, cert *x509.Certificate, digest []byte, digestOID, sigOID asn1.ObjectIdentifier, opts AuthenticodeOptions) []byte {
	var authAttrs []byte
	appendAttr := func(dst *[]byte, oid asn1.ObjectIdentifier, valDERs ...[]byte) {
		var vals []asn1.RawValue
		for _, v := range valDERs {
			var rv asn1.RawValue
			if _, err := asn1.Unmarshal(v, &rv); err != nil {
				panic(err)
			}
			vals = append(vals, rv)
		}
		b, err := asn1.Marshal(cmsAttribute{Type: oid, Values: vals})
		if err != nil {
			panic(err)
		}
		*dst = append(*dst, b...)
	}

	ctDER, _ := asn1.Marshal(oidSpcIndirectData)
	appendAttr(&authAttrs, oidContentType, ctDER)
	mdDER, _ := asn1.Marshal(digest)
	appendAttr(&authAttrs, oidMessageDigest, mdDER)

	if !opts.SigningTime.IsZero() {
		tDER, _ := asn1.Marshal(opts.SigningTime.UTC())
		appendAttr(&authAttrs, oidSigningTime, tDER)
		if opts.DuplicateSigningTime {
			t2DER, _ := asn1.Marshal(opts.SigningTime.Add(2 * time.Hour).UTC())
			appendAttr(&authAttrs, oidSigningTime, t2DER)
		}
	}
	if opts.ProgramName != "" || opts.MoreInfoURL != "" {
		opus := struct {
			ProgramName struct {
				ASCII string `asn1:"optional,tag:1,ia5"`
			} `asn1:"optional,tag:0"`
			MoreInfo struct {
				URL string `asn1:"optional,tag:0,ia5"`
			} `asn1:"optional,tag:1"`
		}{}
		opus.ProgramName.ASCII = opts.ProgramName
		opus.MoreInfo.URL = opts.MoreInfoURL
		opusDER, err := asn1.Marshal(opus)
		if err != nil {
			panic(err)
		}
		appendAttr(&authAttrs, oidSpcOpusInfo, opusDER)
	}
	if len(opts.UnknownAttrOID) > 0 {
		uDER, _ := asn1.Marshal([]byte{1, 2, 3})
		appendAttr(&authAttrs, opts.UnknownAttrOID, uDER)
	}

	setDER, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      authAttrs,
	})
	h := sha256.Sum256(setDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		panic(err)
	}

	sidDER, err := asn1.Marshal(cmsIssuerAndSerial{
		Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
		Serial: cert.SerialNumber,
	})
	if err != nil {
		panic(err)
	}
	var sidVal asn1.RawValue
	_, _ = asn1.Unmarshal(sidDER, &sidVal)

	var unauthAttrs []byte
	if !opts.PKCS9CountersignAt.IsZero() {
		csSI := marshalSignerInfo(key, cert, sig, oidSHA256, oidECDSAWithSHA256, AuthenticodeOptions{
			SigningTime: opts.PKCS9CountersignAt,
		})
		appendAttr(&unauthAttrs, oidCountersignature, csSI)
	}
	if !opts.RFC3161TimestampAt.IsZero() {
		tsBlob := buildRFC3161Token(key, cert, sig, opts.RFC3161TimestampAt)
		appendAttr(&unauthAttrs, oidAuthenticodeTimestamp, tsBlob)
	}
	if len(opts.NestedBlobs) > 0 {
		appendAttr(&unauthAttrs, oidNestedSignature, opts.NestedBlobs...)
	}

	si := cmsSignerInfo{
		Version:         1,
		SID:             sidVal,
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestOID},
		SignedAttrs: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrs,
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Signature:          sig,
	}
	if len(unauthAttrs) > 0 {
		si.UnsignedAttrs = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      unauthAttrs,
		}
	}
	siDER, err := asn1.Marshal(si)
	if err != nil {
		panic(err)
	}
	return siDER
}

func buildRFC3161Token(key *ecdsa.PrivateKey, cert *x509.Certificate, sig []byte, at time.Time) []byte {
	digest := sha256.Sum256(sig)
	tst := cmsTSTInfo{
		Version:      1,
		Policy:       asn1.ObjectIdentifier{1, 2, 3, 4},
		SerialNumber: big.NewInt(99),
		GenTime:      at.UTC().Truncate(time.Second),
	}
	tst.MessageImprint.HashAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	tst.MessageImprint.HashedMessage = digest[:]
	tstDER, err := asn1.Marshal(tst)
	if err != nil {
		panic(err)
	}
	octDER, _ := asn1.Marshal(tstDER)
	siDER := marshalSignerInfo(key, cert, digest[:], oidSHA256, oidECDSAWithSHA256, AuthenticodeOptions{})
	sd := cmsSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: cmsContentInfo{
			ContentType: oidTSTInfo,
			Content:     mustExplicitTag0(octDER),
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      cert.Raw,
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      siDER,
		},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		panic(err)
	}
	ciDER, err := asn1.Marshal(cmsContentInfo{
		ContentType: oidSignedData,
		Content:     mustExplicitTag0(sdDER),
	})
	if err != nil {
		panic(err)
	}
	return ciDER
}

func mustExplicitTag0(inner []byte) asn1.RawValue {
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      inner,
	}
}
