package pe

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
	"unicode/utf16"
)

// Parser limits bounding Authenticode CMS/BER decoding work and allocations.
// They are resource limits, not Windows Authenticode limits.
const (
	// MaxNestedSignatures limits nesting depth of Microsoft nested signature
	// attributes (OID 1.3.6.1.4.1.311.2.4.1).
	MaxNestedSignatures = 16
	// MaxAuthenticodeSignatures limits total decoded SignedData signature
	// layers across all security records and nested signatures.
	MaxAuthenticodeSignatures = 64
	// MaxAuthenticodeSigners limits cumulative SignerInfo entries decoded across
	// a signature parse call.
	MaxAuthenticodeSigners = 64
	// MaxAuthenticodeCertificates limits cumulative X.509 certificates parsed
	// across a signature parse call.
	MaxAuthenticodeCertificates = 256
	// MaxAuthenticodeCRLs limits cumulative X.509 CRLs parsed across a
	// signature parse call.
	MaxAuthenticodeCRLs = 256
	// MaxAuthenticodeAttributes limits attributes in a single SignerInfo's
	// authenticated or unauthenticated attribute set.
	MaxAuthenticodeAttributes = 256
)

var (
	// ErrInvalidAuthenticode indicates malformed or inconsistent CMS, ASN.1,
	// or Authenticode metadata.
	ErrInvalidAuthenticode = errors.New("invalid authenticode metadata")
	// ErrAuthenticodeLimit indicates that Authenticode decoding exceeded a
	// parser resource limit.
	ErrAuthenticodeLimit = errors.New("authenticode parser limit exceeded")
)

// Standard CMS, PKCS#9, RFC 3161, and Authenticode OIDs.
var (
	OIDSignedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDContentType           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDCountersignature      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	OIDTSTInfo               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDRFC3161TimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	OIDSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDSpcSpOpusInfo          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	OIDSpcPEImageData         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	OIDNestedSignature        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	OIDAuthenticodeTimestamp  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

// AuthenticodeTimestampKind identifies the encoding of a signer timestamp.
type AuthenticodeTimestampKind int

const (
	// AuthenticodeTimestampPKCS9 identifies a PKCS#9 v1 countersignature
	// (OID 1.2.840.113549.1.9.6).
	AuthenticodeTimestampPKCS9 AuthenticodeTimestampKind = iota + 1
	// AuthenticodeTimestampRFC3161 identifies an RFC 3161 TimeStampToken
	// (OID 1.3.6.1.4.1.311.3.3.1 or 1.2.840.113549.1.9.16.2.14).
	AuthenticodeTimestampRFC3161
)

// AuthenticodeSignature describes one decoded PKCS#7 / CMS SignedData layer
// from a WIN_CERTIFICATE entry or a nested signature attribute.
//
// Parsing metadata doesn't verify cryptographic signatures, message digests, or
// certificate trust chains.
type AuthenticodeSignature struct {
	RecordOffset         uint32
	NestedDepth          int
	TrailingPaddingBytes int
	Version              int
	ContentType      asn1.ObjectIdentifier
	DigestAlgorithms []pkix.AlgorithmIdentifier
	IndirectData     *AuthenticodeIndirectData
	Content          []byte
	Certificates     []*x509.Certificate
	CRLs             []*x509.RevocationList
	Signers          []AuthenticodeSigner

	encapContentKnown   bool
	encapContentWrapped bool
}

// AuthenticodeIndirectData holds the parsed SpcIndirectDataContent payload
// when ContentType equals [OIDSpcIndirectDataContent].
type AuthenticodeIndirectData struct {
	DataTypeOID     asn1.ObjectIdentifier
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
	RawContent      []byte
}

// AuthenticodeOpusInfo holds the program name and info URL from
// [OIDSpcSpOpusInfo], when present in authenticated attributes.
type AuthenticodeOpusInfo struct {
	ProgramName string
	MoreInfoURL string
}

// AuthenticodeAttribute preserves a raw CMS signed or unsigned attribute entry
// in file order, including duplicate or unrecognized OIDs.
type AuthenticodeAttribute struct {
	Type   asn1.ObjectIdentifier
	Values [][]byte
	Raw    []byte
}

// AuthenticodeSigner describes one CMS SignerInfo entry without verifying its
// cryptographic signature.
type AuthenticodeSigner struct {
	Version                    int
	IssuerRaw                  []byte
	SerialNumber               *big.Int
	SerialBytes                []byte
	SubjectKeyID               []byte
	DigestAlgorithm            pkix.AlgorithmIdentifier
	SignatureAlgorithm         pkix.AlgorithmIdentifier
	Signature                  []byte
	HasSigningTime             bool
	SigningTime                time.Time
	MessageDigest              []byte
	OpusInfo                   *AuthenticodeOpusInfo
	RawAuthenticatedAttributes []byte
	AuthenticatedAttributes    []AuthenticodeAttribute
	UnauthenticatedAttributes  []AuthenticodeAttribute
	Timestamps                 []AuthenticodeTimestamp
}

// AuthenticodeTimestamp preserves parsed countersignature or RFC 3161 timestamp
// metadata from a signer's unauthenticated attributes.
type AuthenticodeTimestamp struct {
	Kind            AuthenticodeTimestampKind
	HasSigningTime  bool
	SigningTime     time.Time
	Policy          asn1.ObjectIdentifier
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
	SerialNumber    *big.Int
	Certificates    []*x509.Certificate
	Signers         []AuthenticodeSigner
	Raw             []byte

	content             []byte
	contentType         asn1.ObjectIdentifier
	encapContentKnown   bool
	encapContentWrapped bool
}

type authParseBudget struct {
	signatures int
	signers    int
	certs      int
	crls       int
}

// AuthenticodeSignatures decodes bounded PKCS#7 SignedData metadata across all
// [CertificateTypePKCS7SignedData] entries in the PE security directory.
//
// If the security directory is absent or empty, AuthenticodeSignatures returns
// nil, nil without allocating. Entries with other certificate types are skipped
// without error. Nested signatures under [OIDNestedSignature] are decoded in
// depth-first order after their enclosing signature and retain NestedDepth > 0.
//
// All returned slices and certificates are owned copies; callers may modify or
// clear data after this call returns. Parsing metadata doesn't verify digests,
// signatures, or trust chains.
func (f *File) AuthenticodeSignatures(data []byte) ([]AuthenticodeSignature, error) {
	records, err := f.Certificates(data)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var out []AuthenticodeSignature
	var budget authParseBudget
	for _, rec := range records {
		if rec.Type != CertificateTypePKCS7SignedData {
			continue
		}
		payload, err := f.CertificatePayload(data, rec)
		if err != nil {
			return nil, err
		}
		der, trailing, err := berToDERWithTrailing(payload)
		if err != nil {
			return nil, err
		}
		if err := parseSignedDataRecursive(der, rec.Offset, 0, trailing, &budget, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ParseAuthenticodeSignatures decodes bounded PKCS#7 SignedData metadata from a
// single raw bCertificate DER/BER payload.
//
// All returned slices and certificates are owned copies; callers may modify or
// clear rawPKCS7 after this call returns. Parsing metadata doesn't verify
// signatures or trust chains.
func ParseAuthenticodeSignatures(rawPKCS7 []byte) ([]AuthenticodeSignature, error) {
	der, trailing, err := berToDERWithTrailing(rawPKCS7)
	if err != nil {
		return nil, err
	}
	var out []AuthenticodeSignature
	var budget authParseBudget
	if err := parseSignedDataRecursive(der, 0, 0, trailing, &budget, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CertificateSerialBytes extracts the unmodified ASN.1 INTEGER content octets
// for cert's serialNumber from its TBSCertificate DER bytes.
func CertificateSerialBytes(cert *x509.Certificate) ([]byte, error) {
	if cert == nil || len(cert.RawTBSCertificate) == 0 {
		return nil, fmt.Errorf("%w: certificate missing TBS bytes", ErrInvalidAuthenticode)
	}
	tbs := cert.RawTBSCertificate
	pos, seqEnd, ok := readDERHeader(tbs, 0)
	if !ok || tbs[0] != 0x30 || seqEnd > len(tbs) {
		return nil, fmt.Errorf("%w: malformed TBSCertificate header", ErrInvalidAuthenticode)
	}
	if pos < seqEnd && tbs[pos] == 0xa0 {
		vStart, vEnd, ok := readDERHeader(tbs, pos)
		if !ok || vEnd > seqEnd {
			return nil, fmt.Errorf("%w: malformed TBSCertificate version", ErrInvalidAuthenticode)
		}
		_ = vStart
		pos = vEnd
	}
	if pos >= seqEnd || tbs[pos] != 0x02 {
		return nil, fmt.Errorf("%w: malformed TBSCertificate serial number", ErrInvalidAuthenticode)
	}
	sStart, sEnd, ok := readDERHeader(tbs, pos)
	if !ok || sEnd > seqEnd {
		return nil, fmt.Errorf("%w: truncated TBSCertificate serial number", ErrInvalidAuthenticode)
	}
	return bytes.Clone(tbs[sStart:sEnd]), nil
}

type rawContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type rawSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo rawContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type rawSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type rawAttribute struct {
	Raw    asn1.RawContent
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type rawIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial asn1.RawValue
}

type rawSpcAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type rawDigestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

type rawSpcIndirectDataContent struct {
	Data          rawSpcAttribute
	MessageDigest rawDigestInfo
}

type rawSpcString struct {
	Unicode []byte `asn1:"optional,tag:0"`
	ASCII   string `asn1:"optional,tag:1,ia5"`
}

type rawSpcLink struct {
	URL     string        `asn1:"optional,tag:0,ia5"`
	Moniker asn1.RawValue `asn1:"optional,tag:1"`
	File    rawSpcString  `asn1:"optional,tag:2"`
}

type rawSpcSpOpusInfo struct {
	ProgramName rawSpcString `asn1:"optional,tag:0"`
	MoreInfo    rawSpcLink   `asn1:"optional,tag:1"`
}

type rawTSTAccuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type rawTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint rawDigestInfo
	SerialNumber   *big.Int
	GenTime        time.Time      `asn1:"generalized"`
	Accuracy       rawTSTAccuracy `asn1:"optional"`
	Ordering       bool           `asn1:"optional,default:false"`
	Nonce          *big.Int       `asn1:"optional"`
	TSA            asn1.RawValue  `asn1:"optional,explicit,tag:0"`
	Extensions     asn1.RawValue  `asn1:"optional,tag:1"`
}

func parseSignedDataRecursive(der []byte, recordOffset uint32, nestedDepth int, trailingPadding int, budget *authParseBudget, out *[]AuthenticodeSignature) error {
	if nestedDepth > MaxNestedSignatures {
		return fmt.Errorf("%w: nested signature depth exceeds %d", ErrAuthenticodeLimit, MaxNestedSignatures)
	}
	if budget.signatures >= MaxAuthenticodeSignatures {
		return fmt.Errorf("%w: signature count exceeds %d", ErrAuthenticodeLimit, MaxAuthenticodeSignatures)
	}
	budget.signatures++

	sig, nestedBlobs, err := decodeSignedDataLayer(der, recordOffset, nestedDepth, budget)
	if err != nil {
		return err
	}
	sig.TrailingPaddingBytes = trailingPadding
	*out = append(*out, sig)

	for _, blob := range nestedBlobs {
		nestedDER, nestedTrailing, err := berToDERWithTrailing(blob)
		if err != nil {
			return err
		}
		if err := parseSignedDataRecursive(nestedDER, recordOffset, nestedDepth+1, nestedTrailing, budget, out); err != nil {
			return err
		}
	}
	return nil
}

func decodeSignedDataLayer(der []byte, recordOffset uint32, nestedDepth int, budget *authParseBudget) (AuthenticodeSignature, [][]byte, error) {
	var ci rawContentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil || len(rest) != 0 {
		return AuthenticodeSignature{}, nil, fmt.Errorf("%w: invalid CMS ContentInfo", ErrInvalidAuthenticode)
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		return AuthenticodeSignature{}, nil, fmt.Errorf("%w: unexpected CMS content type %s", ErrInvalidAuthenticode, ci.ContentType)
	}

	var sd rawSignedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil || len(rest) != 0 {
		return AuthenticodeSignature{}, nil, fmt.Errorf("%w: invalid CMS SignedData", ErrInvalidAuthenticode)
	}

	certs, err := decodeCertificateSet(sd.Certificates, budget)
	if err != nil {
		return AuthenticodeSignature{}, nil, err
	}
	crls, err := decodeCRLSet(sd.CRLs, budget)
	if err != nil {
		return AuthenticodeSignature{}, nil, err
	}

	var contentBytes []byte
	var encapKnown bool
	var encapWrapped bool
	var indirect *AuthenticodeIndirectData
	if len(sd.EncapContentInfo.Content.Bytes) > 0 {
		rawInner, wrapped, err := extractEncapContent(sd.EncapContentInfo.Content.Bytes)
		if err != nil {
			return AuthenticodeSignature{}, nil, err
		}
		contentBytes = bytes.Clone(rawInner)
		encapKnown = true
		encapWrapped = wrapped
		if sd.EncapContentInfo.ContentType.Equal(OIDSpcIndirectDataContent) {
			parsedIndirect, err := decodeIndirectData(rawInner)
			if err != nil {
				return AuthenticodeSignature{}, nil, err
			}
			indirect = parsedIndirect
		}
	}

	signers, nestedBlobs, err := decodeSignerInfos(sd.SignerInfos, budget)
	if err != nil {
		return AuthenticodeSignature{}, nil, err
	}

	return AuthenticodeSignature{
		RecordOffset:        recordOffset,
		NestedDepth:         nestedDepth,
		Version:             sd.Version,
		ContentType:         cloneOID(sd.EncapContentInfo.ContentType),
		DigestAlgorithms:    cloneAlgorithms(sd.DigestAlgorithms),
		IndirectData:        indirect,
		Content:             contentBytes,
		Certificates:        certs,
		CRLs:                crls,
		Signers:             signers,
		encapContentKnown:   encapKnown,
		encapContentWrapped: encapWrapped,
	}, nestedBlobs, nil
}

func extractEncapContent(raw []byte) ([]byte, bool, error) {
	var val asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &val)
	if err != nil || len(rest) != 0 {
		return nil, false, fmt.Errorf("%w: malformed encapsulated content", ErrInvalidAuthenticode)
	}
	if val.Class == asn1.ClassUniversal && val.Tag == asn1.TagOctetString && !val.IsCompound {
		return val.Bytes, true, nil
	}
	return val.FullBytes, false, nil
}

func decodeIndirectData(raw []byte) (*AuthenticodeIndirectData, error) {
	var spc rawSpcIndirectDataContent
	rest, err := asn1.Unmarshal(raw, &spc)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: malformed SpcIndirectDataContent", ErrInvalidAuthenticode)
	}
	return &AuthenticodeIndirectData{
		DataTypeOID:     cloneOID(spc.Data.Type),
		DigestAlgorithm: cloneAlgorithm(spc.MessageDigest.DigestAlgorithm),
		Digest:          bytes.Clone(spc.MessageDigest.Digest),
		RawContent:      bytes.Clone(raw),
	}, nil
}

func decodeCertificateSet(raw asn1.RawValue, budget *authParseBudget) ([]*x509.Certificate, error) {
	if len(raw.Bytes) == 0 {
		return nil, nil
	}
	var certs []*x509.Certificate
	rest := raw.Bytes
	for len(rest) > 0 {
		if budget.certs >= MaxAuthenticodeCertificates {
			return nil, fmt.Errorf("%w: certificate count exceeds %d", ErrAuthenticodeLimit, MaxAuthenticodeCertificates)
		}
		var elem asn1.RawValue
		next, err := asn1.Unmarshal(rest, &elem)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed certificate entry: %v", ErrInvalidAuthenticode, err)
		}
		rest = next
		// Skip non-X.509 certificate choices ([1], [2], [3] attribute certificates).
		if elem.Class != asn1.ClassUniversal || elem.Tag != asn1.TagSequence {
			continue
		}
		cert, err := x509.ParseCertificate(bytes.Clone(elem.FullBytes))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid X.509 certificate: %v", ErrInvalidAuthenticode, err)
		}
		budget.certs++
		certs = append(certs, cert)
	}
	return certs, nil
}

func decodeCRLSet(raw asn1.RawValue, budget *authParseBudget) ([]*x509.RevocationList, error) {
	if len(raw.Bytes) == 0 {
		return nil, nil
	}
	var crls []*x509.RevocationList
	rest := raw.Bytes
	for len(rest) > 0 {
		if budget.crls >= MaxAuthenticodeCRLs {
			return nil, fmt.Errorf("%w: CRL count exceeds %d", ErrAuthenticodeLimit, MaxAuthenticodeCRLs)
		}
		var elem asn1.RawValue
		next, err := asn1.Unmarshal(rest, &elem)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed CRL entry: %v", ErrInvalidAuthenticode, err)
		}
		rest = next
		// Skip non-X.509 revocation choices ([1] other).
		if elem.Class != asn1.ClassUniversal || elem.Tag != asn1.TagSequence {
			continue
		}
		crl, err := x509.ParseRevocationList(bytes.Clone(elem.FullBytes))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid X.509 CRL: %v", ErrInvalidAuthenticode, err)
		}
		budget.crls++
		crls = append(crls, crl)
	}
	return crls, nil
}

func decodeSignerInfos(raw asn1.RawValue, budget *authParseBudget) ([]AuthenticodeSigner, [][]byte, error) {
	if len(raw.Bytes) == 0 {
		return nil, nil, nil
	}
	var signers []AuthenticodeSigner
	var nestedBlobs [][]byte
	rest := raw.Bytes
	for len(rest) > 0 {
		var elem asn1.RawValue
		next, err := asn1.Unmarshal(rest, &elem)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: malformed SignerInfo set entry", ErrInvalidAuthenticode)
		}
		rest = next
		signer, blobs, err := decodeSignerInfo(elem.FullBytes, budget)
		if err != nil {
			return nil, nil, err
		}
		signers = append(signers, signer)
		nestedBlobs = append(nestedBlobs, blobs...)
	}
	return signers, nestedBlobs, nil
}

func decodeSignerInfo(raw []byte, budget *authParseBudget) (AuthenticodeSigner, [][]byte, error) {
	if budget.signers >= MaxAuthenticodeSigners {
		return AuthenticodeSigner{}, nil, fmt.Errorf("%w: signer count exceeds %d", ErrAuthenticodeLimit, MaxAuthenticodeSigners)
	}
	budget.signers++

	var si rawSignerInfo
	rest, err := asn1.Unmarshal(raw, &si)
	if err != nil || len(rest) != 0 {
		return AuthenticodeSigner{}, nil, fmt.Errorf("%w: invalid CMS SignerInfo", ErrInvalidAuthenticode)
	}

	out := AuthenticodeSigner{
		Version:            si.Version,
		DigestAlgorithm:    cloneAlgorithm(si.DigestAlgorithm),
		SignatureAlgorithm: cloneAlgorithm(si.SignatureAlgorithm),
		Signature:          bytes.Clone(si.Signature),
	}

	switch {
	case si.SID.Class == asn1.ClassUniversal && si.SID.Tag == asn1.TagSequence:
		var ias rawIssuerAndSerial
		r, err := asn1.Unmarshal(si.SID.FullBytes, &ias)
		if err != nil || len(r) != 0 || ias.Serial.Class != asn1.ClassUniversal || ias.Serial.Tag != asn1.TagInteger {
			return AuthenticodeSigner{}, nil, fmt.Errorf("%w: invalid SignerIdentifier IssuerAndSerialNumber", ErrInvalidAuthenticode)
		}
		var serial *big.Int
		if _, err := asn1.Unmarshal(ias.Serial.FullBytes, &serial); err != nil {
			return AuthenticodeSigner{}, nil, fmt.Errorf("%w: invalid signer serial number", ErrInvalidAuthenticode)
		}
		out.IssuerRaw = bytes.Clone(ias.Issuer.FullBytes)
		out.SerialNumber = serial
		out.SerialBytes = bytes.Clone(ias.Serial.Bytes)
	case si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0:
		out.SubjectKeyID = bytes.Clone(si.SID.Bytes)
	default:
		return AuthenticodeSigner{}, nil, fmt.Errorf("%w: unsupported SignerIdentifier tag %d", ErrInvalidAuthenticode, si.SID.Tag)
	}

	if len(si.SignedAttrs.FullBytes) > 0 {
		rawSet := bytes.Clone(si.SignedAttrs.FullBytes)
		// Replace [0] IMPLICIT context tag with SET (0x31) per RFC 5652 section 5.4.
		rawSet[0] = 0x31
		out.RawAuthenticatedAttributes = rawSet

		attrs, err := decodeAttributes(si.SignedAttrs.Bytes)
		if err != nil {
			return AuthenticodeSigner{}, nil, err
		}
		out.AuthenticatedAttributes = attrs
		if err := applyAuthenticatedAttributes(&out); err != nil {
			return AuthenticodeSigner{}, nil, err
		}
	}

	var nestedBlobs [][]byte
	if len(si.UnsignedAttrs.Bytes) > 0 {
		attrs, err := decodeAttributes(si.UnsignedAttrs.Bytes)
		if err != nil {
			return AuthenticodeSigner{}, nil, err
		}
		out.UnauthenticatedAttributes = attrs
		timestamps, blobs, err := decodeUnauthenticatedAttributes(attrs, budget)
		if err != nil {
			return AuthenticodeSigner{}, nil, err
		}
		out.Timestamps = timestamps
		nestedBlobs = blobs
	}

	return out, nestedBlobs, nil
}

func decodeAttributes(setContents []byte) ([]AuthenticodeAttribute, error) {
	var out []AuthenticodeAttribute
	rest := setContents
	for len(rest) > 0 {
		if len(out) >= MaxAuthenticodeAttributes {
			return nil, fmt.Errorf("%w: attribute count exceeds %d", ErrAuthenticodeLimit, MaxAuthenticodeAttributes)
		}
		var attr rawAttribute
		next, err := asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed CMS attribute: %v", ErrInvalidAuthenticode, err)
		}
		rest = next
		vals := make([][]byte, len(attr.Values))
		for i, v := range attr.Values {
			vals[i] = bytes.Clone(v.FullBytes)
		}
		out = append(out, AuthenticodeAttribute{
			Type:   cloneOID(attr.Type),
			Values: vals,
			Raw:    bytes.Clone(attr.Raw),
		})
	}
	return out, nil
}

func applyAuthenticatedAttributes(signer *AuthenticodeSigner) error {
	for _, attr := range signer.AuthenticatedAttributes {
		switch {
		case attr.Type.Equal(OIDMessageDigest) && len(attr.Values) > 0:
			var digest []byte
			rest, err := asn1.Unmarshal(attr.Values[0], &digest)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("%w: malformed messageDigest attribute", ErrInvalidAuthenticode)
			}
			if signer.MessageDigest == nil {
				signer.MessageDigest = digest
			}
		case attr.Type.Equal(OIDSigningTime) && len(attr.Values) > 0:
			var t time.Time
			rest, err := asn1.Unmarshal(attr.Values[0], &t)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("%w: malformed signingTime attribute", ErrInvalidAuthenticode)
			}
			if !signer.HasSigningTime {
				signer.HasSigningTime = true
				signer.SigningTime = t
			}
		case attr.Type.Equal(OIDSpcSpOpusInfo) && len(attr.Values) > 0:
			var opus rawSpcSpOpusInfo
			rest, err := asn1.Unmarshal(attr.Values[0], &opus)
			if err != nil || len(rest) != 0 {
				return fmt.Errorf("%w: malformed SpcSpOpusInfo attribute", ErrInvalidAuthenticode)
			}
			if signer.OpusInfo == nil {
				programName, err := decodeSpcString(opus.ProgramName)
				if err != nil {
					return err
				}
				moreInfoURL, err := decodeSpcLinkURL(opus.MoreInfo)
				if err != nil {
					return err
				}
				signer.OpusInfo = &AuthenticodeOpusInfo{
					ProgramName: programName,
					MoreInfoURL: moreInfoURL,
				}
			}
		}
	}
	return nil
}

func decodeUnauthenticatedAttributes(attrs []AuthenticodeAttribute, budget *authParseBudget) ([]AuthenticodeTimestamp, [][]byte, error) {
	var timestamps []AuthenticodeTimestamp
	var nestedBlobs [][]byte

	for _, attr := range attrs {
		switch {
		case attr.Type.Equal(OIDNestedSignature):
			nestedBlobs = append(nestedBlobs, attr.Values...)
		case attr.Type.Equal(OIDCountersignature):
			for _, v := range attr.Values {
				signer, blobs, err := decodeSignerInfo(v, budget)
				if err != nil {
					return nil, nil, err
				}
				nestedBlobs = append(nestedBlobs, blobs...)
				timestamps = append(timestamps, AuthenticodeTimestamp{
					Kind:           AuthenticodeTimestampPKCS9,
					HasSigningTime: signer.HasSigningTime,
					SigningTime:    signer.SigningTime,
					Signers:        []AuthenticodeSigner{signer},
					Raw:            bytes.Clone(v),
				})
			}
		case attr.Type.Equal(OIDAuthenticodeTimestamp) || attr.Type.Equal(OIDRFC3161TimeStampToken):
			for _, v := range attr.Values {
				ts, err := decodeRFC3161Timestamp(v, budget)
				if err != nil {
					return nil, nil, err
				}
				timestamps = append(timestamps, ts)
			}
		}
	}
	return timestamps, nestedBlobs, nil
}

func decodeRFC3161Timestamp(raw []byte, budget *authParseBudget) (AuthenticodeTimestamp, error) {
	der, err := berToDER(raw)
	if err != nil {
		return AuthenticodeTimestamp{}, err
	}
	sig, _, err := decodeSignedDataLayer(der, 0, 0, budget)
	if err != nil {
		return AuthenticodeTimestamp{}, err
	}
	ts := AuthenticodeTimestamp{
		Kind:                AuthenticodeTimestampRFC3161,
		Certificates:        sig.Certificates,
		Signers:             sig.Signers,
		Raw:                 bytes.Clone(raw),
		content:             sig.Content,
		contentType:         sig.ContentType,
		encapContentKnown:   sig.encapContentKnown,
		encapContentWrapped: sig.encapContentWrapped,
	}
	if sig.ContentType.Equal(OIDTSTInfo) && len(sig.Content) > 0 {
		var tst rawTSTInfo
		rest, err := asn1.Unmarshal(sig.Content, &tst)
		if err != nil || len(rest) != 0 {
			return AuthenticodeTimestamp{}, fmt.Errorf("%w: malformed RFC 3161 TSTInfo", ErrInvalidAuthenticode)
		}
		ts.HasSigningTime = true
		ts.SigningTime = tst.GenTime
		ts.Policy = cloneOID(tst.Policy)
		ts.DigestAlgorithm = cloneAlgorithm(tst.MessageImprint.DigestAlgorithm)
		ts.Digest = bytes.Clone(tst.MessageImprint.Digest)
		if tst.SerialNumber != nil {
			ts.SerialNumber = new(big.Int).Set(tst.SerialNumber)
		}
	}
	return ts, nil
}

func decodeSpcString(s rawSpcString) (string, error) {
	if len(s.Unicode) != 0 {
		if len(s.Unicode)%2 != 0 {
			return "", fmt.Errorf("%w: odd-length UTF-16BE SpcString", ErrInvalidAuthenticode)
		}
		words := make([]uint16, len(s.Unicode)/2)
		for i := range words {
			words[i] = binary.BigEndian.Uint16(s.Unicode[i*2:])
		}
		return string(utf16.Decode(words)), nil
	}
	return s.ASCII, nil
}

func decodeSpcLinkURL(link rawSpcLink) (string, error) {
	if link.URL != "" {
		return link.URL, nil
	}
	return decodeSpcString(link.File)
}

func cloneOID(oid asn1.ObjectIdentifier) asn1.ObjectIdentifier {
	if len(oid) == 0 {
		return nil
	}
	out := make(asn1.ObjectIdentifier, len(oid))
	copy(out, oid)
	return out
}

func cloneAlgorithm(alg pkix.AlgorithmIdentifier) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{
		Algorithm: cloneOID(alg.Algorithm),
		Parameters: asn1.RawValue{
			Class:      alg.Parameters.Class,
			Tag:        alg.Parameters.Tag,
			IsCompound: alg.Parameters.IsCompound,
			Bytes:      bytes.Clone(alg.Parameters.Bytes),
			FullBytes:  bytes.Clone(alg.Parameters.FullBytes),
		},
	}
}

func cloneAlgorithms(algs []pkix.AlgorithmIdentifier) []pkix.AlgorithmIdentifier {
	if len(algs) == 0 {
		return nil
	}
	out := make([]pkix.AlgorithmIdentifier, len(algs))
	for i, alg := range algs {
		out[i] = cloneAlgorithm(alg)
	}
	return out
}

func readDERHeader(b []byte, pos int) (contentStart, contentEnd int, ok bool) {
	if pos+2 > len(b) {
		return 0, 0, false
	}
	// Skip single or multi-byte tag.
	if b[pos]&0x1f == 0x1f {
		pos++
		for pos < len(b) && b[pos]&0x80 != 0 {
			pos++
		}
	}
	pos++
	if pos >= len(b) {
		return 0, 0, false
	}
	l := b[pos]
	pos++
	if l < 0x80 {
		end := pos + int(l)
		return pos, end, end <= len(b)
	}
	n := int(l & 0x7f)
	if n == 0 || n > 4 || pos+n > len(b) {
		return 0, 0, false
	}
	var length int
	for range n {
		length = (length << 8) | int(b[pos])
		pos++
	}
	if length < 0 {
		return 0, 0, false
	}
	end := pos + length
	return pos, end, end <= len(b)
}
