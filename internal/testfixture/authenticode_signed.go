package testfixture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" // #nosec G501 -- Test fixture builds legacy Authenticode signatures.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Test fixture builds legacy Authenticode signatures.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"time"
)

var (
	oidDigestMD5        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidDigestSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestSHA384     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidRSAEncryption    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidMD5WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA1WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidMGF1             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSASSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519          = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidPKCS7Data        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidRFC3161TokenAttr = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

// AuthenticodePKI holds an offline test Root CA, Intermediate CA, code-signing
// leaf, and TSA leaf with configurable validity intervals.
type AuthenticodePKI struct {
	RootCert    *x509.Certificate
	RootKey     crypto.Signer
	InterCert   *x509.Certificate
	InterKey    crypto.Signer
	SignerCert  *x509.Certificate
	SignerKey   crypto.Signer
	TSACert     *x509.Certificate
	TSAKey      crypto.Signer
	ExpiredCert *x509.Certificate
	ExpiredKey  crypto.Signer
	RootPool    *x509.CertPool
}

// AuthenticodePKIOptions configures key types and validity windows for
// [NewAuthenticodePKI].
type AuthenticodePKIOptions struct {
	UseRSA            bool
	UseEd25519        bool
	RootNotBefore     time.Time
	RootNotAfter      time.Time
	LeafNotBefore     time.Time
	LeafNotAfter      time.Time
	TSANotBefore      time.Time
	TSANotAfter       time.Time
	ServerAuthOnlyEKU bool
}

// NewAuthenticodePKI generates a self-contained offline PKI hierarchy for
// Authenticode verification testing.
func NewAuthenticodePKI(opts AuthenticodePKIOptions) *AuthenticodePKI {
	rootNotBefore := defaultTime(opts.RootNotBefore, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	rootNotAfter := defaultTime(opts.RootNotAfter, time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	leafNotBefore := defaultTime(opts.LeafNotBefore, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	leafNotAfter := defaultTime(opts.LeafNotAfter, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	tsaNotBefore := defaultTime(opts.TSANotBefore, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	tsaNotAfter := defaultTime(opts.TSANotAfter, time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC))

	genKey := func() crypto.Signer {
		if opts.UseRSA {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			return k
		}
		if opts.UseEd25519 {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			return k
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		return k
	}

	rootKey := genKey()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Authenticode Root CA"},
		NotBefore:             rootNotBefore,
		NotAfter:              rootNotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	rootCert := mustCreateCert(rootTmpl, rootTmpl, rootKey.Public(), rootKey)

	interKey := genKey()
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Authenticode Intermediate CA"},
		NotBefore:             rootNotBefore,
		NotAfter:              rootNotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{2, 3, 4, 5},
	}
	interCert := mustCreateCert(interTmpl, rootCert, interKey.Public(), rootKey)

	leafEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	if opts.ServerAuthOnlyEKU {
		leafEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signerKey := genKey()
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1001),
		Subject:      pkix.Name{CommonName: "Test Code Signer"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  leafEKU,
		SubjectKeyId: []byte{3, 4, 5, 6},
	}
	signerCert := mustCreateCert(signerTmpl, interCert, signerKey.Public(), interKey)

	tsaKey := genKey()
	tsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2001),
		Subject:      pkix.Name{CommonName: "Test TSA"},
		NotBefore:    tsaNotBefore,
		NotAfter:     tsaNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		SubjectKeyId: []byte{4, 5, 6, 7},
	}
	tsaCert := mustCreateCert(tsaTmpl, interCert, tsaKey.Public(), interKey)

	expiredKey := genKey()
	expiredTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x3001),
		Subject:      pkix.Name{CommonName: "Expired Code Signer"},
		NotBefore:    time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SubjectKeyId: []byte{5, 6, 7, 8},
	}
	expiredCert := mustCreateCert(expiredTmpl, interCert, expiredKey.Public(), interKey)

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	return &AuthenticodePKI{
		RootCert:    rootCert,
		RootKey:     rootKey,
		InterCert:   interCert,
		InterKey:    interKey,
		SignerCert:  signerCert,
		SignerKey:   signerKey,
		TSACert:     tsaCert,
		TSAKey:      tsaKey,
		ExpiredCert: expiredCert,
		ExpiredKey:  expiredKey,
		RootPool:    pool,
	}
}

// SignedPKCS7Options controls construction of a cryptographically verifiable
// (or intentionally faulted) Authenticode PKCS#7 blob.
type SignedPKCS7Options struct {
	SignerCert             *x509.Certificate
	SignerKey              crypto.Signer
	ExtraCerts             []*x509.Certificate
	OmitSignerCert         bool
	UseSubjectKeyID        bool
	UseKeyOnlySigOID       bool
	UseRSAPSS              bool
	WrapEncapOctetString   bool
	ImageDigest            []byte
	ImageDigestAlg         crypto.Hash
	CMSDigestAlg           crypto.Hash
	OverrideSigOID         asn1.ObjectIdentifier
	OverrideImageDigestOID asn1.ObjectIdentifier
	SigningTime            time.Time

	// Fault-injection knobs for negative tests.
	CorruptSignature        bool
	CorruptSignedDigest     bool
	DuplicateMessageDigest  bool
	DuplicateSigningTime    bool
	MultiValueContentType   bool
	OmitContentType         bool
	OmitSignedAttrs         bool
	ConflictingDuplicateSID bool

	// Timestamp configuration.
	PKCS9At                 time.Time
	RFC3161At               time.Time
	UseStandardRFC3161OID   bool
	TSACert                 *x509.Certificate
	TSAKey                  crypto.Signer
	CorruptTimestampImprint bool
	CorruptTimestampSig     bool
	OmitTSACertFromToken    bool

	NestedBlobs [][]byte
}

// MinimalAligned builds an 8-byte-aligned PE32 or PE32+ image with one section
// so appending WIN_CERTIFICATE records preserves its Authenticode digest.
func MinimalAligned(is64 bool) []byte {
	data := Minimal(is64, 1)
	if pad := (8 - len(data)%8) % 8; pad > 0 {
		data = append(data, make([]byte, pad)...)
	}
	return data
}

// AppendCertificates appends one or more WIN_CERTIFICATE entries onto base and
// updates DataDirectory[4] without mutating base.
func AppendCertificates(base []byte, is64 bool, specs ...CertificateSpec) []byte {
	out := append([]byte(nil), base...)
	if pad := (8 - len(out)%8) % 8; pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	tableOff := len(out)
	var table []byte
	for _, spec := range specs {
		recLen := 8 + len(spec.Payload)
		paddedLen := (recLen + 7) &^ 7
		buf := make([]byte, paddedLen)
		binary.LittleEndian.PutUint32(buf[0:4], uint32(recLen))
		binary.LittleEndian.PutUint16(buf[4:6], spec.Revision)
		binary.LittleEndian.PutUint16(buf[6:8], spec.Type)
		copy(buf[8:], spec.Payload)
		table = append(table, buf...)
	}
	dirOff := CertificateDirOffset(is64)
	binary.LittleEndian.PutUint32(out[dirOff:], uint32(tableOff))
	binary.LittleEndian.PutUint32(out[dirOff+4:], uint32(len(table)))
	return append(out, table...)
}

// BuildSignedPKCS7 constructs a DER-encoded CMS SignedData blob matching opts.
func BuildSignedPKCS7(opts SignedPKCS7Options) []byte {
	imgAlg := opts.ImageDigestAlg
	if imgAlg == 0 {
		imgAlg = crypto.SHA256
	}
	cmsAlg := opts.CMSDigestAlg
	if cmsAlg == 0 {
		cmsAlg = imgAlg
	}

	imgAlgOID := digestOIDForHash(imgAlg)
	if len(opts.OverrideImageDigestOID) > 0 {
		imgAlgOID = opts.OverrideImageDigestOID
	}

	indirect := cmsSpcIndirectData{}
	indirect.Data.Type = oidSpcPEImageData
	indirect.MessageDigest.DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: imgAlgOID}
	indirect.MessageDigest.Digest = append([]byte(nil), opts.ImageDigest...)
	indirectDER, err := asn1.Marshal(indirect)
	if err != nil {
		panic(err)
	}

	// RFC 2315 hashes contents octets when stored as SEQUENCE directly, or full
	// indirectDER when wrapped in OCTET STRING (CMS v3).
	encapRaw := indirectDER
	payloadToHash := derContentOctets(indirectDER)
	version := 1
	if opts.WrapEncapOctetString {
		version = 3
		oct, err := asn1.Marshal(indirectDER)
		if err != nil {
			panic(err)
		}
		encapRaw = oct
		payloadToHash = indirectDER
	}

	contentDigest := hashBytes(cmsAlg, payloadToHash)
	if opts.CorruptSignedDigest && len(contentDigest) > 0 {
		contentDigest[0] ^= 0xff
	}

	siBytes := buildSignerInfo(signerBuildParams{
		cert:                    opts.SignerCert,
		key:                     opts.SignerKey,
		contentTypeOID:          oidSpcIndirectData,
		contentDigest:           contentDigest,
		digestAlg:               cmsAlg,
		useSubjectKeyID:         opts.UseSubjectKeyID,
		useKeyOnlySigOID:        opts.UseKeyOnlySigOID,
		useRSAPSS:               opts.UseRSAPSS,
		overrideSigOID:          opts.OverrideSigOID,
		signingTime:             opts.SigningTime,
		corruptSignature:        opts.CorruptSignature,
		duplicateMessageDigest:  opts.DuplicateMessageDigest,
		duplicateSigningTime:    opts.DuplicateSigningTime,
		multiValueContentType:   opts.MultiValueContentType,
		omitContentType:         opts.OmitContentType,
		omitSignedAttrs:         opts.OmitSignedAttrs,
		rawContentFallback:      payloadToHash,
		pkcs9At:                 opts.PKCS9At,
		rfc3161At:               opts.RFC3161At,
		useStandardRFC3161OID:   opts.UseStandardRFC3161OID,
		tsaCert:                 opts.TSACert,
		tsaKey:                  opts.TSAKey,
		corruptTimestampImprint: opts.CorruptTimestampImprint,
		corruptTimestampSig:     opts.CorruptTimestampSig,
		omitTSACertFromToken:    opts.OmitTSACertFromToken,
		nestedBlobs:             opts.NestedBlobs,
	})

	var certBytes []byte
	if !opts.OmitSignerCert && opts.SignerCert != nil {
		certBytes = append(certBytes, opts.SignerCert.Raw...)
	}
	if opts.ConflictingDuplicateSID && opts.SignerCert != nil {
		// Create another cert with identical Subject/Issuer/Serial but different key.
		k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		dupTmpl := &x509.Certificate{
			SerialNumber: new(big.Int).Set(opts.SignerCert.SerialNumber),
			Subject:      opts.SignerCert.Subject,
			Issuer:       opts.SignerCert.Issuer,
			NotBefore:    opts.SignerCert.NotBefore,
			NotAfter:     opts.SignerCert.NotAfter,
			SubjectKeyId: append([]byte(nil), opts.SignerCert.SubjectKeyId...),
		}
		dupCert := mustCreateCert(dupTmpl, dupTmpl, &k2.PublicKey, k2)
		// Replace RawIssuer only by re-signing with same Issuer DER via self-signed CA sharing DN:
		_ = dupCert
		kCA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTmpl := &x509.Certificate{
			RawSubject:            opts.SignerCert.RawIssuer,
			SerialNumber:          big.NewInt(999),
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
			NotBefore:             opts.SignerCert.NotBefore,
			NotAfter:              opts.SignerCert.NotAfter,
		}
		caCert := mustCreateCert(caTmpl, caTmpl, &kCA.PublicKey, kCA)
		dupLeaf := mustCreateCert(dupTmpl, caCert, &k2.PublicKey, kCA)
		certBytes = append(certBytes, dupLeaf.Raw...)
	}
	for _, c := range opts.ExtraCerts {
		if c != nil {
			certBytes = append(certBytes, c.Raw...)
		}
	}

	sd := cmsSignedData{
		Version:          version,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestOIDForHash(cmsAlg)}},
		EncapContentInfo: cmsContentInfo{
			ContentType: oidSpcIndirectData,
			Content:     mustExplicitTag0(encapRaw),
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      siBytes,
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
	return ciDER
}

type signerBuildParams struct {
	cert                    *x509.Certificate
	key                     crypto.Signer
	contentTypeOID          asn1.ObjectIdentifier
	contentDigest           []byte
	digestAlg               crypto.Hash
	useSubjectKeyID         bool
	useKeyOnlySigOID        bool
	useRSAPSS               bool
	overrideSigOID          asn1.ObjectIdentifier
	signingTime             time.Time
	corruptSignature        bool
	duplicateMessageDigest  bool
	duplicateSigningTime    bool
	multiValueContentType   bool
	omitContentType         bool
	omitSignedAttrs         bool
	rawContentFallback      []byte
	pkcs9At                 time.Time
	rfc3161At               time.Time
	useStandardRFC3161OID   bool
	tsaCert                 *x509.Certificate
	tsaKey                  crypto.Signer
	corruptTimestampImprint bool
	corruptTimestampSig     bool
	omitTSACertFromToken    bool
	nestedBlobs             [][]byte
}

func buildSignerInfo(p signerBuildParams) []byte {
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

	if !p.omitSignedAttrs {
		if !p.omitContentType {
			ctDER, _ := asn1.Marshal(p.contentTypeOID)
			if p.multiValueContentType {
				ct2DER, _ := asn1.Marshal(oidPKCS7Data)
				appendAttr(&authAttrs, oidContentType, ctDER, ct2DER)
			} else {
				appendAttr(&authAttrs, oidContentType, ctDER)
			}
		}
		mdDER, _ := asn1.Marshal(p.contentDigest)
		appendAttr(&authAttrs, oidMessageDigest, mdDER)
		if p.duplicateMessageDigest {
			appendAttr(&authAttrs, oidMessageDigest, mdDER)
		}
		if !p.signingTime.IsZero() {
			tDER, _ := asn1.Marshal(p.signingTime.UTC())
			appendAttr(&authAttrs, oidSigningTime, tDER)
			if p.duplicateSigningTime {
				t2DER, _ := asn1.Marshal(p.signingTime.Add(time.Minute).UTC())
				appendAttr(&authAttrs, oidSigningTime, t2DER)
			}
		}
	}

	toSign := p.rawContentFallback
	if !p.omitSignedAttrs {
		setDER, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      authAttrs,
		})
		if err != nil {
			panic(err)
		}
		toSign = setDER
	}

	sigOID, sigBytes := signBytes(p.key, p.digestAlg, p.useKeyOnlySigOID, p.useRSAPSS, p.overrideSigOID, toSign)
	if p.corruptSignature && len(sigBytes) > 0 {
		sigBytes[len(sigBytes)/2] ^= 0x55
	}

	siVersion := 1
	var sidVal asn1.RawValue
	if p.useSubjectKeyID && len(p.cert.SubjectKeyId) > 0 {
		siVersion = 3
		raw, _ := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   0,
			Bytes: p.cert.SubjectKeyId,
		})
		_, _ = asn1.Unmarshal(raw, &sidVal)
	} else {
		sidDER, err := asn1.Marshal(cmsIssuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: p.cert.RawIssuer},
			Serial: p.cert.SerialNumber,
		})
		if err != nil {
			panic(err)
		}
		_, _ = asn1.Unmarshal(sidDER, &sidVal)
	}

	var unauthAttrs []byte
	if !p.pkcs9At.IsZero() {
		csCert := p.tsaCert
		csKey := p.tsaKey
		if csCert == nil {
			csCert = p.cert
			csKey = p.key
		}
		imprintTarget := append([]byte(nil), sigBytes...)
		if p.corruptTimestampImprint && len(imprintTarget) > 0 {
			imprintTarget[0] ^= 0x11
		}
		csSI := buildSignerInfo(signerBuildParams{
			cert:             csCert,
			key:              csKey,
			contentTypeOID:   oidPKCS7Data,
			contentDigest:    hashBytes(p.digestAlg, imprintTarget),
			digestAlg:        p.digestAlg,
			omitContentType:  true,
			signingTime:      p.pkcs9At,
			corruptSignature: p.corruptTimestampSig,
		})
		appendAttr(&unauthAttrs, oidCountersignature, csSI)
	}
	if !p.rfc3161At.IsZero() {
		tsaCert := p.tsaCert
		tsaKey := p.tsaKey
		if tsaCert == nil {
			tsaCert = p.cert
			tsaKey = p.key
		}
		tsBlob := buildValidRFC3161Token(tsaKey, tsaCert, sigBytes, p.rfc3161At, p.corruptTimestampImprint, p.corruptTimestampSig, p.omitTSACertFromToken)
		attrOID := oidAuthenticodeTimestamp
		if p.useStandardRFC3161OID {
			attrOID = oidRFC3161TokenAttr
		}
		appendAttr(&unauthAttrs, attrOID, tsBlob)
	}
	for _, nb := range p.nestedBlobs {
		appendAttr(&unauthAttrs, oidNestedSignature, nb)
	}

	si := cmsSignerInfo{
		Version:            siVersion,
		SID:                sidVal,
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestOIDForHash(p.digestAlg)},
		SignatureAlgorithm: sigOID,
		Signature:          sigBytes,
	}
	if !p.omitSignedAttrs {
		si.SignedAttrs = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrs,
		}
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

func buildValidRFC3161Token(
	key crypto.Signer,
	cert *x509.Certificate,
	sig []byte,
	at time.Time,
	corruptImprint bool,
	corruptSig bool,
	omitCert bool,
) []byte {
	imprintTarget := append([]byte(nil), sig...)
	if corruptImprint && len(imprintTarget) > 0 {
		imprintTarget[0] ^= 0xaa
	}
	digest := sha256.Sum256(imprintTarget)
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
	tstDigest := sha256.Sum256(tstDER)

	siDER := buildSignerInfo(signerBuildParams{
		cert:             cert,
		key:              key,
		contentTypeOID:   oidTSTInfo,
		contentDigest:    tstDigest[:],
		digestAlg:        crypto.SHA256,
		corruptSignature: corruptSig,
	})
	sd := cmsSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: cmsContentInfo{
			ContentType: oidTSTInfo,
			Content:     mustExplicitTag0(octDER),
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      siDER,
		},
	}
	if !omitCert && cert != nil {
		sd.Certificates = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      cert.Raw,
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
	return ciDER
}

func signBytes(
	key crypto.Signer,
	alg crypto.Hash,
	keyOnlyOID bool,
	usePSS bool,
	overrideOID asn1.ObjectIdentifier,
	payload []byte,
) (pkix.AlgorithmIdentifier, []byte) {
	digest := hashBytes(alg, payload)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if usePSS {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: alg}
			sig, err := rsa.SignPSS(rand.Reader, k, alg, digest, opts)
			if err != nil {
				panic(err)
			}
			type pssParams struct {
				HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
				MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
				SaltLength       int                      `asn1:"explicit,tag:2"`
				TrailerField     int                      `asn1:"explicit,tag:3"`
			}
			mgfParam, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: digestOIDForHash(alg)})
			paramsDER, err := asn1.Marshal(pssParams{
				HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestOIDForHash(alg)},
				MaskGenAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm:  oidMGF1,
					Parameters: asn1.RawValue{FullBytes: mgfParam},
				},
				SaltLength:   alg.Size(),
				TrailerField: 1,
			})
			if err != nil {
				panic(err)
			}
			oid := oidRSASSAPSS
			if len(overrideOID) > 0 {
				oid = overrideOID
			}
			return pkix.AlgorithmIdentifier{
				Algorithm:  oid,
				Parameters: asn1.RawValue{FullBytes: paramsDER},
			}, sig
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, alg, digest)
		if err != nil {
			panic(err)
		}
		var oid asn1.ObjectIdentifier
		if len(overrideOID) > 0 {
			oid = overrideOID
		} else if keyOnlyOID {
			oid = oidRSAEncryption
		} else {
			oid = rsaSigOIDForHash(alg)
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, sig

	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			panic(err)
		}
		var oid asn1.ObjectIdentifier
		if len(overrideOID) > 0 {
			oid = overrideOID
		} else if keyOnlyOID {
			oid = oidECPublicKey
		} else {
			oid = ecdsaSigOIDForHash(alg)
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, sig

	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, payload)
		oid := oidEd25519
		if len(overrideOID) > 0 {
			oid = overrideOID
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, sig

	default:
		panic(fmt.Sprintf("unsupported key type %T", key))
	}
}

func mustCreateCert(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

func defaultTime(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}

func derContentOctets(der []byte) []byte {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		panic(err)
	}
	return rv.Bytes
}

func digestOIDForHash(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.MD5:
		return oidDigestMD5
	case crypto.SHA1:
		return oidDigestSHA1
	case crypto.SHA256:
		return oidSHA256
	case crypto.SHA384:
		return oidDigestSHA384
	case crypto.SHA512:
		return oidDigestSHA512
	default:
		panic(fmt.Sprintf("unsupported digest %v", h))
	}
}

func rsaSigOIDForHash(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.MD5:
		return oidMD5WithRSA
	case crypto.SHA1:
		return oidSHA1WithRSA
	case crypto.SHA256:
		return oidSHA256WithRSA
	case crypto.SHA384:
		return oidSHA384WithRSA
	case crypto.SHA512:
		return oidSHA512WithRSA
	default:
		panic(fmt.Sprintf("unsupported RSA hash %v", h))
	}
}

func ecdsaSigOIDForHash(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	case crypto.SHA256:
		return oidECDSAWithSHA256
	case crypto.SHA384:
		return oidECDSAWithSHA384
	case crypto.SHA512:
		return oidECDSAWithSHA512
	default:
		panic(fmt.Sprintf("unsupported ECDSA hash %v", h))
	}
}

func hashBytes(alg crypto.Hash, b []byte) []byte {
	var h hash.Hash
	switch alg {
	case crypto.MD5:
		h = md5.New() // #nosec G401 -- Test fixture builds legacy Authenticode digests.
	case crypto.SHA1:
		h = sha1.New() // #nosec G401 -- Test fixture builds legacy Authenticode digests.
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		panic(fmt.Sprintf("unsupported hash %v", alg))
	}
	_, _ = h.Write(b)
	return h.Sum(nil)
}
