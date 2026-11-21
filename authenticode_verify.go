package pe

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// MaxAuthenticodeVerifyOps bounds cumulative signature and certificate-chain
// verification work performed by a single verification call when
// [AuthenticodeVerifyOptions.MaxVerifyOps] is zero.
const MaxAuthenticodeVerifyOps = 512

var (
	oidPKCS7Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	oidDigestMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidDigestSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidOIWSHA1WithRSA  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

// AuthenticodeVerificationStatus identifies the outcome of an individual
// Authenticode verification claim.
type AuthenticodeVerificationStatus uint8

const (
	// AuthenticodeStatusUnchecked indicates a check was skipped or lacked a
	// required caller input (for example, chain trust when Roots is nil).
	AuthenticodeStatusUnchecked AuthenticodeVerificationStatus = iota
	// AuthenticodeStatusValid indicates the checked claim succeeded under the
	// configured options.
	AuthenticodeStatusValid
	// AuthenticodeStatusInvalid indicates the checked claim failed structural,
	// cryptographic, binding, attribute, or validity-time verification.
	AuthenticodeStatusInvalid
	// AuthenticodeStatusUnsupported indicates the structure relies on a digest,
	// signature algorithm, or SignerInfo form unsupported for offline checks.
	AuthenticodeStatusUnsupported
)

// String returns the lowercase name of s.
func (s AuthenticodeVerificationStatus) String() string {
	switch s {
	case AuthenticodeStatusUnchecked:
		return "unchecked"
	case AuthenticodeStatusValid:
		return "valid"
	case AuthenticodeStatusInvalid:
		return "invalid"
	case AuthenticodeStatusUnsupported:
		return "unsupported"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// AuthenticodeVerifyOptions configures offline Authenticode integrity,
// timestamp, and optional certificate-chain trust verification.
//
// Zero options perform offline PE image digest, CMS signed-attribute and
// signer-signature, and timestamp-token integrity checks without consulting
// ambient operating-system trust stores or making network requests (AIA, OCSP,
// or CRL).
type AuthenticodeVerifyOptions struct {
	// Roots supplies explicit trusted root certificates for publisher and
	// timestamp chains. When nil, chain trust is not checked against OS trust
	// and Trust.Status stays [AuthenticodeStatusUnchecked].
	Roots *x509.CertPool

	// TimestampRoots optionally overrides Roots when verifying timestamp
	// authority chains. When nil, Roots is used if non-nil.
	TimestampRoots *x509.CertPool

	// Intermediates supplies additional intermediate CA certificates beyond the
	// certificates embedded in each SignedData certificate set.
	Intermediates *x509.CertPool

	// CRLs supplies additional offline X.509 certificate revocation lists
	// evaluated alongside CRLs embedded in SignedData.
	CRLs []*x509.RevocationList

	// VerificationTime pins the evaluation timestamp for certificate validity
	// windows and chain verification. When zero, verified in-bounds timestamps
	// provide the effective evaluation time for signer certificates, or the
	// current system time is used only if Roots is non-nil or UseCurrentTime is
	// true.
	VerificationTime time.Time

	// UseCurrentTime evaluates signer certificate validity against time.Now()
	// when VerificationTime is zero and no valid timestamp is present.
	UseCurrentTime bool

	// SkipImageDigest skips PE image hashing (leaving Digest.Status as
	// [AuthenticodeStatusUnchecked]). Useful when callers already computed or do
	// not require PE image digest checks.
	SkipImageDigest bool

	// StrictPadding treats trailing NUL padding after a PKCS#7 SignedData TLV
	// as invalid ([AuthenticodeStatusInvalid]) in [AuthenticodeSignatureVerification.Padding],
	// mirroring Windows EnableCertPaddingCheck (CVE-2013-3900) hardening.
	StrictPadding bool

	// KeyUsages overrides extended key usage requirements for publisher chain
	// verification when Roots is non-nil. Defaults to [x509.ExtKeyUsageCodeSigning].
	KeyUsages []x509.ExtKeyUsage

	// TimestampKeyUsages overrides extended key usage requirements for TSA chain
	// verification when Roots or TimestampRoots is non-nil. Defaults to
	// [x509.ExtKeyUsageTimeStamping].
	TimestampKeyUsages []x509.ExtKeyUsage

	// MaxVerifyOps caps total signer, timestamp, and chain verification steps
	// performed per call. When <= 0, [MaxAuthenticodeVerifyOps] is used.
	MaxVerifyOps int
}

// AuthenticodeVerification summarizes offline verification results across all
// PKCS#7 Authenticode signatures extracted from a PE image.
type AuthenticodeVerification struct {
	Signatures []AuthenticodeSignatureVerification
}

// AuthenticodeSignatureVerification reports separated image-digest, CMS
// signature, validity-time, timestamp, and trust-chain claims for one
// [AuthenticodeSignature].
type AuthenticodeSignatureVerification struct {
	SignatureIndex int
	RecordOffset   uint32
	NestedDepth    int
	Digest         AuthenticodeDigestVerification
	Padding        AuthenticodeCheck
	Signers        []AuthenticodeSignerVerification
}

// AuthenticodeDigestVerification reports whether the PE image Authenticode
// digest matches SpcIndirectDataContent.MessageDigest.
type AuthenticodeDigestVerification struct {
	Status       AuthenticodeVerificationStatus
	Algorithm    crypto.Hash
	AlgorithmOID asn1.ObjectIdentifier
	Expected     []byte
	Computed     []byte
	Reason       string
}

// AuthenticodeCheck records the outcome of a single focused verification
// assertion along with an optional diagnostic reason.
type AuthenticodeCheck struct {
	Status AuthenticodeVerificationStatus
	Reason string
}

// AuthenticodeCMSVerification reports offline cryptographic verification of CMS
// authenticated attributes and the asymmetric signer signature.
type AuthenticodeCMSVerification struct {
	Status             AuthenticodeVerificationStatus
	DigestAlgorithm    crypto.Hash
	SignatureAlgorithm x509.SignatureAlgorithm
	Reason             string
}

// AuthenticodeTrustVerification reports offline X.509 certificate-chain
// validation against caller-provided trust roots.
type AuthenticodeTrustVerification struct {
	Status AuthenticodeVerificationStatus
	Chains [][]*x509.Certificate
	Reason string
}

// AuthenticodeSignerVerification reports separated verification claims for one
// CMS SignerInfo within an Authenticode signature.
type AuthenticodeSignerVerification struct {
	SignerIndex       int
	SignerCertificate *x509.Certificate
	Binding           AuthenticodeCheck
	CMS               AuthenticodeCMSVerification
	ValidityTime      time.Time
	SignerValidity    AuthenticodeCheck
	Timestamps        []AuthenticodeTimestampVerification
	Trust             AuthenticodeTrustVerification
	Revocation        AuthenticodeCheck
}

// AuthenticodeTimestampVerification reports separated verification claims for a
// PKCS#9 countersignature or RFC 3161 timestamp token.
type AuthenticodeTimestampVerification struct {
	TimestampIndex int
	Kind           AuthenticodeTimestampKind
	SigningTime    time.Time
	TSACertificate *x509.Certificate
	Imprint        AuthenticodeCheck
	CMS            AuthenticodeCMSVerification
	ValidityBounds AuthenticodeCheck
	Trust          AuthenticodeTrustVerification
}

type authVerifyBudget struct {
	ops int
	max int
}

func (b *authVerifyBudget) consume(reason string) error {
	b.ops++
	if b.ops > b.max {
		return fmt.Errorf("%w: verification work %d exceeds limit %d (%s)", ErrAuthenticodeLimit, b.ops, b.max, reason)
	}
	return nil
}

// VerifyAuthenticode parses Authenticode PKCS#7 signatures in data and verifies
// image digests, CMS signatures, timestamps, and optional certificate-chain
// trust offline according to opts.
//
// Callers must pass the same byte slice passed to [New]. If data contains no
// Authenticode PKCS#7 signatures, VerifyAuthenticode returns an empty
// [AuthenticodeVerification] and nil error.
func (f *File) VerifyAuthenticode(data []byte, opts AuthenticodeVerifyOptions) (AuthenticodeVerification, error) {
	sigs, err := f.AuthenticodeSignatures(data)
	if err != nil {
		return AuthenticodeVerification{}, err
	}
	return f.VerifyAuthenticodeSignatures(data, sigs, opts)
}

// VerifyAuthenticodeSignatures verifies pre-parsed Authenticode signatures
// against data offline according to opts.
func (f *File) VerifyAuthenticodeSignatures(data []byte, sigs []AuthenticodeSignature, opts AuthenticodeVerifyOptions) (AuthenticodeVerification, error) {
	if f == nil || (!f.Is32Bit() && !f.Is64Bit()) {
		return AuthenticodeVerification{}, fmt.Errorf("%w: file headers not parsed", ErrInvalidHeader)
	}
	if len(sigs) == 0 {
		return AuthenticodeVerification{}, nil
	}

	maxOps := opts.MaxVerifyOps
	if maxOps <= 0 {
		maxOps = MaxAuthenticodeVerifyOps
	}
	budget := &authVerifyBudget{max: maxOps}

	var computedDigests map[crypto.Hash][]byte
	if !opts.SkipImageDigest {
		var err error
		computedDigests, err = f.computeSignatureImageDigests(data, sigs)
		if err != nil {
			return AuthenticodeVerification{}, err
		}
	}

	var now time.Time
	if opts.VerificationTime.IsZero() && (opts.UseCurrentTime || opts.Roots != nil || opts.TimestampRoots != nil) {
		now = time.Now().UTC()
	}

	out := AuthenticodeVerification{
		Signatures: make([]AuthenticodeSignatureVerification, len(sigs)),
	}
	for i, sig := range sigs {
		if err := budget.consume("signature"); err != nil {
			return AuthenticodeVerification{}, err
		}
		sigRes, err := verifySingleAuthenticodeSignature(i, sig, computedDigests, opts, now, budget)
		if err != nil {
			return AuthenticodeVerification{}, err
		}
		out.Signatures[i] = sigRes
	}
	return out, nil
}

func (f *File) computeSignatureImageDigests(data []byte, sigs []AuthenticodeSignature) (map[crypto.Hash][]byte, error) {
	if _, err := buildAuthenticodeDigestPlan(f, data); err != nil {
		return nil, err
	}
	if len(sigs) == 0 {
		return nil, nil
	}

	var algs []crypto.Hash
	seen := make(map[crypto.Hash]struct{}, 4)
	for _, sig := range sigs {
		if !sig.ContentType.Equal(OIDSpcIndirectDataContent) || sig.IndirectData == nil {
			continue
		}
		alg, ok := digestAlgorithmFromOID(sig.IndirectData.DigestAlgorithm.Algorithm)
		if !ok {
			continue
		}
		if _, exists := seen[alg]; !exists {
			seen[alg] = struct{}{}
			algs = append(algs, alg)
		}
	}
	if len(algs) == 0 {
		return nil, nil
	}
	digests, err := f.AuthenticodeDigests(data, algs...)
	if err != nil {
		return nil, err
	}
	res := make(map[crypto.Hash][]byte, len(algs))
	for i, alg := range algs {
		res[alg] = digests[i]
	}
	return res, nil
}

func verifySingleAuthenticodeSignature(
	sigIndex int,
	sig AuthenticodeSignature,
	computedDigests map[crypto.Hash][]byte,
	opts AuthenticodeVerifyOptions,
	now time.Time,
	budget *authVerifyBudget,
) (AuthenticodeSignatureVerification, error) {
	res := AuthenticodeSignatureVerification{
		SignatureIndex: sigIndex,
		RecordOffset:   sig.RecordOffset,
		NestedDepth:    sig.NestedDepth,
		Digest:         verifyImageDigest(sig, computedDigests, opts.SkipImageDigest),
		Padding:        verifySignaturePadding(sig.TrailingPaddingBytes, opts.StrictPadding),
	}

	if len(sig.Signers) == 0 {
		return res, nil
	}

	var intermediatePool *x509.CertPool
	if opts.Roots != nil || opts.TimestampRoots != nil {
		intermediatePool = buildIntermediatePool(opts.Intermediates, sig.Certificates)
	}

	res.Signers = make([]AuthenticodeSignerVerification, len(sig.Signers))
	for i, signer := range sig.Signers {
		if err := budget.consume("signer"); err != nil {
			return AuthenticodeSignatureVerification{}, err
		}
		signerRes, err := verifyAuthenticodeSigner(i, sig, signer, intermediatePool, opts, now, budget)
		if err != nil {
			return AuthenticodeSignatureVerification{}, err
		}
		res.Signers[i] = signerRes
	}
	return res, nil
}

func verifyImageDigest(sig AuthenticodeSignature, computedDigests map[crypto.Hash][]byte, skip bool) AuthenticodeDigestVerification {
	if skip {
		return AuthenticodeDigestVerification{
			Status: AuthenticodeStatusUnchecked,
			Reason: "image digest verification skipped",
		}
	}
	if !sig.ContentType.Equal(OIDSpcIndirectDataContent) {
		return AuthenticodeDigestVerification{
			Status: AuthenticodeStatusInvalid,
			Reason: fmt.Sprintf("unexpected CMS content type %s", sig.ContentType),
		}
	}
	if sig.IndirectData == nil {
		return AuthenticodeDigestVerification{
			Status: AuthenticodeStatusInvalid,
			Reason: "missing SpcIndirectDataContent",
		}
	}
	algOID := sig.IndirectData.DigestAlgorithm.Algorithm
	alg, ok := digestAlgorithmFromOID(algOID)
	if !ok {
		return AuthenticodeDigestVerification{
			Status:       AuthenticodeStatusUnsupported,
			AlgorithmOID: cloneOID(algOID),
			Expected:     bytes.Clone(sig.IndirectData.Digest),
			Reason:       fmt.Sprintf("unsupported image digest algorithm %s", algOID),
		}
	}
	computed := computedDigests[alg]
	expected := sig.IndirectData.Digest
	out := AuthenticodeDigestVerification{
		Algorithm:    alg,
		AlgorithmOID: cloneOID(algOID),
		Expected:     bytes.Clone(expected),
		Computed:     bytes.Clone(computed),
	}
	if len(computed) == 0 || subtle.ConstantTimeCompare(expected, computed) != 1 {
		out.Status = AuthenticodeStatusInvalid
		out.Reason = "computed image digest does not match SpcIndirectDataContent"
		return out
	}
	out.Status = AuthenticodeStatusValid
	return out
}

func verifySignaturePadding(trailingBytes int, strict bool) AuthenticodeCheck {
	if trailingBytes == 0 {
		return AuthenticodeCheck{Status: AuthenticodeStatusValid}
	}
	if strict {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: fmt.Sprintf("PKCS#7 payload has %d trailing padding bytes", trailingBytes),
		}
	}
	return AuthenticodeCheck{
		Status: AuthenticodeStatusUnchecked,
		Reason: fmt.Sprintf("PKCS#7 payload has %d trailing NUL padding bytes (StrictPadding disabled)", trailingBytes),
	}
}

func verifyAuthenticodeSigner(
	signerIndex int,
	sig AuthenticodeSignature,
	signer AuthenticodeSigner,
	intermediatePool *x509.CertPool,
	opts AuthenticodeVerifyOptions,
	now time.Time,
	budget *authVerifyBudget,
) (AuthenticodeSignerVerification, error) {
	out := AuthenticodeSignerVerification{
		SignerIndex: signerIndex,
	}

	signerCert, binding := resolveSignerCertificate(signer, sig.Certificates)
	out.SignerCertificate = signerCert
	out.Binding = binding

	contentPayload, ok := signatureEncapDigestPayload(sig)
	if !ok {
		out.CMS = AuthenticodeCMSVerification{
			Status: AuthenticodeStatusInvalid,
			Reason: "malformed or missing encapsulated content",
		}
	} else {
		out.CMS = verifySignerCMS(signer, signerCert, binding, sig.ContentType, false, contentPayload)
	}

	out.Timestamps = make([]AuthenticodeTimestampVerification, len(signer.Timestamps))
	var earliestValidTS time.Time
	tsRoots := opts.TimestampRoots
	if tsRoots == nil {
		tsRoots = opts.Roots
	}
	for i, ts := range signer.Timestamps {
		if err := budget.consume("timestamp"); err != nil {
			return AuthenticodeSignerVerification{}, err
		}
		tsRes, err := verifyAuthenticodeTimestamp(i, ts, signer, signerCert, sig.Certificates, opts, tsRoots, budget)
		if err != nil {
			return AuthenticodeSignerVerification{}, err
		}
		out.Timestamps[i] = tsRes

		if timestampExtendsSignerValidity(tsRes, tsRoots != nil) {
			if earliestValidTS.IsZero() || tsRes.SigningTime.Before(earliestValidTS) {
				earliestValidTS = tsRes.SigningTime
			}
		}
	}

	evalTime := resolveSignerEvalTime(opts, earliestValidTS, now)
	out.ValidityTime = evalTime
	out.SignerValidity = checkCertificateTimeWindow(signerCert, binding.Status, evalTime)

	if opts.Roots == nil {
		out.Trust = AuthenticodeTrustVerification{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no trust roots provided",
		}
	} else {
		if err := budget.consume("publisher chain"); err != nil {
			return AuthenticodeSignerVerification{}, err
		}
		keyUsages := opts.KeyUsages
		if len(keyUsages) == 0 {
			keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}
		out.Trust = verifyCertificateTrust(signerCert, binding.Status, opts.Roots, intermediatePool, evalTime, keyUsages)
	}

	rev, err := checkSignerRevocation(signerCert, binding.Status, sig.Certificates, out.Trust.Chains, sig.CRLs, opts.CRLs, evalTime, budget)
	if err != nil {
		return AuthenticodeSignerVerification{}, err
	}
	out.Revocation = rev
	return out, nil
}

func timestampExtendsSignerValidity(ts AuthenticodeTimestampVerification, checkingTrust bool) bool {
	if ts.Imprint.Status != AuthenticodeStatusValid ||
		ts.CMS.Status != AuthenticodeStatusValid ||
		ts.ValidityBounds.Status != AuthenticodeStatusValid {
		return false
	}
	if checkingTrust && ts.Trust.Status != AuthenticodeStatusValid {
		return false
	}
	return !ts.SigningTime.IsZero()
}

func resolveSignerEvalTime(opts AuthenticodeVerifyOptions, validTSTime, now time.Time) time.Time {
	if !opts.VerificationTime.IsZero() {
		return opts.VerificationTime.UTC()
	}
	if !validTSTime.IsZero() {
		return validTSTime.UTC()
	}
	return now
}

func signatureEncapDigestPayload(sig AuthenticodeSignature) ([]byte, bool) {
	if len(sig.Content) == 0 {
		return nil, false
	}
	if sig.encapContentKnown {
		if sig.encapContentWrapped {
			return sig.Content, true
		}
		start, end, ok := readDERHeader(sig.Content, 0)
		if !ok || end != len(sig.Content) {
			return nil, false
		}
		return sig.Content[start:end], true
	}
	// Fallback when callers construct AuthenticodeSignature manually instead of parsing.
	if sig.Version == 1 && sig.ContentType.Equal(OIDSpcIndirectDataContent) {
		start, end, ok := readDERHeader(sig.Content, 0)
		if !ok || end != len(sig.Content) {
			return nil, false
		}
		return sig.Content[start:end], true
	}
	return sig.Content, true
}

func verifyAuthenticodeTimestamp(
	index int,
	ts AuthenticodeTimestamp,
	parentSigner AuthenticodeSigner,
	parentCert *x509.Certificate,
	parentCerts []*x509.Certificate,
	opts AuthenticodeVerifyOptions,
	tsRoots *x509.CertPool,
	budget *authVerifyBudget,
) (AuthenticodeTimestampVerification, error) {
	out := AuthenticodeTimestampVerification{
		TimestampIndex: index,
		Kind:           ts.Kind,
		SigningTime:    ts.SigningTime,
	}

	switch ts.Kind {
	case AuthenticodeTimestampPKCS9:
		verifyPKCS9Timestamp(&out, ts, parentSigner, parentCert, parentCerts, opts, tsRoots, budget)
		if budget.ops > budget.max {
			return AuthenticodeTimestampVerification{}, fmt.Errorf("%w: verification work %d exceeds limit %d (timestamp chain)", ErrAuthenticodeLimit, budget.ops, budget.max)
		}
		return out, nil
	case AuthenticodeTimestampRFC3161:
		verifyRFC3161Timestamp(&out, ts, parentSigner, parentCert, parentCerts, opts, tsRoots, budget)
		if budget.ops > budget.max {
			return AuthenticodeTimestampVerification{}, fmt.Errorf("%w: verification work %d exceeds limit %d (timestamp chain)", ErrAuthenticodeLimit, budget.ops, budget.max)
		}
		return out, nil
	default:
		out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusUnsupported, Reason: "unsupported timestamp kind"}
		out.CMS = AuthenticodeCMSVerification{Status: AuthenticodeStatusUnsupported, Reason: "unsupported timestamp kind"}
		out.ValidityBounds = AuthenticodeCheck{Status: AuthenticodeStatusUnsupported, Reason: "unsupported timestamp kind"}
		out.Trust = AuthenticodeTrustVerification{Status: AuthenticodeStatusUnsupported, Reason: "unsupported timestamp kind"}
		return out, nil
	}
}

func verifyPKCS9Timestamp(
	out *AuthenticodeTimestampVerification,
	ts AuthenticodeTimestamp,
	parentSigner AuthenticodeSigner,
	parentCert *x509.Certificate,
	parentCerts []*x509.Certificate,
	opts AuthenticodeVerifyOptions,
	tsRoots *x509.CertPool,
	budget *authVerifyBudget,
) {
	if len(ts.Signers) != 1 {
		out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "countersignature must contain one SignerInfo"}
		out.CMS = AuthenticodeCMSVerification{Status: AuthenticodeStatusInvalid, Reason: "countersignature must contain one SignerInfo"}
		out.ValidityBounds = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "missing countersigner"}
		out.Trust = invalidOrUncheckedTrust(tsRoots != nil, "missing countersigner")
		return
	}
	cs := ts.Signers[0]
	tsaCert, binding := resolveSignerCertificate(cs, parentCerts)
	out.TSACertificate = tsaCert

	digestAlg, ok := digestAlgorithmFromOID(cs.DigestAlgorithm.Algorithm)
	if !ok {
		out.Imprint = AuthenticodeCheck{
			Status: AuthenticodeStatusUnsupported,
			Reason: fmt.Sprintf("unsupported countersignature digest algorithm %s", cs.DigestAlgorithm.Algorithm),
		}
	} else if len(parentSigner.Signature) == 0 || len(cs.MessageDigest) == 0 {
		out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "missing countersignature messageDigest or parent signature"}
	} else {
		computed := computeHash(digestAlg, parentSigner.Signature)
		if subtle.ConstantTimeCompare(cs.MessageDigest, computed) == 1 {
			out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusValid}
		} else {
			out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "countersignature messageDigest does not match parent signature"}
		}
	}

	// RFC 2985 section 5.3.6: PKCS#9 countersignatures omit contentType or set pkcs7-data.
	out.CMS = verifySignerCMS(cs, tsaCert, binding, oidPKCS7Data, true, parentSigner.Signature)
	out.ValidityBounds = checkTimestampBounds(ts.HasSigningTime, ts.SigningTime, tsaCert, binding.Status, parentCert)

	var pool *x509.CertPool
	if tsRoots != nil {
		pool = buildIntermediatePool(opts.Intermediates, parentCerts)
	}
	verifyTSATrust(out, tsaCert, binding.Status, ts.SigningTime, opts, tsRoots, pool, budget)
}

func verifyRFC3161Timestamp(
	out *AuthenticodeTimestampVerification,
	ts AuthenticodeTimestamp,
	parentSigner AuthenticodeSigner,
	parentCert *x509.Certificate,
	parentCerts []*x509.Certificate,
	opts AuthenticodeVerifyOptions,
	tsRoots *x509.CertPool,
	budget *authVerifyBudget,
) {
	if !ts.contentType.Equal(OIDTSTInfo) || len(ts.content) == 0 {
		out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "RFC 3161 timestamp missing TSTInfo content"}
		out.CMS = AuthenticodeCMSVerification{Status: AuthenticodeStatusInvalid, Reason: "RFC 3161 timestamp missing TSTInfo content"}
		out.ValidityBounds = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "RFC 3161 timestamp missing TSTInfo content"}
		out.Trust = invalidOrUncheckedTrust(tsRoots != nil, "RFC 3161 timestamp missing TSTInfo content")
		return
	}

	if imprintAlg, ok := digestAlgorithmFromOID(ts.DigestAlgorithm.Algorithm); !ok {
		out.Imprint = AuthenticodeCheck{
			Status: AuthenticodeStatusUnsupported,
			Reason: fmt.Sprintf("unsupported timestamp imprint algorithm %s", ts.DigestAlgorithm.Algorithm),
		}
	} else if len(parentSigner.Signature) == 0 || len(ts.Digest) == 0 {
		out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "missing TSTInfo messageImprint or parent signature"}
	} else {
		computed := computeHash(imprintAlg, parentSigner.Signature)
		if subtle.ConstantTimeCompare(ts.Digest, computed) == 1 {
			out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusValid}
		} else {
			out.Imprint = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "TSTInfo messageImprint does not match parent signature"}
		}
	}

	if len(ts.Signers) != 1 {
		out.CMS = AuthenticodeCMSVerification{Status: AuthenticodeStatusInvalid, Reason: "RFC 3161 timestamp must contain one SignerInfo"}
		out.ValidityBounds = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "missing timestamp signer"}
		out.Trust = invalidOrUncheckedTrust(tsRoots != nil, "missing timestamp signer")
		return
	}

	tsSigner := ts.Signers[0]
	tsaCert, binding := resolveSignerCertificate(tsSigner, ts.Certificates)
	if binding.Status == AuthenticodeStatusInvalid && len(ts.Certificates) == 0 {
		// Fall back to parent SignedData cert bag when the token itself omits certificates.
		tsaCert, binding = resolveSignerCertificate(tsSigner, parentCerts)
	}
	out.TSACertificate = tsaCert

	payload := ts.content
	if ts.encapContentKnown && !ts.encapContentWrapped {
		start, end, ok := readDERHeader(ts.content, 0)
		if !ok || end != len(ts.content) {
			out.CMS = AuthenticodeCMSVerification{Status: AuthenticodeStatusInvalid, Reason: "malformed RFC 3161 TSTInfo payload"}
			out.ValidityBounds = AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "malformed RFC 3161 TSTInfo payload"}
			out.Trust = invalidOrUncheckedTrust(tsRoots != nil, "malformed RFC 3161 TSTInfo payload")
			return
		}
		payload = ts.content[start:end]
	}

	out.CMS = verifySignerCMS(tsSigner, tsaCert, binding, OIDTSTInfo, false, payload)
	out.ValidityBounds = checkTimestampBounds(ts.HasSigningTime, ts.SigningTime, tsaCert, binding.Status, parentCert)

	var pool *x509.CertPool
	if tsRoots != nil {
		tsCerts := make([]*x509.Certificate, 0, len(ts.Certificates)+len(parentCerts))
		tsCerts = append(tsCerts, ts.Certificates...)
		tsCerts = append(tsCerts, parentCerts...)
		pool = buildIntermediatePool(opts.Intermediates, tsCerts)
	}
	verifyTSATrust(out, tsaCert, binding.Status, ts.SigningTime, opts, tsRoots, pool, budget)
}

func verifyTSATrust(
	out *AuthenticodeTimestampVerification,
	tsaCert *x509.Certificate,
	bindingStatus AuthenticodeVerificationStatus,
	signingTime time.Time,
	opts AuthenticodeVerifyOptions,
	tsRoots *x509.CertPool,
	intermediates *x509.CertPool,
	budget *authVerifyBudget,
) {
	if tsRoots == nil {
		out.Trust = AuthenticodeTrustVerification{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no timestamp trust roots provided",
		}
		return
	}
	if budget != nil {
		if err := budget.consume("timestamp chain"); err != nil {
			// The caller returns ErrAuthenticodeLimit for an exhausted budget.
			return
		}
	}
	evalTime := signingTime
	if !opts.VerificationTime.IsZero() {
		evalTime = opts.VerificationTime.UTC()
	}
	if evalTime.IsZero() && tsaCert != nil {
		evalTime = time.Now().UTC()
	}
	keyUsages := opts.TimestampKeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	out.Trust = verifyCertificateTrust(tsaCert, bindingStatus, tsRoots, intermediates, evalTime, keyUsages)
}

func invalidOrUncheckedTrust(rootsProvided bool, reason string) AuthenticodeTrustVerification {
	if !rootsProvided {
		return AuthenticodeTrustVerification{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no timestamp trust roots provided",
		}
	}
	return AuthenticodeTrustVerification{
		Status: AuthenticodeStatusInvalid,
		Reason: reason,
	}
}

func checkTimestampBounds(
	hasSigningTime bool,
	signingTime time.Time,
	tsaCert *x509.Certificate,
	tsaBinding AuthenticodeVerificationStatus,
	parentCert *x509.Certificate,
) AuthenticodeCheck {
	if !hasSigningTime || signingTime.IsZero() {
		return AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "timestamp missing signing time"}
	}
	if tsaBinding != AuthenticodeStatusValid || tsaCert == nil {
		return AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "missing or ambiguous TSA certificate"}
	}
	if signingTime.Before(tsaCert.NotBefore) || signingTime.After(tsaCert.NotAfter) {
		return AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "timestamp signing time is outside TSA certificate validity"}
	}
	if parentCert == nil {
		return AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "missing parent signer certificate"}
	}
	if signingTime.Before(parentCert.NotBefore) || signingTime.After(parentCert.NotAfter) {
		return AuthenticodeCheck{Status: AuthenticodeStatusInvalid, Reason: "timestamp signing time is outside signer certificate validity"}
	}
	return AuthenticodeCheck{Status: AuthenticodeStatusValid}
}

func checkCertificateTimeWindow(cert *x509.Certificate, bindingStatus AuthenticodeVerificationStatus, evalTime time.Time) AuthenticodeCheck {
	if evalTime.IsZero() {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no verification time or valid timestamp",
		}
	}
	if bindingStatus != AuthenticodeStatusValid || cert == nil {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: "missing or ambiguous certificate",
		}
	}
	if evalTime.Before(cert.NotBefore) {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: "certificate is not yet valid at verification time",
		}
	}
	if evalTime.After(cert.NotAfter) {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: "certificate is expired at verification time",
		}
	}
	return AuthenticodeCheck{Status: AuthenticodeStatusValid}
}

func resolveSignerCertificate(signer AuthenticodeSigner, certs []*x509.Certificate) (*x509.Certificate, AuthenticodeCheck) {
	if signer.Version != 1 && signer.Version != 3 {
		return nil, AuthenticodeCheck{
			Status: AuthenticodeStatusUnsupported,
			Reason: fmt.Sprintf("unsupported SignerInfo version %d", signer.Version),
		}
	}

	byIssuerSerial := len(signer.IssuerRaw) > 0 && signer.SerialNumber != nil
	bySubjectKeyID := !byIssuerSerial && len(signer.SubjectKeyID) > 0
	if !byIssuerSerial && !bySubjectKeyID {
		return nil, AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: "signer identifier missing issuer/serial and subject key identifier",
		}
	}

	var match *x509.Certificate
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		matched := false
		if byIssuerSerial {
			matched = cert.SerialNumber != nil &&
				bytes.Equal(cert.RawIssuer, signer.IssuerRaw) &&
				cert.SerialNumber.Cmp(signer.SerialNumber) == 0
		} else {
			matched = len(cert.SubjectKeyId) > 0 && bytes.Equal(cert.SubjectKeyId, signer.SubjectKeyID)
		}
		if !matched {
			continue
		}
		if match == nil {
			match = cert
			continue
		}
		if !bytes.Equal(match.Raw, cert.Raw) {
			return nil, AuthenticodeCheck{
				Status: AuthenticodeStatusInvalid,
				Reason: "ambiguous signer identifier matched multiple distinct certificates",
			}
		}
	}
	if match == nil {
		return nil, AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: "signer certificate not found in SignedData certificates",
		}
	}
	return match, AuthenticodeCheck{Status: AuthenticodeStatusValid}
}

func verifySignerCMS(
	signer AuthenticodeSigner,
	signerCert *x509.Certificate,
	binding AuthenticodeCheck,
	expectedContentType asn1.ObjectIdentifier,
	allowMissingContentType bool,
	contentPayload []byte,
) AuthenticodeCMSVerification {
	digestAlg, ok := digestAlgorithmFromOID(signer.DigestAlgorithm.Algorithm)
	if !ok {
		return AuthenticodeCMSVerification{
			Status: AuthenticodeStatusUnsupported,
			Reason: fmt.Sprintf("unsupported CMS digest algorithm %s", signer.DigestAlgorithm.Algorithm),
		}
	}

	hasSignedAttrs := len(signer.RawAuthenticatedAttributes) > 0 || len(signer.AuthenticatedAttributes) > 0
	if !hasSignedAttrs && (!expectedContentType.Equal(oidPKCS7Data) || allowMissingContentType) {
		return AuthenticodeCMSVerification{
			Status:          AuthenticodeStatusInvalid,
			DigestAlgorithm: digestAlg,
			Reason:          "missing required CMS signed attributes",
		}
	}

	var signedData []byte
	if hasSignedAttrs {
		if status, reason := validateSignedAttributes(signer.AuthenticatedAttributes, expectedContentType, allowMissingContentType, contentPayload, digestAlg, signerCert, binding.Status); status != AuthenticodeStatusValid {
			return AuthenticodeCMSVerification{
				Status:          status,
				DigestAlgorithm: digestAlg,
				Reason:          reason,
			}
		}
		signedData = signer.RawAuthenticatedAttributes
	} else {
		signedData = contentPayload
	}

	sigPlan, status, reason := resolveSignaturePlan(signer.SignatureAlgorithm, digestAlg)
	if status != AuthenticodeStatusValid {
		return AuthenticodeCMSVerification{
			Status:             status,
			DigestAlgorithm:    digestAlg,
			SignatureAlgorithm: sigPlan.x509Alg,
			Reason:             reason,
		}
	}

	if binding.Status != AuthenticodeStatusValid {
		bindingStatus := binding.Status
		if bindingStatus == AuthenticodeStatusUnchecked {
			bindingStatus = AuthenticodeStatusInvalid
		}
		return AuthenticodeCMSVerification{
			Status:             bindingStatus,
			DigestAlgorithm:    digestAlg,
			SignatureAlgorithm: sigPlan.x509Alg,
			Reason:             binding.Reason,
		}
	}
	if signerCert == nil {
		return AuthenticodeCMSVerification{
			Status:             AuthenticodeStatusInvalid,
			DigestAlgorithm:    digestAlg,
			SignatureAlgorithm: sigPlan.x509Alg,
			Reason:             "missing signer certificate",
		}
	}

	if len(signer.Signature) == 0 {
		return AuthenticodeCMSVerification{
			Status:             AuthenticodeStatusInvalid,
			DigestAlgorithm:    digestAlg,
			SignatureAlgorithm: sigPlan.x509Alg,
			Reason:             "empty CMS signature",
		}
	}

	if err := verifyAsymmetricSignature(signerCert.PublicKey, sigPlan, signedData, signer.Signature); err != nil {
		return AuthenticodeCMSVerification{
			Status:             AuthenticodeStatusInvalid,
			DigestAlgorithm:    digestAlg,
			SignatureAlgorithm: sigPlan.x509Alg,
			Reason:             err.Error(),
		}
	}

	return AuthenticodeCMSVerification{
		Status:             AuthenticodeStatusValid,
		DigestAlgorithm:    digestAlg,
		SignatureAlgorithm: sigPlan.x509Alg,
	}
}

type rawESSCertID struct {
	CertHash     []byte
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type rawSigningCertificate struct {
	Certs    []rawESSCertID
	Policies asn1.RawValue `asn1:"optional"`
}

type rawESSCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

type rawSigningCertificateV2 struct {
	Certs    []rawESSCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

func validateSignedAttributes(
	attrs []AuthenticodeAttribute,
	expectedContentType asn1.ObjectIdentifier,
	allowMissingContentType bool,
	contentPayload []byte,
	digestAlg crypto.Hash,
	signerCert *x509.Certificate,
	bindingStatus AuthenticodeVerificationStatus,
) (AuthenticodeVerificationStatus, string) {
	seen := make(map[string]struct{}, len(attrs))
	var hasContentType bool
	var gotContentType asn1.ObjectIdentifier
	var hasMessageDigest bool
	var gotDigest []byte

	for _, attr := range attrs {
		key := attr.Type.String()
		if _, dup := seen[key]; dup {
			return AuthenticodeStatusInvalid, "duplicate signed attribute " + key
		}
		seen[key] = struct{}{}

		switch {
		case attr.Type.Equal(OIDContentType):
			if len(attr.Values) != 1 {
				return AuthenticodeStatusInvalid, "contentType attribute must have one value"
			}
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(attr.Values[0], &oid)
			if err != nil || len(rest) != 0 {
				return AuthenticodeStatusInvalid, "malformed contentType signed attribute"
			}
			hasContentType = true
			gotContentType = oid

		case attr.Type.Equal(OIDMessageDigest):
			if len(attr.Values) != 1 {
				return AuthenticodeStatusInvalid, "messageDigest attribute must have one value"
			}
			var digest []byte
			rest, err := asn1.Unmarshal(attr.Values[0], &digest)
			if err != nil || len(rest) != 0 {
				return AuthenticodeStatusInvalid, "malformed messageDigest signed attribute"
			}
			hasMessageDigest = true
			gotDigest = digest

		case attr.Type.Equal(OIDSigningTime):
			if len(attr.Values) != 1 {
				return AuthenticodeStatusInvalid, "signingTime attribute must have one value"
			}
			var t time.Time
			rest, err := asn1.Unmarshal(attr.Values[0], &t)
			if err != nil || len(rest) != 0 {
				return AuthenticodeStatusInvalid, "malformed signingTime signed attribute"
			}

		case attr.Type.Equal(OIDSpcSpOpusInfo):
			if len(attr.Values) > 1 {
				return AuthenticodeStatusInvalid, "SpcSpOpusInfo attribute must have at most one value"
			}

		case attr.Type.Equal(oidSigningCertificate):
			if status, reason := validateSigningCertificateAttr(attr, signerCert, bindingStatus); status != AuthenticodeStatusValid {
				return status, reason
			}

		case attr.Type.Equal(oidSigningCertificateV2):
			if status, reason := validateSigningCertificateV2Attr(attr, signerCert, bindingStatus); status != AuthenticodeStatusValid {
				return status, reason
			}
		}
	}

	if !hasMessageDigest {
		return AuthenticodeStatusInvalid, "missing messageDigest signed attribute"
	}
	if hasContentType {
		if len(expectedContentType) > 0 && !gotContentType.Equal(expectedContentType) {
			return AuthenticodeStatusInvalid, fmt.Sprintf("signed contentType %s does not match encapsulated content type %s", gotContentType, expectedContentType)
		}
	} else if !allowMissingContentType {
		return AuthenticodeStatusInvalid, "missing contentType signed attribute"
	}

	computed := computeHash(digestAlg, contentPayload)
	if subtle.ConstantTimeCompare(gotDigest, computed) != 1 {
		return AuthenticodeStatusInvalid, "signed messageDigest does not match encapsulated content digest"
	}
	return AuthenticodeStatusValid, ""
}

func validateSigningCertificateAttr(attr AuthenticodeAttribute, signerCert *x509.Certificate, bindingStatus AuthenticodeVerificationStatus) (AuthenticodeVerificationStatus, string) {
	if len(attr.Values) != 1 {
		return AuthenticodeStatusInvalid, "signingCertificate attribute must have one value"
	}
	var sc rawSigningCertificate
	rest, err := asn1.Unmarshal(attr.Values[0], &sc)
	if err != nil || len(rest) != 0 || len(sc.Certs) == 0 {
		return AuthenticodeStatusInvalid, "malformed signingCertificate signed attribute"
	}
	if bindingStatus == AuthenticodeStatusValid && signerCert != nil {
		want := computeHash(crypto.SHA1, signerCert.Raw)
		if subtle.ConstantTimeCompare(sc.Certs[0].CertHash, want) != 1 {
			return AuthenticodeStatusInvalid, "signingCertificate hash does not match signer certificate"
		}
	}
	return AuthenticodeStatusValid, ""
}

func validateSigningCertificateV2Attr(attr AuthenticodeAttribute, signerCert *x509.Certificate, bindingStatus AuthenticodeVerificationStatus) (AuthenticodeVerificationStatus, string) {
	if len(attr.Values) != 1 {
		return AuthenticodeStatusInvalid, "signingCertificateV2 attribute must have one value"
	}
	var sc rawSigningCertificateV2
	rest, err := asn1.Unmarshal(attr.Values[0], &sc)
	if err != nil || len(rest) != 0 || len(sc.Certs) == 0 {
		return AuthenticodeStatusInvalid, "malformed signingCertificateV2 signed attribute"
	}
	alg := crypto.SHA256
	if len(sc.Certs[0].HashAlgorithm.Algorithm) > 0 {
		var ok bool
		alg, ok = digestAlgorithmFromOID(sc.Certs[0].HashAlgorithm.Algorithm)
		if !ok {
			return AuthenticodeStatusUnsupported, fmt.Sprintf("unsupported signingCertificateV2 hash algorithm %s", sc.Certs[0].HashAlgorithm.Algorithm)
		}
	}
	if bindingStatus == AuthenticodeStatusValid && signerCert != nil {
		want := computeHash(alg, signerCert.Raw)
		if subtle.ConstantTimeCompare(sc.Certs[0].CertHash, want) != 1 {
			return AuthenticodeStatusInvalid, "signingCertificateV2 hash does not match signer certificate"
		}
	}
	return AuthenticodeStatusValid, ""
}

type sigKeyKind uint8

const (
	sigKeyRSA sigKeyKind = iota + 1
	sigKeyRSAPSS
	sigKeyECDSA
	sigKeyEd25519
)

type signaturePlan struct {
	keyKind sigKeyKind
	hash    crypto.Hash
	x509Alg x509.SignatureAlgorithm
	pssSalt int
}

type rawRSAPSSParams struct {
	HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength       int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField     int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func resolveSignaturePlan(sigAlg pkix.AlgorithmIdentifier, signerDigest crypto.Hash) (signaturePlan, AuthenticodeVerificationStatus, string) {
	oid := sigAlg.Algorithm
	switch {
	case oid.Equal(oidRSAEncryption):
		return signaturePlan{
			keyKind: sigKeyRSA,
			hash:    signerDigest,
			x509Alg: rsaPKCS1AlgFromHash(signerDigest),
		}, AuthenticodeStatusValid, ""

	case oid.Equal(oidMD5WithRSA):
		return matchExplicitHashSig(sigKeyRSA, crypto.MD5, signerDigest, x509.MD5WithRSA)
	case oid.Equal(oidSHA1WithRSA), oid.Equal(oidOIWSHA1WithRSA):
		return matchExplicitHashSig(sigKeyRSA, crypto.SHA1, signerDigest, x509.SHA1WithRSA)
	case oid.Equal(oidSHA256WithRSA):
		return matchExplicitHashSig(sigKeyRSA, crypto.SHA256, signerDigest, x509.SHA256WithRSA)
	case oid.Equal(oidSHA384WithRSA):
		return matchExplicitHashSig(sigKeyRSA, crypto.SHA384, signerDigest, x509.SHA384WithRSA)
	case oid.Equal(oidSHA512WithRSA):
		return matchExplicitHashSig(sigKeyRSA, crypto.SHA512, signerDigest, x509.SHA512WithRSA)

	case oid.Equal(oidRSASSAPSS):
		return resolveRSAPSSPlan(sigAlg, signerDigest)

	case oid.Equal(oidECPublicKey):
		if signerDigest == crypto.MD5 {
			return signaturePlan{}, AuthenticodeStatusUnsupported, "ECDSA with MD5 is unsupported"
		}
		return signaturePlan{
			keyKind: sigKeyECDSA,
			hash:    signerDigest,
			x509Alg: ecdsaAlgFromHash(signerDigest),
		}, AuthenticodeStatusValid, ""

	case oid.Equal(oidECDSAWithSHA1):
		return matchExplicitHashSig(sigKeyECDSA, crypto.SHA1, signerDigest, x509.ECDSAWithSHA1)
	case oid.Equal(oidECDSAWithSHA256):
		return matchExplicitHashSig(sigKeyECDSA, crypto.SHA256, signerDigest, x509.ECDSAWithSHA256)
	case oid.Equal(oidECDSAWithSHA384):
		return matchExplicitHashSig(sigKeyECDSA, crypto.SHA384, signerDigest, x509.ECDSAWithSHA384)
	case oid.Equal(oidECDSAWithSHA512):
		return matchExplicitHashSig(sigKeyECDSA, crypto.SHA512, signerDigest, x509.ECDSAWithSHA512)

	case oid.Equal(oidEd25519):
		if signerDigest != crypto.SHA512 {
			return signaturePlan{}, AuthenticodeStatusInvalid, "SignerInfo DigestAlgorithm must be SHA-512 for Ed25519"
		}
		return signaturePlan{
			keyKind: sigKeyEd25519,
			hash:    signerDigest,
			x509Alg: x509.PureEd25519,
		}, AuthenticodeStatusValid, ""

	default:
		return signaturePlan{}, AuthenticodeStatusUnsupported, fmt.Sprintf("unsupported CMS signature algorithm %s", oid)
	}
}

func matchExplicitHashSig(kind sigKeyKind, sigHash, digestHash crypto.Hash, x509Alg x509.SignatureAlgorithm) (signaturePlan, AuthenticodeVerificationStatus, string) {
	if sigHash != digestHash {
		return signaturePlan{}, AuthenticodeStatusInvalid, "SignerInfo DigestAlgorithm does not match SignatureAlgorithm hash"
	}
	return signaturePlan{
		keyKind: kind,
		hash:    sigHash,
		x509Alg: x509Alg,
	}, AuthenticodeStatusValid, ""
}

func resolveRSAPSSPlan(sigAlg pkix.AlgorithmIdentifier, signerDigest crypto.Hash) (signaturePlan, AuthenticodeVerificationStatus, string) {
	pssHash := crypto.SHA1
	saltLen := 20

	if len(sigAlg.Parameters.FullBytes) > 0 {
		var params rawRSAPSSParams
		rest, err := asn1.Unmarshal(sigAlg.Parameters.FullBytes, &params)
		if err != nil || len(rest) != 0 {
			return signaturePlan{}, AuthenticodeStatusInvalid, "malformed RSASSA-PSS parameters"
		}
		if len(params.HashAlgorithm.Algorithm) > 0 {
			var ok bool
			pssHash, ok = digestAlgorithmFromOID(params.HashAlgorithm.Algorithm)
			if !ok {
				return signaturePlan{}, AuthenticodeStatusUnsupported, fmt.Sprintf("unsupported RSASSA-PSS hash algorithm %s", params.HashAlgorithm.Algorithm)
			}
		}
		if len(params.MaskGenAlgorithm.Algorithm) > 0 {
			if !params.MaskGenAlgorithm.Algorithm.Equal(oidMGF1) {
				return signaturePlan{}, AuthenticodeStatusUnsupported, fmt.Sprintf("unsupported RSASSA-PSS MGF algorithm %s", params.MaskGenAlgorithm.Algorithm)
			}
			if len(params.MaskGenAlgorithm.Parameters.FullBytes) > 0 {
				var mgfHash pkix.AlgorithmIdentifier
				rest, err := asn1.Unmarshal(params.MaskGenAlgorithm.Parameters.FullBytes, &mgfHash)
				if err != nil || len(rest) != 0 {
					return signaturePlan{}, AuthenticodeStatusInvalid, "malformed RSASSA-PSS MGF1 parameters"
				}
				gotMGFHash, ok := digestAlgorithmFromOID(mgfHash.Algorithm)
				if !ok {
					return signaturePlan{}, AuthenticodeStatusUnsupported, fmt.Sprintf("unsupported RSASSA-PSS MGF1 hash %s", mgfHash.Algorithm)
				}
				if gotMGFHash != pssHash {
					return signaturePlan{}, AuthenticodeStatusInvalid, "RSASSA-PSS MGF1 hash does not match PSS hash"
				}
			}
		}
		if params.SaltLength < 0 {
			return signaturePlan{}, AuthenticodeStatusInvalid, "negative RSASSA-PSS salt length"
		}
		saltLen = params.SaltLength
		if params.TrailerField != 1 {
			return signaturePlan{}, AuthenticodeStatusUnsupported, fmt.Sprintf("unsupported RSASSA-PSS trailer field %d", params.TrailerField)
		}
	}

	if pssHash != signerDigest {
		return signaturePlan{}, AuthenticodeStatusInvalid, "SignerInfo DigestAlgorithm does not match RSASSA-PSS hash"
	}
	if pssHash == crypto.MD5 {
		return signaturePlan{}, AuthenticodeStatusUnsupported, "RSASSA-PSS with MD5 is unsupported"
	}
	return signaturePlan{
		keyKind: sigKeyRSAPSS,
		hash:    pssHash,
		x509Alg: rsaPSSAlgFromHash(pssHash),
		pssSalt: saltLen,
	}, AuthenticodeStatusValid, ""
}

func verifyAsymmetricSignature(pub crypto.PublicKey, plan signaturePlan, signedData, signature []byte) error {
	switch plan.keyKind {
	case sigKeyRSA:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("signer key type mismatch: expected RSA public key")
		}
		digest := computeHash(plan.hash, signedData)
		if err := rsa.VerifyPKCS1v15(rsaPub, plan.hash, digest, signature); err != nil {
			return fmt.Errorf("RSA PKCS1v15 signature verification failed: %w", err)
		}
		return nil

	case sigKeyRSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("signer key type mismatch: expected RSA public key")
		}
		digest := computeHash(plan.hash, signedData)
		if err := rsa.VerifyPSS(rsaPub, plan.hash, digest, signature, &rsa.PSSOptions{SaltLength: plan.pssSalt}); err != nil {
			return fmt.Errorf("RSA-PSS signature verification failed: %w", err)
		}
		return nil

	case sigKeyECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("signer key type mismatch: expected ECDSA public key")
		}
		digest := computeHash(plan.hash, signedData)
		if !ecdsa.VerifyASN1(ecPub, digest, signature) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil

	case sigKeyEd25519:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("signer key type mismatch: expected Ed25519 public key")
		}
		if !ed25519.Verify(edPub, signedData, signature) {
			return errors.New("Ed25519 signature verification failed")
		}
		return nil

	default:
		return errors.New("unsupported signature plan")
	}
}

func verifyCertificateTrust(
	cert *x509.Certificate,
	bindingStatus AuthenticodeVerificationStatus,
	roots *x509.CertPool,
	intermediates *x509.CertPool,
	evalTime time.Time,
	keyUsages []x509.ExtKeyUsage,
) AuthenticodeTrustVerification {
	if roots == nil {
		return AuthenticodeTrustVerification{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no trust roots provided",
		}
	}
	if bindingStatus != AuthenticodeStatusValid || cert == nil {
		return AuthenticodeTrustVerification{
			Status: AuthenticodeStatusInvalid,
			Reason: "missing or ambiguous certificate",
		}
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   evalTime,
		KeyUsages:     keyUsages,
	})
	if err != nil {
		return AuthenticodeTrustVerification{
			Status: AuthenticodeStatusInvalid,
			Reason: err.Error(),
		}
	}
	return AuthenticodeTrustVerification{
		Status: AuthenticodeStatusValid,
		Chains: chains,
	}
}

func checkSignerRevocation(
	signerCert *x509.Certificate,
	bindingStatus AuthenticodeVerificationStatus,
	embeddedCerts []*x509.Certificate,
	verifiedChains [][]*x509.Certificate,
	embeddedCRLs []*x509.RevocationList,
	optionCRLs []*x509.RevocationList,
	evalTime time.Time,
	budget *authVerifyBudget,
) (AuthenticodeCheck, error) {
	if len(embeddedCRLs) == 0 && len(optionCRLs) == 0 {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no CRLs available",
		}, nil
	}
	if bindingStatus != AuthenticodeStatusValid || signerCert == nil || signerCert.SerialNumber == nil {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusInvalid,
			Reason: "missing or ambiguous signer certificate",
		}, nil
	}

	var issuers []*x509.Certificate
	for _, c := range embeddedCerts {
		if c != nil && bytes.Equal(c.RawSubject, signerCert.RawIssuer) {
			issuers = append(issuers, c)
		}
	}
	for _, chain := range verifiedChains {
		for _, c := range chain {
			if c != nil && bytes.Equal(c.RawSubject, signerCert.RawIssuer) {
				issuers = append(issuers, c)
			}
		}
	}
	if len(issuers) == 0 {
		return AuthenticodeCheck{
			Status: AuthenticodeStatusUnchecked,
			Reason: "no issuer certificate available to verify CRL",
		}, nil
	}

	verifiedCRL := false
	checkList := func(crls []*x509.RevocationList) (AuthenticodeCheck, bool, error) {
		for _, crl := range crls {
			if crl == nil || !bytes.Equal(crl.RawIssuer, signerCert.RawIssuer) {
				continue
			}
			sigOK := false
			for _, issuer := range issuers {
				if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
					continue
				}
				if budget != nil {
					if err := budget.consume("crl"); err != nil {
						return AuthenticodeCheck{}, false, err
					}
				}
				if crl.CheckSignatureFrom(issuer) == nil {
					sigOK = true
					break
				}
			}
			if !sigOK {
				continue
			}
			verifiedCRL = true
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber != nil && entry.SerialNumber.Cmp(signerCert.SerialNumber) == 0 {
					if !evalTime.IsZero() && entry.RevocationTime.After(evalTime) {
						continue
					}
					return AuthenticodeCheck{
						Status: AuthenticodeStatusInvalid,
						Reason: fmt.Sprintf("certificate serial %s revoked at %s", signerCert.SerialNumber, entry.RevocationTime.UTC().Format(time.RFC3339)),
					}, true, nil
				}
			}
		}
		return AuthenticodeCheck{}, false, nil
	}

	if res, done, err := checkList(embeddedCRLs); err != nil || done {
		return res, err
	}
	if res, done, err := checkList(optionCRLs); err != nil || done {
		return res, err
	}
	if verifiedCRL {
		return AuthenticodeCheck{Status: AuthenticodeStatusValid}, nil
	}
	return AuthenticodeCheck{
		Status: AuthenticodeStatusUnchecked,
		Reason: "no verifiable CRL matched signer issuer",
	}, nil
}

func buildIntermediatePool(base *x509.CertPool, extra []*x509.Certificate) *x509.CertPool {
	var pool *x509.CertPool
	if base != nil {
		pool = base.Clone()
	} else {
		pool = x509.NewCertPool()
	}
	for _, c := range extra {
		if c != nil {
			pool.AddCert(c)
		}
	}
	return pool
}

func digestAlgorithmFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidDigestMD5):
		return crypto.MD5, true
	case oid.Equal(oidDigestSHA1):
		return crypto.SHA1, true
	case oid.Equal(oidDigestSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidDigestSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidDigestSHA512):
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func computeHash(alg crypto.Hash, data []byte) []byte {
	h, err := newAuthenticodeHasher(alg)
	if err != nil {
		return nil
	}
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func rsaPKCS1AlgFromHash(h crypto.Hash) x509.SignatureAlgorithm {
	switch h {
	case crypto.MD5:
		return x509.MD5WithRSA
	case crypto.SHA1:
		return x509.SHA1WithRSA
	case crypto.SHA256:
		return x509.SHA256WithRSA
	case crypto.SHA384:
		return x509.SHA384WithRSA
	case crypto.SHA512:
		return x509.SHA512WithRSA
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

func rsaPSSAlgFromHash(h crypto.Hash) x509.SignatureAlgorithm {
	switch h {
	case crypto.SHA256:
		return x509.SHA256WithRSAPSS
	case crypto.SHA384:
		return x509.SHA384WithRSAPSS
	case crypto.SHA512:
		return x509.SHA512WithRSAPSS
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

func ecdsaAlgFromHash(h crypto.Hash) x509.SignatureAlgorithm {
	switch h {
	case crypto.SHA1:
		return x509.ECDSAWithSHA1
	case crypto.SHA256:
		return x509.ECDSAWithSHA256
	case crypto.SHA384:
		return x509.ECDSAWithSHA384
	case crypto.SHA512:
		return x509.ECDSAWithSHA512
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
