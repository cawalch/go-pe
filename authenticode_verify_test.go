package pe_test

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cawalch/go-pe"
	"github.com/cawalch/go-pe/internal/testfixture"
)

func signSyntheticPE(t *testing.T, is64 bool, alg crypto.Hash, opts testfixture.SignedPKCS7Options) ([]byte, *pe.File) {
	t.Helper()
	base := testfixture.MinimalAligned(is64)
	bf, err := pe.New(base)
	if err != nil {
		t.Fatalf("pe.New(base): %v", err)
	}
	if opts.ImageDigest == nil {
		d, err := bf.AuthenticodeDigest(base, alg)
		if err != nil {
			t.Fatalf("AuthenticodeDigest: %v", err)
		}
		opts.ImageDigest = d
	}
	opts.ImageDigestAlg = alg
	blob := testfixture.BuildSignedPKCS7(opts)
	signed := testfixture.AppendCertificates(base, is64, testfixture.CertificateSpec{
		Revision: pe.CertificateRevision2_0,
		Type:     pe.CertificateTypePKCS7SignedData,
		Payload:  blob,
	})
	f, err := pe.New(signed)
	if err != nil {
		t.Fatalf("pe.New(signed): %v", err)
	}
	return signed, f
}

func TestVerifyAuthenticodeAlgorithmsAndFormats(t *testing.T) {
	inWindow := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		is64 bool
		pki  testfixture.AuthenticodePKIOptions
		alg  crypto.Hash
		opts testfixture.SignedPKCS7Options
	}{
		{
			name: "PE32/ECDSA-SHA256",
			is64: false,
			alg:  crypto.SHA256,
		},
		{
			name: "PE32Plus/ECDSA-SHA384-KeyOnlyOID",
			is64: true,
			alg:  crypto.SHA384,
			opts: testfixture.SignedPKCS7Options{UseKeyOnlySigOID: true},
		},
		{
			name: "PE32Plus/RSA-SHA256-KeyOnlyOID",
			is64: true,
			pki:  testfixture.AuthenticodePKIOptions{UseRSA: true},
			alg:  crypto.SHA256,
			opts: testfixture.SignedPKCS7Options{UseKeyOnlySigOID: true},
		},
		{
			name: "PE32/RSA-SHA1-Legacy",
			is64: false,
			pki:  testfixture.AuthenticodePKIOptions{UseRSA: true},
			alg:  crypto.SHA1,
		},
		{
			name: "PE32/RSA-MD5-Legacy",
			is64: false,
			pki:  testfixture.AuthenticodePKIOptions{UseRSA: true},
			alg:  crypto.MD5,
		},
		{
			name: "PE32Plus/RSA-PSS-SHA256",
			is64: true,
			pki:  testfixture.AuthenticodePKIOptions{UseRSA: true},
			alg:  crypto.SHA256,
			opts: testfixture.SignedPKCS7Options{UseRSAPSS: true},
		},
		{
			name: "PE32Plus/Ed25519-SKID-WrappedOctetString",
			is64: true,
			pki:  testfixture.AuthenticodePKIOptions{UseEd25519: true},
			alg:  crypto.SHA512,
			opts: testfixture.SignedPKCS7Options{
				UseSubjectKeyID:      true,
				WrapEncapOctetString: true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pki := testfixture.NewAuthenticodePKI(tc.pki)
			opts := tc.opts
			opts.SignerCert = pki.SignerCert
			opts.SignerKey = pki.SignerKey
			opts.ExtraCerts = []*x509.Certificate{pki.InterCert}

			data, f := signSyntheticPE(t, tc.is64, tc.alg, opts)

			// 1. Offline integrity only (no roots, no wall clock).
			res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
			if err != nil {
				t.Fatalf("VerifyAuthenticode(no roots): %v", err)
			}
			if len(res.Signatures) != 1 || len(res.Signatures[0].Signers) != 1 {
				t.Fatalf("unexpected signature/signer counts: %+v", res)
			}
			sig := res.Signatures[0]
			if sig.Digest.Status != pe.AuthenticodeStatusValid || sig.Digest.Algorithm != tc.alg {
				t.Fatalf("Digest = %+v, want Valid/%v", sig.Digest, tc.alg)
			}
			signer := sig.Signers[0]
			if signer.Binding.Status != pe.AuthenticodeStatusValid {
				t.Fatalf("Binding = %+v, want Valid", signer.Binding)
			}
			if signer.CMS.Status != pe.AuthenticodeStatusValid {
				t.Fatalf("CMS = %+v, want Valid", signer.CMS)
			}
			if signer.SignerValidity.Status != pe.AuthenticodeStatusUnchecked {
				t.Fatalf("SignerValidity = %+v, want Unchecked without time/timestamp", signer.SignerValidity)
			}
			if signer.Trust.Status != pe.AuthenticodeStatusUnchecked {
				t.Fatalf("Trust = %+v, want Unchecked when Roots is nil", signer.Trust)
			}

			// 2. With explicit roots and VerificationTime.
			trusted, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{
				Roots:            pki.RootPool,
				VerificationTime: inWindow,
			})
			if err != nil {
				t.Fatalf("VerifyAuthenticode(roots): %v", err)
			}
			tSigner := trusted.Signatures[0].Signers[0]
			if tSigner.SignerValidity.Status != pe.AuthenticodeStatusValid {
				t.Fatalf("SignerValidity = %+v, want Valid", tSigner.SignerValidity)
			}
			if tSigner.Trust.Status != pe.AuthenticodeStatusValid || len(tSigner.Trust.Chains) == 0 {
				t.Fatalf("Trust = %+v, want Valid chain", tSigner.Trust)
			}
		})
	}
}

func TestVerifyAuthenticodeTamperingAndNegativeCases(t *testing.T) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	inWindow := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("TamperedImageBytesBreaksDigestNotCMS", func(t *testing.T) {
		data, _ := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert: pki.SignerCert,
			SignerKey:  pki.SignerKey,
		})
		// Modify section byte inside signed PE image (last byte before cert table).
		dirOff := testfixture.CertificateDirOffset(true)
		certTableOff := int(binary.LittleEndian.Uint32(data[dirOff:]))
		data[certTableOff-1] ^= 0xff

		f, err := pe.New(data)
		if err != nil {
			t.Fatalf("pe.New: %v", err)
		}
		res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		sig := res.Signatures[0]
		if sig.Digest.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("Digest = %+v, want Invalid after tampering image", sig.Digest)
		}
		if sig.Signers[0].CMS.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("CMS = %+v, expected CMS itself to stay valid independently of PE digest", sig.Signers[0].CMS)
		}
	})

	t.Run("TamperedCMSMessageDigest", func(t *testing.T) {
		data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert:          pki.SignerCert,
			SignerKey:           pki.SignerKey,
			CorruptSignedDigest: true,
		})
		res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		if res.Signatures[0].Digest.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("Digest = %+v, want Valid", res.Signatures[0].Digest)
		}
		if res.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("CMS = %+v, want Invalid", res.Signatures[0].Signers[0].CMS)
		}
	})

	t.Run("TamperedSignatureBytes", func(t *testing.T) {
		data, f := signSyntheticPE(t, false, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert:       pki.SignerCert,
			SignerKey:        pki.SignerKey,
			CorruptSignature: true,
		})
		res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		if res.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("CMS = %+v, want Invalid", res.Signatures[0].Signers[0].CMS)
		}
	})

	t.Run("SignedAttributeAmbiguityRejected", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts testfixture.SignedPKCS7Options
		}{
			{
				name: "DuplicateMessageDigest",
				opts: testfixture.SignedPKCS7Options{DuplicateMessageDigest: true},
			},
			{
				name: "DuplicateSigningTime",
				opts: testfixture.SignedPKCS7Options{SigningTime: inWindow, DuplicateSigningTime: true},
			},
			{
				name: "MultiValuedContentType",
				opts: testfixture.SignedPKCS7Options{MultiValueContentType: true},
			},
			{
				name: "MissingContentType",
				opts: testfixture.SignedPKCS7Options{OmitContentType: true},
			},
			{
				name: "MissingSignedAttrs",
				opts: testfixture.SignedPKCS7Options{OmitSignedAttrs: true},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				opts := tc.opts
				opts.SignerCert = pki.SignerCert
				opts.SignerKey = pki.SignerKey
				data, f := signSyntheticPE(t, true, crypto.SHA256, opts)
				res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
				if err != nil {
					t.Fatalf("VerifyAuthenticode: %v", err)
				}
				if got := res.Signatures[0].Signers[0].CMS.Status; got != pe.AuthenticodeStatusInvalid {
					t.Fatalf("%s: CMS.Status = %v (%q), want invalid", tc.name, got, res.Signatures[0].Signers[0].CMS.Reason)
				}
			})
		}
	})

	t.Run("IncorrectAndAmbiguousSignerBinding", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts testfixture.SignedPKCS7Options
		}{
			{
				name: "MissingSignerCert",
				opts: testfixture.SignedPKCS7Options{OmitSignerCert: true},
			},
			{
				name: "ConflictingDuplicateIssuerAndSerial",
				opts: testfixture.SignedPKCS7Options{ConflictingDuplicateSID: true},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				opts := tc.opts
				opts.SignerCert = pki.SignerCert
				opts.SignerKey = pki.SignerKey
				data, f := signSyntheticPE(t, false, crypto.SHA256, opts)
				res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
				if err != nil {
					t.Fatalf("VerifyAuthenticode: %v", err)
				}
				signer := res.Signatures[0].Signers[0]
				if signer.Binding.Status != pe.AuthenticodeStatusInvalid {
					t.Fatalf("%s: Binding = %+v, want Invalid", tc.name, signer.Binding)
				}
				if signer.CMS.Status != pe.AuthenticodeStatusInvalid {
					t.Fatalf("%s: CMS = %+v, want Invalid", tc.name, signer.CMS)
				}
			})
		}
	})

	t.Run("UnsupportedDigestAndSignatureOIDs", func(t *testing.T) {
		unknownDigest := asn1.ObjectIdentifier{1, 2, 3, 999, 1}
		data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert:             pki.SignerCert,
			SignerKey:              pki.SignerKey,
			OverrideImageDigestOID: unknownDigest,
			OverrideSigOID:         asn1.ObjectIdentifier{1, 2, 3, 999, 2},
		})
		res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		if res.Signatures[0].Digest.Status != pe.AuthenticodeStatusUnsupported {
			t.Fatalf("Digest = %+v, want Unsupported", res.Signatures[0].Digest)
		}
		if res.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusUnsupported {
			t.Fatalf("CMS = %+v, want Unsupported", res.Signatures[0].Signers[0].CMS)
		}
	})

	t.Run("AmbientOSTrustNotUsedWhenRootsNil", func(t *testing.T) {
		noEKUPKI := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{ServerAuthOnlyEKU: true})
		data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert: noEKUPKI.SignerCert,
			SignerKey:  noEKUPKI.SignerKey,
			ExtraCerts: []*x509.Certificate{noEKUPKI.InterCert},
		})
		res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		if res.Signatures[0].Signers[0].Trust.Status != pe.AuthenticodeStatusUnchecked {
			t.Fatalf("Trust = %+v, want Unchecked when Roots == nil", res.Signatures[0].Signers[0].Trust)
		}

		// With Roots + default CodeSigning EKU, missing EKU fails chain verification.
		withRoots, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{
			Roots:            noEKUPKI.RootPool,
			VerificationTime: inWindow,
		})
		if err != nil {
			t.Fatalf("VerifyAuthenticode(roots): %v", err)
		}
		if withRoots.Signatures[0].Signers[0].Trust.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("Trust = %+v, want Invalid when CodeSigning EKU missing", withRoots.Signatures[0].Signers[0].Trust)
		}

		// Overriding KeyUsages to Any allows verification against explicit Roots.
		overrideEKU, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{
			Roots:            noEKUPKI.RootPool,
			VerificationTime: inWindow,
			KeyUsages:        []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			t.Fatalf("VerifyAuthenticode(Any EKU): %v", err)
		}
		if overrideEKU.Signatures[0].Signers[0].Trust.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("Trust = %+v, want Valid with ExtKeyUsageAny", overrideEKU.Signatures[0].Signers[0].Trust)
		}
	})
}

func TestVerifyAuthenticodeTimestampsAndExpiry(t *testing.T) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	validTS := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	t.Run("ValidPKCS9AndRFC3161Timestamps", func(t *testing.T) {
		for _, standardOID := range []bool{false, true} {
			data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
				SignerCert:            pki.SignerCert,
				SignerKey:             pki.SignerKey,
				ExtraCerts:            []*x509.Certificate{pki.InterCert, pki.TSACert},
				PKCS9At:               validTS,
				RFC3161At:             validTS.Add(time.Minute),
				UseStandardRFC3161OID: standardOID,
				TSACert:               pki.TSACert,
				TSAKey:                pki.TSAKey,
			})
			res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{
				Roots: pki.RootPool,
			})
			if err != nil {
				t.Fatalf("VerifyAuthenticode(standardOID=%v): %v", standardOID, err)
			}
			signer := res.Signatures[0].Signers[0]
			if len(signer.Timestamps) != 2 {
				t.Fatalf("len(Timestamps) = %d, want 2", len(signer.Timestamps))
			}
			for i, ts := range signer.Timestamps {
				if ts.Imprint.Status != pe.AuthenticodeStatusValid ||
					ts.CMS.Status != pe.AuthenticodeStatusValid ||
					ts.ValidityBounds.Status != pe.AuthenticodeStatusValid ||
					ts.Trust.Status != pe.AuthenticodeStatusValid {
					t.Fatalf("ts[%d] = %+v, want all Valid", i, ts)
				}
			}
			if signer.Trust.Status != pe.AuthenticodeStatusValid {
				t.Fatalf("signer Trust = %+v, want Valid", signer.Trust)
			}
		}
	})

	t.Run("ExpiredSignerExtendedOnlyByValidTrustedTimestamp", func(t *testing.T) {
		// ExpiredCert is valid 2021-01-01..2022-01-01. Timestamp during 2021 makes it valid at 2026!
		validHistoricalTS := time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC)
		historicalPKI := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{
			TSANotBefore: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
		})
		data, f := signSyntheticPE(t, false, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert: historicalPKI.ExpiredCert,
			SignerKey:  historicalPKI.ExpiredKey,
			ExtraCerts: []*x509.Certificate{historicalPKI.InterCert},
			RFC3161At:  validHistoricalTS,
			TSACert:    historicalPKI.TSACert,
			TSAKey:     historicalPKI.TSAKey,
		})
		res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{
			Roots: historicalPKI.RootPool,
		})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		signer := res.Signatures[0].Signers[0]
		if signer.SignerValidity.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("SignerValidity = %+v, want Valid via historical timestamp", signer.SignerValidity)
		}
		if signer.Trust.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("Trust = %+v, want Valid via historical timestamp", signer.Trust)
		}

		// Without trusted TSA roots matching untrusted TSA, expired cert must NOT be extended!
		untrustedTSA := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{
			TSANotBefore: time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC),
		})
		forgedTSData, forgedF := signSyntheticPE(t, false, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert: historicalPKI.ExpiredCert,
			SignerKey:  historicalPKI.ExpiredKey,
			ExtraCerts: []*x509.Certificate{historicalPKI.InterCert},
			RFC3161At:  validHistoricalTS,
			TSACert:    untrustedTSA.TSACert,
			TSAKey:     untrustedTSA.TSAKey,
		})
		untrustedRes, err := forgedF.VerifyAuthenticode(forgedTSData, pe.AuthenticodeVerifyOptions{
			Roots: historicalPKI.RootPool,
		})
		if err != nil {
			t.Fatalf("VerifyAuthenticode(untrusted TSA): %v", err)
		}
		uSigner := untrustedRes.Signatures[0].Signers[0]
		if uSigner.Timestamps[0].Trust.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("untrusted TSA Trust = %+v, want Invalid", uSigner.Timestamps[0].Trust)
		}
		if uSigner.SignerValidity.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("expired SignerValidity = %+v, want Invalid when TSA untrusted", uSigner.SignerValidity)
		}
	})

	t.Run("TimestampBeforeAndAfterCertValidityBounds", func(t *testing.T) {
		beforeNotBefore := pki.SignerCert.NotBefore.Add(-24 * time.Hour)
		afterNotAfter := pki.SignerCert.NotAfter.Add(24 * time.Hour)

		for _, tc := range []struct {
			name string
			at   time.Time
		}{
			{name: "BeforeSignerNotBefore", at: beforeNotBefore},
			{name: "AfterSignerNotAfter", at: afterNotAfter},
		} {
			t.Run(tc.name, func(t *testing.T) {
				data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
					SignerCert: pki.SignerCert,
					SignerKey:  pki.SignerKey,
					RFC3161At:  tc.at,
					TSACert:    pki.TSACert,
					TSAKey:     pki.TSAKey,
				})
				res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
				if err != nil {
					t.Fatalf("VerifyAuthenticode: %v", err)
				}
				ts := res.Signatures[0].Signers[0].Timestamps[0]
				if ts.Imprint.Status != pe.AuthenticodeStatusValid || ts.CMS.Status != pe.AuthenticodeStatusValid {
					t.Fatalf("expected crypto valid, got %+v", ts)
				}
				if ts.ValidityBounds.Status != pe.AuthenticodeStatusInvalid {
					t.Fatalf("ValidityBounds = %+v, want Invalid", ts.ValidityBounds)
				}
			})
		}
	})

	t.Run("TimestampBadImprintAndBadCMS", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts testfixture.SignedPKCS7Options
		}{
			{name: "BadRFC3161Imprint", opts: testfixture.SignedPKCS7Options{RFC3161At: validTS, CorruptTimestampImprint: true}},
			{name: "BadRFC3161Sig", opts: testfixture.SignedPKCS7Options{RFC3161At: validTS, CorruptTimestampSig: true}},
			{name: "BadPKCS9Imprint", opts: testfixture.SignedPKCS7Options{PKCS9At: validTS, CorruptTimestampImprint: true}},
			{name: "BadPKCS9Sig", opts: testfixture.SignedPKCS7Options{PKCS9At: validTS, CorruptTimestampSig: true}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				opts := tc.opts
				opts.SignerCert = pki.SignerCert
				opts.SignerKey = pki.SignerKey
				opts.ExtraCerts = []*x509.Certificate{pki.TSACert}
				opts.TSACert = pki.TSACert
				opts.TSAKey = pki.TSAKey
				data, f := signSyntheticPE(t, true, crypto.SHA256, opts)
				res, err := f.VerifyAuthenticode(data, pe.AuthenticodeVerifyOptions{})
				if err != nil {
					t.Fatalf("VerifyAuthenticode: %v", err)
				}
				ts := res.Signatures[0].Signers[0].Timestamps[0]
				if tc.opts.CorruptTimestampImprint && ts.Imprint.Status != pe.AuthenticodeStatusInvalid {
					t.Fatalf("Imprint = %+v, want Invalid", ts.Imprint)
				}
				if tc.opts.CorruptTimestampSig && ts.CMS.Status != pe.AuthenticodeStatusInvalid {
					t.Fatalf("CMS = %+v, want Invalid", ts.CMS)
				}
			})
		}
	})
}

func TestVerifyAuthenticodeNestedUnsignedLimitsAndRace(t *testing.T) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	rsaPKI := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{UseRSA: true})

	t.Run("NestedSignaturesEvaluatedIndependently", func(t *testing.T) {
		base := testfixture.MinimalAligned(true)
		bf, err := pe.New(base)
		if err != nil {
			t.Fatalf("pe.New(base): %v", err)
		}
		digests, err := bf.AuthenticodeDigests(base, crypto.SHA1, crypto.SHA256)
		if err != nil {
			t.Fatalf("AuthenticodeDigests: %v", err)
		}

		// Valid nested SHA-256 signature.
		nestedValid := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
			SignerCert:     pki.SignerCert,
			SignerKey:      pki.SignerKey,
			ExtraCerts:     []*x509.Certificate{pki.InterCert},
			ImageDigest:    digests[1],
			ImageDigestAlg: crypto.SHA256,
		})
		// Invalid nested SHA-256 signature (tampered CMS signature).
		nestedBad := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
			SignerCert:       pki.SignerCert,
			SignerKey:        pki.SignerKey,
			ImageDigest:      digests[1],
			ImageDigestAlg:   crypto.SHA256,
			CorruptSignature: true,
		})
		// Primary SHA-1 signature carrying both nested signatures.
		primary := testfixture.BuildSignedPKCS7(testfixture.SignedPKCS7Options{
			SignerCert:     rsaPKI.SignerCert,
			SignerKey:      rsaPKI.SignerKey,
			ExtraCerts:     []*x509.Certificate{rsaPKI.InterCert},
			ImageDigest:    digests[0],
			ImageDigestAlg: crypto.SHA1,
			NestedBlobs:    [][]byte{nestedValid, nestedBad},
		})
		signed := testfixture.AppendCertificates(base, true, testfixture.CertificateSpec{
			Revision: pe.CertificateRevision2_0,
			Type:     pe.CertificateTypePKCS7SignedData,
			Payload:  primary,
		})
		f, err := pe.New(signed)
		if err != nil {
			t.Fatalf("pe.New(signed): %v", err)
		}
		res, err := f.VerifyAuthenticode(signed, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode: %v", err)
		}
		if len(res.Signatures) != 3 {
			t.Fatalf("len(Signatures) = %d, want 3", len(res.Signatures))
		}
		if res.Signatures[0].Digest.Status != pe.AuthenticodeStatusValid ||
			res.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("primary signature should be valid: %+v", res.Signatures[0])
		}
		if res.Signatures[1].NestedDepth != 1 ||
			res.Signatures[1].Digest.Status != pe.AuthenticodeStatusValid ||
			res.Signatures[1].Signers[0].CMS.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("nestedValid should be valid: %+v", res.Signatures[1])
		}
		if res.Signatures[2].Digest.Status != pe.AuthenticodeStatusValid ||
			res.Signatures[2].Signers[0].CMS.Status != pe.AuthenticodeStatusInvalid {
			t.Fatalf("nestedBad expected valid digest + invalid CMS: %+v", res.Signatures[2])
		}

		// Enforce finite work budget.
		if _, err := f.VerifyAuthenticode(signed, pe.AuthenticodeVerifyOptions{MaxVerifyOps: 2}); !errors.Is(err, pe.ErrAuthenticodeLimit) {
			t.Fatalf("MaxVerifyOps=2 error = %v, want ErrAuthenticodeLimit", err)
		}
	})

	t.Run("UnsignedAndSkipDigestAndStatusString", func(t *testing.T) {
		unsigned := testfixture.MinimalAligned(false)
		uf, err := pe.New(unsigned)
		if err != nil {
			t.Fatalf("pe.New: %v", err)
		}
		res, err := uf.VerifyAuthenticode(unsigned, pe.AuthenticodeVerifyOptions{})
		if err != nil {
			t.Fatalf("VerifyAuthenticode(unsigned): %v", err)
		}
		if len(res.Signatures) != 0 {
			t.Fatalf("expected 0 signatures for unsigned PE, got %d", len(res.Signatures))
		}

		data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert: pki.SignerCert,
			SignerKey:  pki.SignerKey,
		})
		sigs, err := f.AuthenticodeSignatures(data)
		if err != nil {
			t.Fatalf("AuthenticodeSignatures: %v", err)
		}
		skipped, err := f.VerifyAuthenticodeSignatures(nil, sigs, pe.AuthenticodeVerifyOptions{SkipImageDigest: true})
		if err != nil {
			t.Fatalf("VerifyAuthenticodeSignatures(SkipImageDigest): %v", err)
		}
		if skipped.Signatures[0].Digest.Status != pe.AuthenticodeStatusUnchecked {
			t.Fatalf("Digest.Status = %v, want unchecked", skipped.Signatures[0].Digest.Status)
		}
		if skipped.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusValid {
			t.Fatalf("CMS.Status = %v, want valid", skipped.Signatures[0].Signers[0].CMS.Status)
		}

		// Verify bounds / truncation rejection when data size doesn't match.
		if _, err := f.VerifyAuthenticodeSignatures(data[:len(data)-1], sigs, pe.AuthenticodeVerifyOptions{}); !errors.Is(err, pe.ErrOutOfBounds) {
			t.Fatalf("truncated data err = %v, want ErrOutOfBounds", err)
		}

		if pe.AuthenticodeStatusValid.String() != "valid" || pe.AuthenticodeStatusUnsupported.String() != "unsupported" {
			t.Fatalf("unexpected String() output")
		}
		// Keep unused math/big import happy if needed; check serial test coverage separately.
		_ = big.NewInt(1)
	})

	t.Run("ConcurrentSafe", func(t *testing.T) {
		data, f := signSyntheticPE(t, true, crypto.SHA256, testfixture.SignedPKCS7Options{
			SignerCert: pki.SignerCert,
			SignerKey:  pki.SignerKey,
			ExtraCerts: []*x509.Certificate{pki.InterCert},
			RFC3161At:  time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
			TSACert:    pki.TSACert,
			TSAKey:     pki.TSAKey,
		})
		opts := pe.AuthenticodeVerifyOptions{Roots: pki.RootPool}

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 5 {
					res, err := f.VerifyAuthenticode(data, opts)
					if err != nil {
						t.Errorf("VerifyAuthenticode: %v", err)
						return
					}
					if res.Signatures[0].Digest.Status != pe.AuthenticodeStatusValid ||
						res.Signatures[0].Signers[0].CMS.Status != pe.AuthenticodeStatusValid ||
						res.Signatures[0].Signers[0].Trust.Status != pe.AuthenticodeStatusValid {
						t.Errorf("unexpected verification failure: %+v", res)
						return
					}
				}
			})
		}
		wg.Wait()
	})
}

func TestVerifyAuthenticodeTimestampChainBudget(t *testing.T) {
	pki := testfixture.NewAuthenticodePKI(testfixture.AuthenticodePKIOptions{})
	signingTime := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"PKCS9", "RFC3161"} {
		t.Run(kind, func(t *testing.T) {
			opts := testfixture.SignedPKCS7Options{
				SignerCert: pki.SignerCert,
				SignerKey:  pki.SignerKey,
				ExtraCerts: []*x509.Certificate{pki.InterCert, pki.TSACert},
				TSACert:    pki.TSACert,
				TSAKey:     pki.TSAKey,
			}
			if kind == "PKCS9" {
				opts.PKCS9At = signingTime
			} else {
				opts.RFC3161At = signingTime
			}
			data, f := signSyntheticPE(t, true, crypto.SHA256, opts)
			chainChecks := 0
			roots := x509.NewCertPool()
			roots.AddCertWithConstraint(pki.RootCert, func([]*x509.Certificate) error {
				chainChecks++
				return nil
			})
			// The signature, signer, and timestamp consume the first three
			// operations. The timestamp chain must not start without a fourth.
			verifyOpts := pe.AuthenticodeVerifyOptions{TimestampRoots: roots, MaxVerifyOps: 3}
			result, err := f.VerifyAuthenticode(data, verifyOpts)
			if !errors.Is(err, pe.ErrAuthenticodeLimit) || len(result.Signatures) != 0 {
				t.Fatalf("VerifyAuthenticode = %+v, %v; want no results and ErrAuthenticodeLimit", result, err)
			}
			if chainChecks != 0 {
				t.Fatalf("performed %d chain checks after exhausting the budget", chainChecks)
			}

			verifyOpts.MaxVerifyOps = 4
			result, err = f.VerifyAuthenticode(data, verifyOpts)
			if err != nil {
				t.Fatal(err)
			}
			if chainChecks == 0 || result.Signatures[0].Signers[0].Timestamps[0].Trust.Status != pe.AuthenticodeStatusValid {
				t.Fatal("timestamp chain was not verified with sufficient budget")
			}
		})
	}
}
