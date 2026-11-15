# Authenticode reuse and dependency boundary decision

This document records the evaluation of existing Go Authenticode and CMS/PKCS#7
implementations for `go-pe` (`go-pe#13`) and defines the dependency boundary for
parse-only signer metadata (`go-pe#14`) and offline Authenticode verification
(`go-pe#15`).

## Decision

Implement bounded Authenticode CMS/BER decoding (`go-pe#14`) and offline
signature and timestamp verification (`go-pe#15`) as lazy, standard-library-only
components inside the root `github.com/cawalch/go-pe` module:

- **Keep root `go.mod` at `go 1.26.0` with zero external dependencies.**
  Callers that don't invoke Authenticode APIs don't link `crypto/x509` or any
  PKCS#7 parser, preserving the core binary size (`2.38 MiB`, `61` standard
  library packages) and `New` / non-PE costs.
- **No external Authenticode/PKCS#7 dependency or separate submodule is
  warranted.** None of the four evaluated external implementations provides
  bounded BER/DER parsing, full co-signer and `1.3.6.1.4.1.311.2.4.1` nested
  signature metadata without trusting or rejecting unsupported algorithms, Go
  1.26 compatibility, zero transitive bloat, and offline-only policy together.
- **Reuse scope and attribution:** bounded BER-to-DER normalization can adapt
  strict parent-boundary, depth-limit, and length-overflow checks directly on
  top of `encoding/asn1` and `crypto/x509` (citing upstream MIT design
  improvements from `digitorus/pkcs7` where applicable) while enforcing `go-pe`'s
  explicit record, element, depth, and byte budgets.

## Reproducibility metadata

- **Toolchain:** `go1.27.4 darwin/arm64` (`go-pe` root `go.mod` targets `go 1.26.0`)
- **Pinned candidate revisions inspected (`2026-11-14`):**
  - `github.com/digitorus/pkcs7 v0.0.0-20261104125046-a476de3098e4` (`go 1.27`, MIT)
  - `github.com/foxboron/go-uefi v0.0.0-20261004203234-c7f1f57bdc6e` (`go 1.23`, MIT)
  - `github.com/sassoftware/relic/v8 v8.2.0` (`go 1.22.0`, Apache-2.0)
  - `github.com/saferwall/pe v1.6.5` (`go 1.15`, MIT) with `github.com/ayoubfaouzi/pkcs7 v0.2.3` (`go 1.14`, MIT)

## Linked dependency graph, binary size, and build cost

Each candidate was imported into a standalone minimal `main` package using only
the target package (`authenticode` or `pkcs7`) and built with an isolated `GOCACHE`
(`CGO_ENABLED=1` default on `darwin/arm64`; zero `C` package imports observed in
any candidate):

| Target / Package Imported | `go.mod` Minimum | CGO Deps | Total Linked Pkgs | Non-Std Pkgs | Binary Size | Delta vs `go-pe + x509` | Cold `go build` |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `github.com/cawalch/go-pe` (`baseline`) | `1.26.0` | `0` | `61` | `1` | `2,500,610 B` (`2.38 MiB`) | `-1.81 MiB` | `1.76 s` |
| `github.com/cawalch/go-pe` + `crypto/x509` | `1.26.0` | `0` | `147` | `1` | `4,398,482 B` (`4.19 MiB`) | `0 B` | `2.37 s` |
| `github.com/digitorus/pkcs7` | `1.27` | `0` | `152` | `1` | `4,399,506 B` (`4.20 MiB`) | `+1,024 B` | `2.48 s` |
| `github.com/ayoubfaouzi/pkcs7` | `1.14` | `0` | `150` | `4` | `4,575,634 B` (`4.36 MiB`) | `+177,152 B` | `2.53 s` |
| `github.com/saferwall/pe` | `1.15` | `0` | `165` | `15` | `3,868,178 B` (`3.69 MiB`) | `-530,304 B` | `2.88 s` |
| `github.com/foxboron/go-uefi/authenticode` | `1.23` | `0` | `216` | `22` | `5,442,994 B` (`5.19 MiB`) | `+1.00 MiB` | `3.67 s` |
| `github.com/sassoftware/relic/v8/lib/authenticode` | `1.22.0` | `0` | `279` | `60` | `7,002,018 B` (`6.68 MiB`) | `+2.49 MiB` | `3.94 s` |

Notable linked transitive packages (observed directly via `go list -deps`):

- **`digitorus/pkcs7`:** Zero external packages (`152` total stdlib + self), but
  imports Go 1.27's `crypto/mldsa` and sets `go 1.27` in `go.mod`, making it
  incompatible with `go-pe`'s `go 1.26.0` baseline.
- **`foxboron/go-uefi/authenticode`:** Even without calling EFI variable APIs,
  linking `authenticode` pulls in `efi/signature`, `efi/fs`, `efivar`,
  `spf13/afero`, `golang.org/x/text/*`, `golang.org/x/crypto/cryptobyte`, and
  `pkg/errors` (`22` non-std packages, `+1.00 MiB`).
- **`sassoftware/relic/v8/lib/authenticode`:** Omits cloud KMS SDKs (AWS, Azure,
  GCP) from its link graph, but still links `ProtonMail/go-crypto/openpgp`,
  `cloudflare/circl`, `spf13/cobra`, `zalando/go-keyring`, `howeyc/gopass`,
  `go-pkcs12`, and `golang.org/x/term` (`60` non-std packages, `+2.49 MiB`).
- **`ayoubfaouzi/pkcs7`:** Pulls `golang.org/x/crypto/cryptobyte` and ships a
  vendored `internal/legacy/x509` fork (`4` non-std packages).

## Capability, safety, and semantic matrix

| Criterion | `digitorus/pkcs7` | `ayoubfaouzi/pkcs7` + `saferwall/pe` | `foxboron/go-uefi/authenticode` | `sassoftware/relic/v8/lib/authenticode` |
| --- | --- | --- | --- | --- |
| **License & status** | MIT; active (`2026-11-04`) | MIT; active `saferwall/pe` (`v1.6.5`), stalled `pkcs7 v0.2.3` | MIT; active (`2026-10-04`) | Apache-2.0; `v8.2.0` (`2025-01-17`) |
| **Go baseline compatible (`1.26.0`)** | No (`go 1.27`, uses `crypto/mldsa`) | Yes (`go 1.14` / `go 1.15`) | Yes (`go 1.23`) | Yes (`go 1.22.0`) |
| **Parse-only without crypto verify** | Yes (`pkcs7.Parse`, no Authenticode wrapper) | Partial (`Parse()` skips on error; mixes verification unless disabled) | Partial (`ParseAuthenticode`, returns unexported `[]*signerinfo`) | No (`VerifyPE(..., skipDigests)` still checks PKCS#7 and timestamps) |
| **Image digest & verification** | No PE Authenticode support | `AuthentihashExt` (PE ranges; ignores nested/second `WIN_CERTIFICATE` records) | PE COFF digest + RSA-SHA256 `Verify` | PE, page hashes, CAB/MSI; no parse-only bypass for invalid signatures |
| **Timestamps & countersignatures** | Manual via `SignerInfos[0]` only | Minimal (`GetOnlySigner` ignores multi-signer/extra records) | RFC 3161 (`VerifyTimestampBytes`) only | PKCS#9 + RFC 3161 (`lib/pkcs9`) during verification |
| **Unsupported digest/sig OIDs** | Preserved in `signerInfo`; fails only on `Verify` | Preserved until `Verify`; fails if `GetOnlySigner` ambiguous | Parse preserves `pkix.AlgorithmIdentifier`; `pkcs7.Verify` hardcodes RSA-SHA256 | Fails `VerifyPE` on unsupported `x509tools` OIDs |
| **Malformed ASN.1 / BER limits** | Bounded (`maxNestingDepth = 500`, strict BER parent bounds, overflow checks) | Unbounded recursion in `ber2der`; high-tag OOB slice panic at `ber.go:144` | DER-only (`cryptobyte`, rejects legacy BER); iterative parser | DER-only (`encoding/asn1`); rejects legacy BER indefinite length |
| **Signed-attribute handling** | `SignerInfos` slice stored, but `UnmarshalSignedAttribute` uses index `0` | Same `GetOnlySigner` / `SignerInfos[0]` limitation | Single `Attributes` struct; overwrites duplicate standard attributes | `AttributeList.GetOne` returns first match on duplicates |
| **Nested signatures (`1.3.6.1.4.1.311.2.4.1`)** | Not handled automatically | `saferwall` loops without a depth bound | Not handled | Not handled inside a single `WIN_CERTIFICATE` |
| **Cert-chain & network behavior** | Caller supplies `x509.VerifyOptions`; no network | Calls `x509.SystemCertPool()` unless disabled; spawns `certutil` into `%TEMP%\certs` on Windows | Offline caller `*x509.Certificate`; no `certutil`/network | Offline caller `*x509.CertPool`; no network |
| **Raw DN / serial / cert byte preservation** | Yes (`x509.Certificate.Raw*`, `asn1.RawValue`) | Yes (plus legacy X.509 copy) | Partial (`pkix`/`x509`; `signerinfo` type is unexported) | Yes (`Signature` preserves `*x509.Certificate` and timestamps) |

## Implementation guidance for follow-on issues

1. **`go-pe#14` (bounded Authenticode metadata):** Implement bounded BER-to-DER
   normalization (`maxDepth`, `maxElements`, total byte cap `MaxCertificateBytes`)
   plus `SignedData`, `SignerInfo`, `SpcIndirectDataContent`, co-signer, nested
   signature (`1.3.6.1.4.1.311.2.4.1`), PKCS#9 (`1.2.840.113549.1.9.6`), and RFC
   3161 (`1.3.6.1.4.1.311.3.3.1`) metadata extraction directly in root `go-pe`
   using `encoding/asn1` and `crypto/x509`. Preserve raw `RawIssuer`,
   `RawSubject`, `Raw` certificate bytes, serial bytes, timestamps, duplicate
   attribute diagnostics or slice ordering, and unknown algorithm OIDs without
   requiring signature verification or touching system trust stores.
2. **`go-pe#15` (offline integrity & timestamps):** Build on `go-pe#12` (image
   digests) and `go-pe#14` (parsed CMS metadata) using caller-supplied trust roots
   and verification options only, with zero network requests and zero external
   binaries.
