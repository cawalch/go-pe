# Changelog

All notable changes to `go-pe` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for pre-v1 releases (`0.y.z` minor bumps may include API additions or changes).

## [Unreleased]

### Added
- Bits-per-byte Shannon entropy helpers: `ShannonEntropy`,
  `File.SectionEntropy`, and `File.OverlayEntropy` (#84).
- TLS, CLR (.NET), and exception directory parsers: `File.TLS`, `File.CLR`,
  and `File.Exceptions` (#84).
- `RichHeader.MD5` digest of Rich header clear data (#84).
- Load configuration and base relocation parsers: `File.LoadConfig` and
  `File.BaseRelocs` (#85).
- Delay-aware import hashing: `DelayAwareImphash` and
  `File.DelayAwareImphash` (#85).
- `detect` subpackage (`github.com/cawalch/go-pe/detect`) with heuristic
  checks: `detect.Sections`, `detect.Mitigations`, `detect.ImportsAndExports`,
  `detect.Runtime`, `detect.Rich`, and `detect.PDB` (#84, #85).

## [v0.2.0] - 2026-11-21

### Added
- Bounded `io.ReaderAt` APIs for large files without full-image buffering:
  `NewFromReaderAt`, `File.ImportsFromReaderAt`, `File.ExportsFromReaderAt`, and
  `File.CertificatesFromReaderAt` (#16).
- PE header checksum calculation and verification helpers:
  `File.ComputeCheckSum` and `File.VerifyCheckSum` (#44).
- Non-mutating overlay and PE layout anomaly inspection helpers:
  `File.OverlayOffset`, `File.Overlay`, `File.LayoutAnomalies`, and
  `File.HasOverlappingSections` (#44, #53).
- `WIN_CERTIFICATE` and PKCS#7 trailing-padding surfacing for CVE-2013-3900
  awareness (#55).
- Embedded and option CRL evaluation in `File.VerifyAuthenticodeSignatures` (#54).
- RFC 2634 `SigningCertificate` and RFC 5035/5816 `SigningCertificateV2`
  attribute verification in Authenticode verification (#69).
- `MachineARM64EC` and `DllCharacteristics*` constants in `types.go` (#70).
- Runnable `Example*` tests in `example_test.go` for `pkg.go.dev` (#72).
- `golangci-lint` configuration (`.golangci.yml`) and CI `lint` job (#62).
- Differential `libyara`, cross-library, and Corkami-style low-alignment PE
  regression tests (#51, #59, #71).

### Changed
- Single-pass `rvaSpan` and linear two-pass `berToDER` for improved parsing
  performance (#42).
- Unified directory-precondition validation and error wrapping (#45).
- Synced `doc.go`, `README.md`, and `docs/parsing.md` with new APIs (#63, #68).

### Fixed
- Nil `File` receiver guards and empty signature verification handling (#41).
- Tightened Authenticode ASN.1 and CMS edge-case handling (#43).
- Allowed non-zero 12-byte padding after `DanS` in `File.RichHeader` (#58).

## [v0.1.0] - 2026-11-17

### Added
- Initial experimental MVP release of `go-pe` (`b7801b4`):
  - PE32 and PE32+ header, section, RVA/offset conversion, and truncated-input
    extent reporting.
  - Standard and delayed imports, import hashes (`Imphash`), exports, ordinal
    exports, and forwarders.
  - Resources, version information, Rich headers, and CodeView debug records.
  - Attribute certificates, Authenticode image digests, and offline signature
    and timestamp verification with caller-supplied trust roots.

[Unreleased]: https://github.com/cawalch/go-pe/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/cawalch/go-pe/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/cawalch/go-pe/releases/tag/v0.1.0
