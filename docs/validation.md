# Validation corpus and assurance

This inventory describes release evidence as of 2026-11-17. Passing these tests
supports the stated parser contracts; it does not establish universal PE
compatibility or Windows trust equivalence.

## Corpus and provenance

| Corpus | Source and reproduction | Checks |
| --- | --- | --- |
| Synthetic PE32 and PE32+ structures | Root tests and `internal/testfixture`; generated in memory | Boundaries, limits, malformed metadata, ownership, and per-feature contracts. |
| MinGW executables, including stripped PE32 | Three executable fixtures in the installed Go toolchain's `src/debug/pe/testdata` | Root tests compare named imports with `debug/pe`. The comparison module compares complete named-import sequences with `debug/pe` and Binject, and DLL, symbol, hint/ordinal, and IAT-slot fields with saferwall. |
| Go Windows executables | `TestGoCompilerCorpus` compiles a benign source program for 386, amd64, and arm64; amd64 is stripped | Section fields and named imports match `debug/pe`. Derived cases truncate signatures, optional headers, section tables, and payloads, or corrupt the PE signature. |
| Signed PE/COFF and EFI images | Two fixtures from the pinned `github.com/foxboron/go-uefi` module | Known digest vectors, cross-library digest and signature checks, and a modified section byte in each signed image. |
| COFF objects and minimal EFI stub | Installed Go toolchain testdata | Existing comparison tests record explicit acceptance/rejection differences. COFF object support is outside go-pe's contract. |

The compiler corpus writes only to test temporary directories and never executes
its Windows binaries. It requires an installed Go compiler and no new external
binary download. Tests log SHA-256 hashes and sizes for compiler and MinGW inputs;
compiler output depends on the Go version. The upstream signed fixtures are pinned
by the comparison module version and module checksum. Missing signed fixtures
fail the tests instead of silently skipping validation.

Unstripped Go executables use COFF long section names. A prefix that omits the
COFF string table fails header parsing. The stripped amd64 fixture has inline
names: complete headers can parse while `InputTruncated` reports missing payload,
and reading absent imports fails. These are distinct expected contracts.

## Run the checks

From the repository root:

```sh
go test -race ./...
go vet ./...
(cd benchmarks/exports && go test -race -v ./... && go vet ./...)
```

The comparison CI job runs the compiler corpus on Go 1.26. Root CI also runs on
stable Go, Windows, and macOS; that does not mean the optional comparison module
runs on every platform. Run the comparison module with stable Go locally before
release. The existing fuzz suite and synthetic malformed tests complement this
small corpus. Differential checks deliberately avoid treating another parser's
malformed-input recovery as the required behavior.

## Authenticode assurance

Existing signed-fixture tests check image digests and CMS signatures against
independent implementations. The new mutation cases preserve the CMS signature
but invalidate the image digest; go-pe must report both statuses separately,
leave trust unchecked without roots, and agree with go-uefi's image rejection.

This is offline integrity evidence. The go-uefi test certificate has an invalid
validity window; its acceptance by go-uefi is not evidence of valid X.509 trust.
Existing tests explicitly distinguish that result from go-pe's chain validation.
Generated tests cover additional timestamp and chain-policy cases. The native Windows checks below add a narrow `WinVerifyTrust` comparison.
The corpus does not cover revocation services, catalog signing, or the diversity
of production publisher chains and timestamp authorities.

Before claiming broader compatibility, extend the small native compiler and
signed Windows samples below with licensed, provenance-recorded samples from real
consumers and relevant malformed files with explicit expected results. Keep
samples benign and redistributable; preserve a source revision, license, hash,
and expected result for every imported sample. No Windows loader or trust
conformance claim is justified by the current corpus.

## Benchmark dependency review

The 2026-11-17 scan initially found no reachable vulnerable symbols, but reported
one imported-package and 23 module-level findings in the comparison dependency
graph. Updating `golang.org/x/crypto` from v0.33.0 to v0.59.0 and
`golang.org/x/text` from v0.22.0 to v0.44.0 also selected `golang.org/x/sys`
v0.50.0. All retain Go 1.26 compatibility. The root module remains dependency-free.

After the updates, `govulncheck -test -show verbose ./...` reports no findings in
the comparison module. This is a dated database result, not a guarantee against
unknown vulnerabilities. Run both module scans before release. Historical
benchmark timings remain tied to their recorded revisions and dependency versions;
these updates do not refresh those measurements.

## Native Windows checks

The Windows amd64 CI job runs `.github/scripts/native-validation.ps1` in an
MSVC developer environment. It requires both MSVC and Clang's `clang-cl` driver.
Each compiler builds the same repository-authored C function into a DLL with no
entry point or C runtime dependency. Tests compare its ordinary export RVA and
forwarder string with Windows loader resolution, call the generated function
(expected value: 42), and resolve the forwarded process-ID function. Only these
benign, locally compiled DLLs are loaded; no external corpus binary is executed.
This tests Clang's compiler with the MSVC linker, not an independent LLVM linker.

The job also reads the runner's installed MSVC compiler executable (`cl.exe`). It
requires an embedded signature and timestamp, checks image digest, CMS, timestamp
imprint and timestamp CMS integrity, and requires trust to remain unchecked in
go-pe without explicit roots. It compares the original image and a temporary
section-byte mutation with `WinVerifyTrust`: the original must be accepted, the
mutation must return `TRUST_E_BAD_DIGEST`, and generated unsigned DLLs must return
`TRUST_E_NOSIGNATURE`.

`WinVerifyTrust` uses `WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI, disabled
revocation checking, and cache-only URL retrieval. The test closes trust-provider
state and does not install certificates or change trust stores. Windows uses the
runner's existing roots and policy; go-pe uses no roots. Agreement here concerns
these specific acceptance and integrity outcomes, not equivalent trust decisions.
See Microsoft's [WinVerifyTrust documentation](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
and [WINTRUST_DATA flags](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

Run the script on a disposable Windows amd64 host with Go, Visual Studio C++ tools,
and LLVM installed. It changes compiler environment variables only in the current
process. The tests are opt-in outside this CI step. The signed compiler file is read
from its existing installation and is never committed, uploaded, or redistributed;
only a temporary mutated copy is written and deleted by the test harness. Generated
DLLs use repository-authored source under this repository's license.

The runner OS, compiler paths/versions, sample paths, sizes, SHA-256 hashes, and
timestamp times are logged. Hosted images and installed binaries change, so this
is a reproducible procedure, not a byte-pinned corpus. A changed sample lacking an
embedded signature or timestamp fails explicitly instead of silently losing
coverage. It does not cover revocation, catalog signatures, arbitrary commercial
publishers, exhaustive loader behavior, or every Windows trust-policy option.
