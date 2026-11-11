# go-pe

A standalone, pure-Go reader for PE32 and PE32+ image headers and sections.
Go 1.26 or newer; standard library only; MIT licensed.

**Status: early development.** The core has regression tests, bounded fuzz
targets and benchmarks. It is not a complete PE analysis engine, a Windows
loader, or a proven panic-free parser. No release has been published yet.

## Implemented

- DOS and COFF file headers, normalized PE32/PE32+ optional headers, and the
  first 16 data-directory descriptors (not their contents).
- Section headers and names, including bounded COFF long-name resolution when
  a symbol-table pointer is present.
- File-backed RVA/offset translation, section lookup, and DLL/bitness helpers.
- Bounds-checked little-endian reads and bounded NUL-terminated string reads.
- `New([]byte)` and `Open(path)`. `Open` reads the entire file into memory.

**Not implemented:** imports/exports, imphash, Authenticode or certificate
verification, Rich headers, resource/version information, standalone COFF
objects, ROM images, `io.ReaderAt`, mmap, or lazy directory parsing.

## Usage

```go
import (
    "fmt"
    pe "github.com/cawalch/go-pe"
)

f, err := pe.New(data) // data is a []byte containing an on-disk PE image
if err != nil {
    return err
}
fmt.Printf("machine=%#x sections=%d\n", f.FileHeader.Machine, f.NumberOfSections())
if offset, ok := f.RVAToOffset(f.OptionalHeader.AddressOfEntryPoint); ok {
    fmt.Printf("entry-point file offset=%#x\n", offset)
}
```

Use `go get github.com/cawalch/go-pe@main` for the development version.
No stable release is tagged yet; pin a commit when integrating a consumer.

## Parsing and ownership contract

- `New` reads the input synchronously and retains no reference to it. The result
  owns its headers and section names, so callers can reuse or release the input
  after parsing. There is no `Close` requirement or global parser state.
  Concurrent reads are supported when callers leave the exported fields unchanged.
  The separate `SafeReader` utility borrows its input for the reader's lifetime.
- Successful parsing requires complete DOS, signature, COFF, optional-header,
  and declared section-table bytes. Missing or unsupported optional headers,
  PE headers overlapping the DOS header, and directory counts exceeding the
  optional-header space return errors. Errors never accompany a partial `File`.
- Up to `MaxSections` (256) sections are accepted. This is a resource limit,
  not a claim about which images Windows can load. All declared section headers
  are checked before allocating the section array.
- Long section names must terminate within their declared COFF string table
  and `MaxSectionNameBytes` (256 bytes, including NUL). Malformed references
  return errors. Ordinary eight-byte names need no terminator. Symbol records
  are not decoded, and an unused symbol table is not validated.
- Directory descriptors are metadata only. A successful parse does not certify
  directory contents or section bodies. Missing bodies can be inspected through
  their headers, but address translation cannot return an absent file byte.
- `ReadASCIIZ` requires a positive bound and a NUL within that bound and the
  input. It does not silently return an unterminated prefix.

Use `errors.Is` with `ErrNotPE`, `ErrShortDOS`, `ErrInvalidMagic`,
`ErrInvalidHeader`, `ErrOutOfBounds`, `ErrIntegerOverflow`,
`ErrUnterminatedString`, and `ErrSectionLimit` as appropriate. These classify
parser failures; they do not decide an application's detection or trust policy.

### Address translation

Headers below `SizeOfHeaders` map directly if the byte exists. For other RVAs,
the first section in table order covering the RVA in
`max(VirtualSize, SizeOfRawData)` wins. Only its raw bytes map: virtual zero-fill,
arithmetic overflow and missing file bytes return `ok == false`. Raw alignment
padding is addressable. Reverse translation checks the first matching raw
section; overlays do not map. Overlapping sections can make the two functions
non-inverses. This explicit file-byte policy does not emulate the Windows loader
or promise another parser's malformed-image semantics.

## Scope and existing alternatives

The project began because of unmet Go PE-analysis requirements. That rationale
must be checked as the ecosystem changes, rather than assuming other parsers
are absent or unmaintained. Upstream review on **2026-11-11**:

| Alternative | Relevant capabilities and tradeoff |
| --- | --- |
| [Go `debug/pe`](https://pkg.go.dev/debug/pe) | Maintained PE/COFF access; useful as an independent oracle for valid headers. Its documentation explicitly excludes adversarial-input hardening. |
| [saferwall/pe](https://github.com/saferwall/pe) | Broad malware-analysis features and documented fuzzing. The inspected v1.6.5 exposes `NewBytes`, header-only `Fast` mode and per-directory omission options; it is not necessarily an eager full-file analysis. Evaluate these paths before duplicating its features. |
| [Velocidex/go-pe](https://github.com/Velocidex/go-pe) | The inspected v0.1.0 accepts `io.ReaderAt` and exposes imports, sections, RSDS/PDB and version information. Its short README understates its implementation. |
| [Binject/debug](https://github.com/Binject/debug) | Extends standard-library parsers with executable writing and relocation editing; a different scope from this reader. |

This core aims for explicit bounds, predictable work and a small dependency
surface. It has not established overall superiority to these libraries. Prefer
`encoding/binary` and other standard primitives; assess reuse, dependencies,
licenses, adversarial behavior and equivalent-work benchmarks before extending
the parser. Do not grow a generic binary-analysis framework speculatively.

## Consumer integration

`go-pe` has no dependency on go-yara and no YARA schema, module registry, global
cache, scanner lifecycle, or rule semantics. Any consumer owns input acquisition,
size limits, cancellation around this bounded synchronous core, and cache lifetime.
`Open` is a convenience for trusted file sizes, not bounded or cancellable I/O.

A go-yara adapter belongs in go-yara: it should own `pe.*` fields, undefined-value
behavior, scan-state reset, serialization integration and libyara parity tests.
Any future expensive directory parsing needs explicit work limits and cancellation
appropriate for general library callers. `io.ReaderAt` support should be driven
by measured consumer needs rather than coupled to a scanner's block model.

## Validation and performance

```sh
go test -race -cover ./...
go vet ./...
go test -run '^$' -fuzz '^FuzzNew$' -fuzztime=30s -parallel=2
go test -run '^$' -fuzz '^FuzzSafeReader$' -fuzztime=30s -parallel=2
go test -run '^$' -bench . -benchmem -count=5
```

Fixtures are generated locally; tests need no malware downloads, sibling
repositories, or network. Valid PE32/PE32+ scalar fields and sections are compared
with `debug/pe`; this is not malformed-input or full-engine parity. Regressions
cover header truncation, directory bounds, COFF strings, overflow, zero-fill,
overlaps, and concurrent reads. Fuzzing checks parser and reader invariants;
bounded runs are evidence, not proof of safety.

Benchmarks include 1/8/96/256 sections, non-PE rejection, address lookup and a
standard-library header-only comparison. Record the Go version, CPU and raw
results when comparing changes. Header parsing allocates a `File`, a section
slice and names; zero allocation for valid files and fixed nanosecond targets
are not promised. Header hardening and full DOS-field decoding replace the
initial prototype's permissive truncation and partial field population.

Format reference: [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
