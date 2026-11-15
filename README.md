# go-pe

go-pe is a Go library for reading Portable Executable (PE) image headers,
sections, standard imports, and exports. It supports PE32 and PE32+ images, uses only the
Go standard library, and requires Go 1.26 or later.

The library is in early development. No stable release is available.

## Supported features

You can use go-pe to read:

- DOS headers and Common Object File Format (COFF) file headers within PE images.
- PE32 and PE32+ optional headers and the first 16 data directory descriptors.
- Section headers and names, including names stored in a COFF string table.
- Standard import descriptors, DLL names, imports by name and hint or ordinal, and standard import hashes (`File.Imphash`, `Imphash`).
- Export directories, address slots, ordinal values, name aliases, and raw forwarders.
- Resource directory metadata, leaf paths, and bounded payload extraction (`File.Resources`, `File.ResourcePayload`).
- Rich headers (`File.RichHeader`), decoding XOR keys, raw/clear byte spans, `(@comp.id, count)` entries, and explicit checksum status.
- Bounded `VS_VERSION_INFO` version-information decoding (`ParseVersionInfo`), preserving ordered language/code-page tables, duplicate keys, translations, and unrecognized blocks.
- Bounded debug directory entries (`File.Debug`) and CodeView `RSDS`/`NB10` records with raw path bytes, GUID/signature, and age, while retaining unknown debug types as metadata.
- Security directory attribute certificate (`WIN_CERTIFICATE`) metadata records and raw payload extraction.
- Bounded PKCS#7 / CMS Authenticode signer, certificate, attribute, nested signature, and timestamp metadata without signature verification.
- Authenticode PE image digests and checked byte-range inspection for MD5, SHA-1, SHA-256, SHA-384, and SHA-512.

The library also provides section lookup, dynamic-link library (DLL) and format
checks, and conversion between relative virtual addresses (RVAs) and file
offsets. The `SafeReader` utility provides bounds-checked integer and string reads.

go-pe doesn't verify certificate trust chains, and it
doesn't parse delayed imports or external PDB symbol files.
It doesn't resolve bound import addresses. It doesn't
support standalone COFF objects, ROM images, loaded-memory images, memory-mapped
input, or `io.ReaderAt`.

## Install the library

To install the development version, run the following command in your Go module:

```sh
go get github.com/cawalch/go-pe@main
```

For reproducible builds, commit the resulting `go.mod` and `go.sum` files. Go
records a version that identifies the selected commit.

## Parse a file

The following program reads a PE file, prints its headers and standard imports,
and converts its entry-point RVA to a file offset. Save it as `main.go`:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cawalch/go-pe"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: inspect FILE")
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	file, err := pe.New(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Machine: %#x\n", file.FileHeader.Machine)
	fmt.Printf("Sections: %d\n", file.NumberOfSections())

	rva := file.OptionalHeader.AddressOfEntryPoint
	if offset, ok := file.RVAToOffset(rva); ok {
		fmt.Printf("Entry-point file offset: %#x\n", offset)
	} else {
		fmt.Println("Entry point has no file offset.")
	}

	libraries, err := file.Imports(data)
	if err != nil {
		log.Fatal(err)
	}
	for _, library := range libraries {
		for _, symbol := range library.Symbols {
			if symbol.ByOrdinal {
				fmt.Printf("%s: ordinal %d\n", library.DLL, symbol.Ordinal)
			} else {
				fmt.Printf("%s: %s (hint %d)\n", library.DLL, symbol.Name, symbol.Hint)
			}
		}
	}
}
```

To run the program, replace `sample.exe` with the path to your PE file:

```sh
go run . sample.exe
```

For headers and sections alone, you can use `Open(path)`. It reads the entire file
into memory and calls `New`. Neither function parses imports or exports. If you need to
control input size or I/O, acquire the bytes in your application and pass them to
`New(data)`.

## Use the parsed metadata

`New` copies header values and section names without retaining the input buffer.
It records `int64(len(data))` as `File.FileSize`, not the declared image extent;
a truncated input succeeds as long as its headers fit in `data`. Call
`File.DeclaredExtent` or `File.InputTruncated` to detect when `FileSize` is
smaller than the declared headers, raw sections, or certificate directory, or
use `NewWithLength(data, streamLength)` when only a stream prefix is buffered
while the full stream length is known. You can reuse or release the buffer
after `New` or `NewWithLength` returns unless you plan to pass it to `Imports`,
`Exports`, or another payload-reading method. The returned `File` doesn't require
a `Close` call.

If you don't modify its exported fields, you can read a `File` from multiple
goroutines. `SectionByName` returns a pointer into `File.Sections`, so changes through
that pointer modify the `File`.

Unlike `File`, `SafeReader` retains a reference to its input buffer. Don't modify
that buffer concurrently with reads.

### Read standard imports

Call `file.Imports(data)` with the original bytes passed to `New`. The method
returns owned DLL and symbol records in file order, preserving spelling and
duplicates. It doesn't retain the input, modify `File`, or cache results. Don't
modify the input or `File` during a call. Names preserve their bytes without
validating their encoding.

The parser uses the import lookup table when present. If its RVA is zero, the
parser uses the import address table only when the descriptor's timestamp is
zero. A bound image with a lookup table is supported; a bound image without one
returns `ErrInvalidImport`. The parser doesn't read the address table when a
lookup table is available.

A missing import directory returns `nil, nil`. A malformed or unsupported
directory returns an error and no partial results. Descriptors must end with a
zero descriptor within the declared directory size. Lookup tables and names
must terminate within their selected raw section or header range, the original
file size, and the supplied input. Virtual zero-fill doesn't supply missing
terminators.

The following limits apply to each call:

| Limit | Maximum |
| --- | --- |
| `MaxImportLibraries` | 1,024 descriptors |
| `MaxImportSymbols` | 65,536 symbols across all descriptors |
| `MaxImportNameBytes` | 4,096 bytes per name, including the NUL terminator |
| `MaxImportStringBytes` | 1 MiB of names, including NUL terminators and repeated references |

These limits bound parsing work and output. They aren't Windows loader limits.
Use `errors.Is` with `ErrInvalidImport`, `ErrImportLimit`, or the bounds and
string errors listed below to classify failures. An overlong name returns
`ErrUnterminatedString` when no NUL byte occurs within `MaxImportNameBytes`.

Use `file.Imphash(data)` (or `Imphash(libraries)` on already-parsed results) to
compute the lowercase hexadecimal MD5 import hash using libyara-compatible
extension stripping (`.dll`, `.ocx`, `.sys`) and frozen ordinal alias tables
for `ws2_32.dll`, `wsock32.dll`, and `oleaut32.dll`. Images with zero imported
symbols return `ErrNoImports` (from `File.Imphash`) or `("", false)` (from
`Imphash`) rather than hashing the empty string to `md5("")`.

### Read standard exports

Call `file.Exports(data)` with the original bytes passed to `New`. The method
returns an owned `ExportDirectory` or `nil, nil` for a missing directory. It
doesn't retain the input, modify `File`, or cache results. Don't modify the input
or `File` during a call.

`Symbols` follows export address table order and includes unused slots whose
`RVA` is zero. Each symbol has its full ordinal, including the directory's
ordinal base. `Names` preserves all aliases, duplicates, and empty names in name
pointer table order within that symbol. A nil `Names` slice means the slot has
no name pointers; the slot can be an ordinal-only export or an unused slot.
Names preserve their bytes without encoding checks or case folding.

`Forwarded` identifies an RVA within the export directory's declared range.
`Forwarder` contains the raw NUL-terminated string, which can be empty. The
parser doesn't validate its syntax or resolve other DLLs. Ordinary target RVAs
are returned without dereferencing them; they can refer to virtual zero-fill or
unmapped data.

`DLLNameRVA` preserves the export directory's raw DLL-name RVA. Zero means the
name is absent and `DLL` is empty. A nonzero RVA can point to a present empty
string, so use `DLLNameRVA` to distinguish these cases. `DLL` continues to hold
the decoded name. Nonzero name RVAs use the same bounds and terminator checks
as other export strings.

Tables and strings must fit within their selected raw section or header range,
the original file size, and the supplied bytes. Forwarder strings must also
terminate within the export directory's RVA range. The other tables and names
can be outside that range, including in another section. Unused table pointers
aren't read when their count is zero. The parser checks ordinal indexes, RVA
extent arithmetic, and ordinal-base addition before using them.

Each call permits at most 65,536 address slots (`MaxExportSymbols`), 65,536 name
pointers (`MaxExportNames`), 4,096 bytes per string including its NUL
(`MaxExportNameBytes`), and 1 MiB of total string bytes
(`MaxExportStringBytes`). Repeated references consume the string budget on each
read. These are work and output limits, not Windows loader limits. Parsing is
synchronous and doesn't accept a cancellation callback.

Failures return no partial directory. Use `errors.Is` with `ErrInvalidExport`,
`ErrExportLimit`, or the bounds, overflow, section-limit, and string errors below.
An overlong string returns `ErrUnterminatedString`; exhaustion of the total
string budget returns `ErrExportLimit`. The parser doesn't enforce name sorting
or establish that Windows can load the image.

See [Export parser comparisons](benchmarks/exports/README.md) and
[Workload comparisons and parser audit](docs/workloads-and-audit.md) for the
existing implementations assessed, limit and contract audits, benchmark
commands, and consumer directory gating.

### Read attribute certificates

`File.Certificates` enumerates `WIN_CERTIFICATE` records from the security data
directory (`DataDirectoryCertificate`, directory index 4) on demand from the
caller's byte slice. Because the security directory stores raw file offsets
rather than RVAs, this method doesn't convert directory addresses through the
section table. When the directory is absent or both its offset and size are
zero, `File.Certificates` returns `nil, nil` without allocating.

Each `CertificateRecord` reports the record's file offset, `dwLength` (including
the 8-byte header), `wRevision`, and `wCertificateType`. `File.Certificates`
validates 8-byte table and record alignment, alignment padding through the end of
the security directory, file bounds, overlap with PE headers or section raw
data, and `MaxCertificateRecords` (1,024 records) and `MaxCertificateBytes`
(4 MiB total directory bytes and individual payload bytes). It preserves entries
with unrecognized revision or type codes and returns no partial slice on error.

Use `File.CertificatePayload` with the same byte slice and a returned record to
extract an owned copy of `bCertificate` without retaining references into the
input buffer. On error, use `errors.Is` with `ErrInvalidCertificate`,
`ErrCertificateLimit`, `ErrInvalidHeader`, `ErrOutOfBounds`,
`ErrIntegerOverflow`, or `ErrSectionLimit`. Enumerating records and reading
payloads don't verify Authenticode signatures or parse embedded PKCS#7 structures.

### Calculate Authenticode image digests

Use `File.AuthenticodeDigest`, `File.AuthenticodeDigests`, and
`File.AuthenticodeDigestRanges` with the original bytes passed to `New` to
inspect hashed byte ranges and compute Authenticode PE image digests for
`crypto.MD5`, `crypto.SHA1`, `crypto.SHA256`, `crypto.SHA384`, and
`crypto.SHA512`. Each call excludes `OptionalHeader.CheckSum`,
`DataDirectory[DataDirectoryCertificate]` when present, and the
`WIN_CERTIFICATE` security directory when present, after validating header
bounds, non-overlapping sections in ascending `PointerToRawData` order,
security directory placement, and `MaxAuthenticodeDigestBytes` (256 MiB).

Images whose section bodies or headers overlap, overflow, or extend past EOF
return an error rather than partially hashing truncated bytes. Non-empty
inter-section gaps and trailing data after a security directory are included in
the non-excluded ranges, and unaligned unsigned binaries aren't padded with
virtual zero bytes. Pass an unsupported `crypto.Hash` to check for
`ErrUnsupportedDigestAlgorithm`.

### Parse version-information resources

Use `ParseVersionInfo` with a single `RT_VERSION` payload (for example from
`File.ResourcePayload`) to decode a Windows `VS_VERSION_INFO` tree into owned
Go records in file order:

- `HasFixedInfo` and `FixedInfo`: exposes `VS_FIXEDFILEINFO` when present
  (`Signature == VersionFixedInfoSignature`).
- `StringTables`: preserves every `StringFileInfo` child `StringTable` and all
  ordered `VersionString` key-value entries, including duplicate keys, empty
  values, and non-ASCII UTF-16 names.
- `Vars` and `Translations`: preserves ordered `VarFileInfo` records and
  decodes `(LanguageID, CodePage)` pairs from `"Translation"` binary values.
- `UnknownBlocks`: retains unrecognized child blocks directly inside
  `VS_VERSION_INFO` with owned raw value and remainder slices.

`ParseVersionInfo` enforces child-length bounds, 4-byte alignment, NUL
termination for node keys, unit semantics (`wType == VersionValueText` counts
UTF-16 code units while `wType == VersionValueBinary` counts bytes), and explicit
limits (`MaxVersionPayloadBytes`, `MaxVersionNodes`, `MaxVersionTables`,
`MaxVersionStrings`, `MaxVersionTranslations`, `MaxVersionNameUnits`,
`MaxVersionValueUnits`, and `MaxVersionOutputBytes`). On error, use `errors.Is`
with `ErrInvalidVersionInfo` or `ErrVersionInfoLimit`.

### Decode Rich headers

Use `File.RichHeader` to locate and decode MSVC-style Rich metadata between the
64-byte DOS header and `e_lfanew`:

- Returns `(nil, nil)` when no `"Rich"` marker exists in `[64, e_lfanew)`.
- Scans backward from `e_lfanew` for the last `"Rich"` marker and then backward
  in 4-byte steps for the nearest XOR-encoded `"DanS"` marker.
- Returns `Offset`, `RichOffset`, `Length`, `Key`, `RawData`, `ClearData`,
  ordered `Entries` (`ToolID`, `Version`, `Count`), `ComputedChecksum`, and
  `ChecksumValid`.
- Computes and reports `ChecksumValid == false` on checksum mismatch rather than
  returning an error; returns `ErrInvalidRichHeader` on missing matching markers,
  zero XOR keys, short or unaligned spans, or non-zero header padding, and
  `ErrRichHeaderLimit` when `MaxRichStubBytes`, `MaxRichHeaderBytes`, or
  `MaxRichEntries` is exceeded.

### Read debug directories and CodeView records

Use `File.Debug` with the original bytes passed to `New` to read bounded
`IMAGE_DEBUG_DIRECTORY` descriptors in file table order:

- Returns `(nil, nil)` when `DataDirectoryDebug` (index 6) is absent or both
  its `VirtualAddress` and `Size` are zero.
- Maps the 28-byte-aligned directory table through `RVAToOffset` within one
  header or raw section range, and preserves all entry header fields and entry
  ordering.
- Decodes `DebugTypeCodeView` payloads for `RSDS` (`CodeViewSignatureRSDS`,
  PDB 7.0 GUID and age) and `NB10` (`CodeViewSignatureNB10`, NB10 offset,
  signature, and age), retaining raw NUL-terminated path bytes (`PDBPath`)
  verbatim as an owned slice (`nil` when header-only, non-nil empty slice for
  explicit `""`). Non-CodeView debug types and unrecognized CodeView signatures
  retain metadata with `CodeView == nil`.
- Enforces file-offset precedence on CodeView payloads: `PointerToRawData`
  without `AddressOfRawData` reads directly within `[0, min(FileSize, len(data)))`
  (supporting overlay debug data); `AddressOfRawData` without
  `PointerToRawData` maps via `RVAToOffset`; and when both pointers are
  non-zero, `RVAToOffset(AddressOfRawData)` must equal `PointerToRawData` and
  stay within both file and section bounds (mismatches return `ErrInvalidDebug`).
- Enforces `MaxDebugEntries` (256), `MaxDebugPayloadBytes` (64 KiB per CodeView
  payload), `MaxCodeViewPathBytes` (4,096 bytes including NUL), and
  `MaxDebugTotalBytes` (1 MiB cumulative CodeView payload bytes).

### Verify Authenticode integrity and timestamps offline

Use `File.VerifyAuthenticode` or `File.VerifyAuthenticodeSignatures` with
`AuthenticodeVerifyOptions` to evaluate offline verification claims separately
without collapsing integrity, timestamp validity, and certificate trust into
a single boolean:

- `Digest`: compares computed PE Authenticode digests (`File.AuthenticodeDigests`)
  against `SpcIndirectDataContent.MessageDigest` and distinguishes invalid
  digests from unsupported algorithms.
- `Binding` and `CMS`: resolve `SignerIdentifier` uniquely within the
  `SignedData` certificate set, reject duplicate or multi-valued signed
  attributes (`contentType`, `messageDigest`, `signingTime`), check encapsulated
  content digests (both PKCS#7 v1 direct `SEQUENCE` contents and `OCTET STRING`
  wrapped CMS content), and verify RSA PKCS#1 v1.5, RSA-PSS, ECDSA, and Ed25519
  signatures offline.
- `Timestamps`: verify legacy PKCS#9 countersignatures (`1.2.840.113549.1.9.6`)
  and RFC 3161 `TSTInfo` tokens (`1.3.6.1.4.1.311.3.3.1` and
  `1.2.840.113549.1.9.16.2.14`) against parent signature bytes and validity
  bounds (`[NotBefore, NotAfter]` on both TSA and signer certificates).
- `Trust`: remains `AuthenticodeStatusUnchecked` unless explicit `Roots` (or
  `TimestampRoots`) are supplied in `AuthenticodeVerifyOptions`. Ambient OS
  trust stores and network AIA/OCSP/CRL fetches are never consulted.
- `MaxVerifyOps` (`MaxAuthenticodeVerifyOps = 512`) bounds cumulative
  signature, timestamp, and chain verification work with `ErrAuthenticodeLimit`.

### Handle malformed input

`New` returns either a complete header snapshot or an error. It requires complete
DOS and COFF headers, the PE signature, and the declared optional header and
section table. It rejects missing or unsupported optional headers, PE headers
that overlap the DOS header, and data directory counts that exceed the optional
header's capacity.

The following limits bound parsing work:

- `MaxSections` allows up to 256 sections. The parser checks the complete section
  table before allocating the section slice.
- `MaxSectionNameBytes` allows up to 256 bytes for a COFF long name, including its
  terminating NUL byte (`0x00`). The name must also fit within the declared COFF
  string table. Ordinary eight-byte section names don't need a terminator.

The parser resolves COFF long names when a symbol-table pointer is present. It
returns an error for an invalid reference. It doesn't decode symbol records or
validate an unused symbol table.

A successful parse confirms the header structure, not the contents of sections
or data directories. You can inspect headers when section bodies are missing or
truncated. These checks don't establish that Windows can load the image.

To classify errors, use `errors.Is` with `ErrNotPE`, `ErrShortDOS`,
`ErrInvalidMagic`, `ErrInvalidHeader`, `ErrOutOfBounds`, `ErrIntegerOverflow`,
`ErrUnterminatedString`, or `ErrSectionLimit`.

`SafeReader.ReadASCIIZ` requires a positive read limit and a NUL byte within both
that limit and the input. It returns an error if no terminator is present.

### Convert addresses

`RVAToOffset` maps an RVA to a byte that existed in the parsed input:

1. An RVA below `SizeOfHeaders` maps directly to the same file offset if that byte
   existed in the input.
2. For other RVAs, the method selects the first section in table order whose
   range contains the RVA. The range starts at `VirtualAddress` and spans
   `max(VirtualSize, SizeOfRawData)` bytes.
3. The method returns an offset only if the selected section contains the byte
   in its raw data and the offset fits within the original input.

Raw alignment padding can map to a file offset. Virtual zero-fill, arithmetic
overflow, and missing bytes return `ok == false`.

`OffsetToRVA` checks the headers, then the first matching raw section. File data
outside those ranges has no mapping. Overlapping sections can prevent the two
methods from being inverses. These methods don't emulate the Windows loader or
another parser's behavior for malformed images.

The certificate data directory stores a file offset in its `VirtualAddress`
field. Don't pass that value to `RVAToOffset`.

## Integrate with an application

go-pe is independent of go-yara and other scanners. Your application controls
input acquisition, input size limits, cancellation, and cache lifetime. Parsing
is synchronous; `Open` doesn't provide bounded or cancellable I/O.

Keep scanner adapters in the consuming project. For example, a go-yara adapter
owns YARA fields, undefined values, scan-state reset, and compatibility with
libyara. These behaviors aren't part of go-pe's API.

## Related libraries

Other Go libraries provide PE analysis features beyond this parser's scope.
The following descriptions reflect the source reviewed on November 11, 2026:

| Library | Capabilities |
| --- | --- |
| [Go `debug/pe`](https://pkg.go.dev/debug/pe) | PE and COFF access. Its documentation excludes hardening for adversarial input. |
| [saferwall/pe](https://github.com/saferwall/pe) | Malware analysis features. Version 1.6.5 supports byte-slice input, a `Fast` mode that skips data directories, and options to skip individual directories. |
| [Velocidex/go-pe](https://github.com/Velocidex/go-pe) | Version 0.1.0 accepts `io.ReaderAt` and reads imports, sections, debug metadata, and version information. |
| [Binject/debug](https://github.com/Binject/debug) | Extends standard-library parsers with executable writing and relocation editing. |

## Contribute

See [Contributing](CONTRIBUTING.md) for validation commands, feature scope, and
documentation style. The tests use generated fixtures and Go toolchain PE
fixtures. They require no malware samples, sibling repositories, or network
access after you install Go.

## References

- [API reference](https://pkg.go.dev/github.com/cawalch/go-pe)
- [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MIT license](LICENSE)
