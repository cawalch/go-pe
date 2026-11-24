# Parse PE metadata

This guide describes buffer ownership, parser limits, error handling, and
address conversion. For installation and a complete example, see the
[README](../README.md).

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

The parser uses the import lookup table when present, while deriving each
symbol's IAT slot RVA (`IATSlotRVA`, `HasIATSlot`) from `FirstThunk` and the
PE32/PE32+ pointer width without dereferencing IAT pointer values (using
`HasIATSlot == false, IATSlotRVA == 0` when `FirstThunk` is zero or the slot RVA
overflows `uint32`). If its lookup-table RVA is zero, the
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

### Read delayed imports

Use `file.DelayImports(data)` with the original bytes passed to `New` to read
delayed import descriptors (`DataDirectoryDelayImport`, index 13) in file
order. It enforces the same bounds and limits (`MaxDelayImportLibraries = 1,024`,
`MaxDelayImportSymbols = 65,536`, `MaxDelayImportNameBytes = 4,096`,
`MaxDelayImportStringBytes = 1 MiB`) and classifies errors with
`ErrInvalidDelayImport` and `ErrDelayImportLimit`.

Descriptors with `Attributes == DelayImportAttrRVA` (`1`) use direct RVAs on
PE32 and PE32+. Legacy descriptors with `Attributes == 0` subtract
`OptionalHeader.ImageBase` from nonzero descriptor addresses and non-ordinal
thunk values on PE32 images and return `ErrInvalidDelayImport` on PE32+; any
other attribute bits also return `ErrInvalidDelayImport`. When
`ImportNameTableRVA` is zero and `TimeDateStamp` is zero, lookup falls back to
`ImportAddressTableRVA`.

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

See [Export parser comparisons](../benchmarks/exports/README.md) and
[Workload comparisons and parser audit](workloads-and-audit.md) for the
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
  ordered `Entries` (`ToolID`, `Version`, `Count`), `ComputedChecksum`,
  `ChecksumValid`, and `PaddingNonZero`.
- Computes and reports `ChecksumValid == false` on checksum mismatch rather than
  returning an error, and preserves non-zero 12-byte padding after `"DanS"`
  with `PaddingNonZero == true`; returns `ErrInvalidRichHeader` on missing
  matching markers, zero XOR keys, or short or unaligned spans, and
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

## Load configuration and base relocations

- `File.LoadConfig` decodes `IMAGE_LOAD_CONFIG_DIRECTORY32` / `IMAGE_LOAD_CONFIG_DIRECTORY64` (`SecurityCookie`, `SEHandlerTable`, `GuardCFFunctionTable`, `CHPEMetadataPointer`).
- `File.BaseRelocs` decodes `IMAGE_BASE_RELOCATION` blocks and counts active (non-`ABSOLUTE`) relocation entries.
- `DelayAwareImphash` and `File.DelayAwareImphash` hash both standard and delayed imports.
- Package `detect` (`github.com/cawalch/go-pe/detect`) provides higher-level heuristic checks (`detect.Mitigations`, `detect.ImportsAndExports`, `detect.Runtime`, `detect.Rich`, `detect.PDB`) outside the core parser.

## Related libraries

Other Go libraries provide PE analysis features beyond this parser's scope.
The following descriptions reflect the source reviewed on November 11, 2026:

| Library | Capabilities |
| --- | --- |
| [Go `debug/pe`](https://pkg.go.dev/debug/pe) | PE and COFF access. Its documentation excludes hardening for adversarial input. |
| [saferwall/pe](https://github.com/saferwall/pe) | Malware analysis features. Version 1.6.5 supports byte-slice input, a `Fast` mode that skips data directories, and options to skip individual directories. |
| [Velocidex/go-pe](https://github.com/Velocidex/go-pe) | Version 0.1.0 accepts `io.ReaderAt` and reads imports, sections, debug metadata, and version information. |
| [Binject/debug](https://github.com/Binject/debug) | Extends standard-library parsers with executable writing and relocation editing. |

