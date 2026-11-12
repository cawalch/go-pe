# Export parser comparisons

This optional module compares go-pe with existing export parsers. Its dependencies
are separate from the root module; importing go-pe doesn't download these parsers.

## Implementations assessed

The source review on November 12, 2026 covered the following implementations:

| Implementation | Findings relevant to this change |
| --- | --- |
| [Go `debug/pe`, Go 1.26.9](https://github.com/golang/go/blob/go1.26.9/src/debug/pe/file.go) | Provides headers and imports, but no export parser API. |
| [saferwall/pe v1.6.5](https://github.com/saferwall/pe/blob/v1.6.5/exports.go) | Reads names, ordinals, and forwarders into mutable `File.Export` state. It filters symbol names, skips zero-RVA slots, and records anomalies. Its options can omit unrelated directories. Dependencies include PKCS#7, memory mapping, and text support. The repository has an MIT license; the export source carries an Apache 2.0 notice. |
| [Binject/debug at `4e22595eaac6`](https://github.com/Binject/debug/blob/4e22595eaac6ef91e0f45a2a1ef6e765d75a88a7/pe/exports.go) | Offers `Exports()` on a reader-backed file under a BSD-style license. Its export path reads from the directory's section and maps one name per ordinal. Its forwarder classification uses the section range. |

The DLL-name RVA addition also follows the existing APIs: saferwall retains
this value in `Export.Struct.Name`, and Binject names its raw directory field
`NameRVA`. go-pe exposes `DLLNameRVA` alongside its existing `DLL` string. This
preserves missing-versus-empty name information without another parsing pass or
a runtime dependency.

The implementation follows the
[Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)
and reuses go-pe's existing RVA bounds logic. It doesn't copy code from these
parsers or wrap their error recovery. This preserves go-pe's owned snapshots,
per-call limits, mapping rules, aliases, and all-or-error contract without a
new runtime dependency. The root package's tests cover those policies separately.

## Comparison scope

`TestCommonExportRecords` compares names, full ordinals, target RVAs, and
forwarder strings on generated PE32 and PE32+ metadata. Cases include named,
ordinal-only, and forwarded exports. The shared fixtures have valid metadata
tables and target RVAs outside the file; these parsers don't read target code.
The saferwall comparison also checks the DLL name and its raw RVA.

The common cases exclude holes, duplicate aliases, unsorted or unusual names,
cross-section tables, and malformed metadata. Those behaviors differ between
implementations and aren't an independent correctness oracle for go-pe. The
root tests exercise them against explicit format and parser contracts.

Each `BenchmarkParseExports` iteration starts from the same in-memory bytes,
parses headers and exports, checks the symbol count, and closes any reader-backed
file. Saferwall's options omit unrelated data directories, although its normal
header parsing includes Rich and COFF metadata. No timed file I/O occurs.
The libraries perform different checks and return different representations.
These measurements don't establish overall speed or safety superiority.

## Run the comparisons

From this directory, download the pinned dependencies and run the comparisons:

```sh
go test -race ./...
go test -run '^$' -bench '^BenchmarkParseExports$' -benchmem -benchtime=1s -count=6
```

To measure only export parsing from an existing go-pe header snapshot, run this
command from the repository root:

```sh
go test -run '^$' -bench '^BenchmarkExports$' -benchmem -benchtime=500ms -count=6
```

Keep concurrent fuzzing and other timed workloads out of benchmark runs. Record
the CPU, Go version, source revision, sample duration, and raw results. Use
`benchstat` to compare samples; don't interpret a single run as a regression.

The [recorded samples](results/README.md) include the source revisions, measured
medians, and the baseline check for the shared RVA-bounds helper.
