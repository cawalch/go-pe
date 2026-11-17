# Workload comparisons and parser audit

This document records the parser limit audit, semantic contract comparison,
and reproducible benchmark measurements for `go-pe` (`go-pe#4`). It qualifies
work limits and resource bounds across headers, standard imports, standard
exports, malformed inputs, and non-PE rejection without comparing eager full
parsing against header-only parsing as equivalent.

This is a historical comparison of commit `1fd2b31748950d1030ddbf2ff90f1eae4f7d37b2`
(2026-11-12), not an audit of the current release. The results do not measure
later parser changes or metadata and Authenticode features. For current behavior
and limits, see the [parsing guide](parsing.md).

## Reproducibility metadata

- **CPU and OS:** Apple M3 Max, `darwin/arm64` (`GOMAXPROCS=14`)
- **Go toolchain:** `go1.27.4 darwin/arm64` (module `go.mod` targets `go 1.26.0`+)
- **Root module dependencies:** zero external dependencies (`go 1.26.0` standard library only)
- **Compared implementations (`benchmarks/exports/go.mod`):**
  - `github.com/cawalch/go-pe` (unchanged core at `1fd2b31748950d1030ddbf2ff90f1eae4f7d37b2`)
  - `debug/pe` (`Go 1.27.4` standard library)
  - `github.com/saferwall/pe v1.6.5` (`Fast: true` for headers; `Omit*Directory: true` except the target directory for single-directory runs; custom discard logger)
  - `github.com/Binject/debug v0.0.0-20260128230015-4e22595eaac6`
  - `github.com/Velocidex/go-pe v0.1.0` (`NewPEFile(io.ReaderAt)` eagerly parses headers, sections, imports, `.rsrc` version strings, and `RSDS` debug data; no directory-skipping options exist)

### Fixture inventory

All comparison inputs are synthetic fixtures from `internal/testfixture` or
redistributable binaries shipped with Go in `$GOROOT/src/debug/pe/testdata`:

| Fixture | Format | Size (B) | SHA-256 |
| --- | --- | ---: | --- |
| `SyntheticPE32_8Sec` | Synthetic PE32, 8 sections | 5,120 | `410b2a3261279e5720e385e7b91760250b286cedb4d5988914d23d470aadc73d` |
| `SyntheticPE64_8Sec` | Synthetic PE32+, 8 sections | 5,120 | `40abba3aa52159438faab75e05d49c2dfc6f63f14268bb52e9f8a48d77bef196` |
| `SyntheticPE32_Imports16` | Synthetic PE32, 1 DLL, 16 imports | 1,024 | `68f740db58aa4b4119d73b1a360912a8c114443fa343caf31dfe9e3ff154ed29` |
| `SyntheticPE64_Imports16` | Synthetic PE32+, 1 DLL, 16 imports | 1,024 | `73a8812d5f20fed0176f19d031d536ae97e58144583ea3fbf40caa2413f7bdc2` |
| `gcc-386-mingw-exec` | Go toolchain PE32 executable | 29,941 | `41735cf200a619638541bfa8372df9a8bf736c77bb790863a58ff5c5c1160a36` |
| `gcc-amd64-mingw-exec` | Go toolchain PE32+ executable | 273,083 | `fc2c31e826718712cb56787f7ea30dae8d2feb2c29c9f1b75f8fa019d0bbd08e` |
| `gcc-386-mingw-no-symbols-exec` | Go toolchain PE32 stripped | 8,704 | `a939363feed3acf6732f95cd718a5237f31e955b6e97e903e0f097f1acf9675c` |
| `vmlinuz-4.15.0-47-generic` | Go toolchain PE32+ EFI stub | 474 | `8dc489079133c761f3a8b070180cf370ca4b21fdb6645f22e36aa0a1bf0dedca` |
| `gcc-amd64-mingw-obj` | Go toolchain COFF object | 736 | `953a5b4706351490a52016cc4b792cf4c4f75379d5f8547e398bfe454ca497c2` |

To reproduce the tests and benchmarks:

```sh
cd benchmarks/exports
go test -v -race ./...
go test -run '^$' -bench . -benchmem -count=5 | tee results/comparison-workloads.txt
benchstat results/comparison-workloads.txt
```

## Parser limit, mutability, and error audit

### Work and output bounds

`go-pe` executes synchronously without cancellation callbacks or internal caches.
The entry points examined in this historical audit apply the following limits:

| Entry point | Hard limits | Worst-case work / allocation notes |
| --- | --- | --- |
| `New` / `Open` | `MaxSections = 256`, `MaxSectionNameBytes = 256`, first `16` data directories (`NumberOfDataDirectories`) | Validates the `40*N`-byte section table (max `10,240` B) before allocating `[]Section`. Resolves up to `256` COFF long names (`<= 64` KiB total). `OptionalHeader` contains copied values, including a fixed-size data-directory array; it does not retain the input. Section bodies are never read. `Open` calls `os.ReadFile` eagerly, so callers must bound file size if reading untrusted paths. |
| `File.Imports` | `MaxImportLibraries = 1,024`, `MaxImportSymbols = 65,536`, `MaxImportNameBytes = 4,096`, `MaxImportStringBytes = 1 MiB` | `1 MiB` budget decrements on every DLL and symbol name, including NULs and repeated RVA references. Each descriptor lookup table and named thunk calls `rvaSpan`, which scans up to `MaxSections` (`256`) sections twice (`<= 33.5M` section comparisons worst case at 65,536 symbols across 256 sections). Returns `nil, nil` with `0` allocations if no import directory exists. |
| `File.Exports` | `MaxExportSymbols = 65,536`, `MaxExportNames = 65,536`, `MaxExportNameBytes = 4,096`, `MaxExportStringBytes = 1 MiB` | Validates directory extent overflow, ordinal-base overflow, table bounds, and every ordinal-table index before allocating `Symbols` and the single alias string backing array (`pool := make([]string, names)`). String budget covers `DLL`, forwarders, and names including repeated references and NULs. Returns `nil, nil` with `0` allocations if no export directory exists. |

### Ownership and mutability contracts

- **`New(data)`**: Returns an owned `File` snapshot that retains no reference to
  `data`. Callers can overwrite or release `data` immediately unless later
  passing it to `Imports` or `Exports`.
- **`File` and `SectionByName`**: `File` exposes mutable exported fields
  (`DOSHeader`, `FileHeader`, `OptionalHeader`, `Sections`). `SectionByName`
  returns a `*Section` pointer directly into `File.Sections`; writing through
  it modifies the `File`. Read-only concurrent use is safe as long as callers do
  not mutate `File`.
- **`File.Imports` and `File.Exports`**: Neither mutates `File`, caches results,
  or retains references to `data`. Returned slices and strings are freshly owned
  (no shared alias slice capacity across export symbols).

### Strict rejection vs. partial recovery

| Input condition | `go-pe` | `debug/pe` | `Binject/debug` | `saferwall/pe` | `Velocidex/go-pe` |
| --- | --- | --- | --- | --- | --- |
| Non-PE (`NonPE4KiB`) | `ErrNotPE` (`nil` result) | Error (unknown machine) | Error (allocates `2.04 GiB` before failing) | Error (`ErrDOSMagicNotFound`) | Error |
| Standalone COFF object (`gcc-amd64-mingw-obj`) | `ErrNotPE` | Accepts (`OptionalHeader == nil`; `ImportedSymbols` returns `nil, nil`) | `NewFile` accepts; `ImportedSymbols()` panics on nil `OptionalHeader` | Error (`ErrDOSMagicNotFound`) | Error |
| Minimal optional-header EFI stub (`vmlinuz-4.15.0-47-generic`) | Accepts (`0` imports) | Accepts (`nil` `OptionalHeader`, `0` imports) | `NewFile` accepts; `ImportedSymbols()` panics on nil `OptionalHeader` | Accepts | Accepts |
| Over section limit (`257` sections) | `ErrSectionLimit` (`nil` result) | Accepts all `257` | Accepts all `257` | Accepts all `257` | Accepts all `257` |
| Over import limit (`65,537` symbols) | `ErrImportLimit` (`nil` result) | Accepts all `65,537` | Accepts all `65,537` | Accepts all `65,537` | Accepts all `65,537` |
| Over export limit (`65,537` slots) | `ErrExportLimit` (`nil` result) | Unsupported (no export parser) | Accepts (`exports`) | Partial / logs warning, returns `nil` error | Unsupported |
| Unmapped import DLL RVA | `ErrOutOfBounds` (`nil` result) | Ignores error, keeps library with empty DLL | Ignores error, keeps library with empty DLL | Logs warning, returns `nil` error (partial recovery) | Skips via offset `0`, no error |

The header, import, and export parsers examined here enforce atomic error handling:
on malformed structure, truncated
span, integer overflow (`ErrIntegerOverflow`), or limit breach
(`ErrSectionLimit`, `ErrImportLimit`, `ErrExportLimit`), methods discard
partial state and return `(nil, err)`. Errors classify with `errors.Is` using
`ErrNotPE`, `ErrShortDOS`, `ErrInvalidMagic`, `ErrInvalidHeader`,
`ErrSectionLimit`, `ErrOutOfBounds`, `ErrIntegerOverflow`,
`ErrUnterminatedString`, `ErrInvalidImport`, `ErrImportLimit`,
`ErrInvalidExport`, and `ErrExportLimit`.

## Benchmark results

All timings below are medians of 5 runs (`-benchmem -count=5`) saved in
[comparison-workloads.txt](../benchmarks/exports/results/comparison-workloads.txt).
Retained heap bytes per kept object come from `TestRetainedBytes` (100 live
instances on `gcc-amd64-mingw-exec`, double GC before/after measurement).

### Headers and retained heap memory

Because `debug/pe`, `Binject`, `saferwall` (`Fast: true`), and `Velocidex`
eagerly parse additional tables (COFF symbols/relocs for `debug/pe` and
`Binject`; Rich header and COFF symbols for `saferwall`; imports, `.rsrc`
version info, and `RSDS` debug metadata for `Velocidex`), those columns reflect
their actual header-entry API work rather than identical subsets:

| Workload | Implementation | Time/op | Alloc/op | Allocs/op | Scope notes |
| --- | --- | ---: | ---: | ---: | --- |
| `SyntheticPE32_8Sec` | `go-pe` (`New`) | `256.4 ns` | `874 B` | `10` | Headers + 8 sections only |
| `SyntheticPE32_8Sec` | `debug/pe` | `2.815 µs` | `2.539 KiB` | `72` | Headers + section readers + relocs |
| `SyntheticPE32_8Sec` | `Binject` | `3.311 µs` | `3.219 KiB` | `45` | Headers + DOS stub check + relocs |
| `SyntheticPE32_8Sec` | `saferwall` (`Fast`) | `3.407 µs` | `3.533 KiB` | `43` | Headers + Rich/COFF checks |
| `SyntheticPE32_8Sec` | `Velocidex` (`NewPEFile`) | `3.942 µs` | `15.30 KiB` | `215` | Eager: headers + dirs |
| `SyntheticPE64_8Sec` | `go-pe` (`New`) | `261.5 ns` | `874 B` | `10` | Headers + 8 sections only |
| `SyntheticPE64_8Sec` | `debug/pe` | `2.856 µs` | `2.570 KiB` | `71` | Headers + section readers + relocs |
| `SyntheticPE64_8Sec` | `Binject` | `3.312 µs` | `3.234 KiB` | `45` | Headers + DOS stub check + relocs |
| `SyntheticPE64_8Sec` | `saferwall` (`Fast`) | `3.440 µs` | `3.564 KiB` | `43` | Headers + Rich/COFF checks |
| `SyntheticPE64_8Sec` | `Velocidex` (`NewPEFile`) | `3.942 µs` | `15.30 KiB` | `215` | Eager: headers + dirs |
| `GCC_386_MinGW` | `go-pe` (`New`) | `524.3 ns` | `1.406 KiB` | `17` | No COFF symbol-table read |
| `GCC_386_MinGW` | `Velocidex` (`NewPEFile`) | `15.27 µs` | `74.71 KiB` | `583` | Eager reader-based |
| `GCC_386_MinGW` | `Binject` | `75.34 µs` | `66.97 KiB` | `1,128` | Eager COFF symbols + string table |
| `GCC_386_MinGW` | `debug/pe` | `90.59 µs` | `66.24 KiB` | `1,794` | Eager COFF symbols + string table |
| `GCC_386_MinGW` | `saferwall` (`Fast`) | `158.5 µs` | `134.2 KiB` | `6,933` | Eager COFF symbols + Rich |
| `GCC_AMD64_MinGW` | `go-pe` (`New`) | `540.1 ns` | `1.547 KiB` | `19` | No COFF symbol-table read |
| `GCC_AMD64_MinGW` | `Velocidex` (`NewPEFile`) | `23.54 µs` | `118.0 KiB` | `798` | Eager reader-based |
| `GCC_AMD64_MinGW` | `Binject` | `198.2 µs` | `173.4 KiB` | `2,698` | Eager COFF symbols + string table |
| `GCC_AMD64_MinGW` | `debug/pe` | `246.4 µs` | `176.5 KiB` | `4,509` | Eager COFF symbols + string table |
| `GCC_AMD64_MinGW` | `saferwall` (`Fast`) | `363.5 µs` | `306.5 KiB` | `14,460` | Eager COFF symbols + Rich |

Retained heap memory per kept object on `gcc-amd64-mingw-exec` (273,083 B input):

| Implementation | Retained bytes/object | Why retained |
| --- | ---: | --- |
| `go-pe` (`New`) | `1,859 B` | Copied header/section metadata only; input buffer freed |
| `go-pe` (`Imports`) | `3,245 B` | Owned `[]ImportLibrary`; input buffer freed |
| `Velocidex` (`NewPEFile`) | `282,057 B` | Retains `bytes.NewReader` backing buffer and eager structs |
| `saferwall` (`Fast`) | `351,841 B` | Retains input slice, copied `Header`, and COFF symbols |
| `saferwall` (`ImportsOnly`) | `356,793 B` | Retains input slice and parsed import structures |
| `debug/pe` | `405,059 B` | Retains `bytes.NewReader`, `StringTable`, `COFFSymbols`, and section readers |
| `Binject` | `405,707 B` | Retains `bytes.NewReader`, `COFFSymbols`, and section readers |

### Standard imports

| Workload | Implementation | Time/op | Alloc/op | Allocs/op |
| --- | --- | ---: | ---: | ---: |
| `SyntheticPE64_Symbols16` | `go-pe` (`New`+`Imports`) | `655.5 ns` | `1.500 KiB` | `27` |
| `SyntheticPE64_Symbols16` | `debug/pe` | `2.320 µs` | `3.805 KiB` | `84` |
| `SyntheticPE64_Symbols16` | `Binject` | `2.653 µs` | `3.430 KiB` | `59` |
| `SyntheticPE64_Symbols16` | `Velocidex` (`NewPEFile`) | `4.764 µs` | `23.52 KiB` | `175` |
| `SyntheticPE64_Symbols16` | `saferwall` (`ImportsOnly`) | `9.282 µs` | `12.25 KiB` | `192` |
| `SyntheticPE64_Symbols256` | `go-pe` (`New`+`Imports`) | `6.419 µs` | `19.88 KiB` | `271` |
| `SyntheticPE64_Symbols256` | `Binject` | `12.52 µs` | `27.55 KiB` | `543` |
| `SyntheticPE64_Symbols256` | `debug/pe` | `13.73 µs` | `40.18 KiB` | `568` |
| `SyntheticPE64_Symbols256` | `Velocidex` (`NewPEFile`) | `49.54 µs` | `294.1 KiB` | `1,383` |
| `SyntheticPE64_Symbols256` | `saferwall` (`ImportsOnly`) | `113.4 µs` | `179.6 KiB` | `2,156` |
| `SyntheticPE32_Symbols256` | `go-pe` (`New`+`Imports`) | `8.072 µs` | `19.88 KiB` | `271` |
| `SyntheticPE32_Symbols256` | `Binject` | `12.67 µs` | `26.91 KiB` | `543` |
| `SyntheticPE32_Symbols256` | `debug/pe` | `13.91 µs` | `38.32 KiB` | `571` |
| `SyntheticPE32_Symbols256` | `Velocidex` (`NewPEFile`) | `52.38 µs` | `291.5 KiB` | `1,383` |
| `SyntheticPE32_Symbols256` | `saferwall` (`ImportsOnly`) | `112.2 µs` | `149.4 KiB` | `2,154` |
| `GCC_AMD64_MinGW` | `go-pe` (`New`+`Imports`) | `3.228 µs` | `5.859 KiB` | `101` |
| `GCC_AMD64_MinGW` | `Velocidex` (`NewPEFile`) | `24.51 µs` | `118.0 KiB` | `798` |
| `GCC_AMD64_MinGW` | `Binject` | `205.2 µs` | `181.1 KiB` | `2,842` |
| `GCC_AMD64_MinGW` | `debug/pe` | `250.7 µs` | `192.0 KiB` | `4,653` |
| `GCC_AMD64_MinGW` | `saferwall` (`ImportsOnly`) | `458.4 µs` | `350.5 KiB` | `15,090` |

### Standard exports (`BenchmarkParseExports`)

| Workload | Implementation | Time/op | Alloc/op | Allocs/op |
| --- | --- | ---: | ---: | ---: |
| `Symbols16` | `go-pe` (`New`+`Exports`) | `854.6 ns` | `2.086 KiB` | `24` |
| `Symbols16` | `Binject` | `3.677 µs` | `4.562 KiB` | `45` |
| `Symbols16` | `saferwall` (`ExportsOnly`) | `7.058 µs` | `8.312 KiB` | `101` |
| `Symbols256` | `go-pe` (`New`+`Exports`) | `9.743 µs` | `26.27 KiB` | `264` |
| `Symbols256` | `Binject` | `28.30 µs` | `54.38 KiB` | `297` |
| `Symbols256` | `saferwall` (`ExportsOnly`) | `76.65 µs` | `99.81 KiB` | `844` |

### Non-PE rejection, limits, and I/O separation

| Workload | Implementation | Time/op | Alloc/op | Allocs/op | Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| `NonPE4KiB` | `go-pe` | `5.499 ns` | `0 B` | `0` | Rejects at DOS magic |
| `NonPE4KiB` | `Velocidex` | `135.0 ns` | `706 B` | `4` | Rejects at DOS magic |
| `NonPE4KiB` | `debug/pe` | `214.4 ns` | `426 B` | `8` | Rejects on COFF machine fallback |
| `NonPE4KiB` | `saferwall` (`Fast`) | `445.0 ns` | `1.266 KiB` | `4` | Rejects at DOS magic |
| `NonPE4KiB` | `Binject` | `25.24 ms` | `2.040 GiB` | `14` | Allocates based on bytes `[60:64]` before checking `MZ` |
| `SectionLimit257` | `go-pe` | `210.1 ns` | `178 B` | `5` | Rejects before section-slice alloc |
| `SectionLimit257` | `saferwall` (`Fast`) | `67.61 µs` | `63.43 KiB` | `800` | Accepts 257 sections |
| `ExportLimit65537` | `go-pe` | `152.9 ns` | `456 B` | `3` | Rejects before slot-slice alloc |
| `ExportLimit65537` | `saferwall` (`ExportsOnly`) | `3.682 µs` | `5.004 KiB` | `42` | Partial / warns on truncated names |
| `ImportLimit65537` | `go-pe` | `2.759 ms` | `8.684 MiB` | `65.58k` | Fails cleanly at symbol `65,537` |
| `ImportLimit65537` | `saferwall` (`ImportsOnly`) | `33.90 ms` | `59.27 MiB` | `526.5k` | Accepts 65,537 symbols |
| `FileIO_GCC_AMD64_MinGW` | `os.ReadFile` only | `45.29 µs` | `272.4 KiB` | `6` | Raw OS read baseline |
| `FileIO_GCC_AMD64_MinGW` | `go-pe.Open` | `44.06 µs` | `274.0 KiB` | `24` | `ReadFile` + `New` (`~540 ns` parse) |
| `FileIO_GCC_AMD64_MinGW` | `debug/pe.Open` | `930.2 µs` | `176.6 KiB` | `4,511` | Reader-based syscalls + COFF symbols |

Paired core benchmarks before vs. after adding test coverage show zero production
code changes, identical allocation counts (`allocs/op`), and `0 B` allocation
differences on `New`, `StandardLibraryHeaders`, and `RVAToOffset`.

## Feature scope since the comparison

As of 2026-11-17, the library implements resources, version information, Rich
headers, attribute certificates, delayed imports, CodeView debug metadata,
import hashing, and offline Authenticode parsing, digest calculation, and
signature and timestamp verification. These features are outside the benchmark
results above. Offline verification does not establish Windows trust equivalence.

Standalone COFF objects, TLS callbacks, base relocations, exception tables,
load-config directories, bound-import resolution, and CLR metadata parsing
remain outside the implemented scope. Data-directory header entries expose
addresses and sizes; they do not parse the corresponding structures. Scope new
features from concrete consumer needs, as described in
[Contributing](../CONTRIBUTING.md#scope-a-change).
