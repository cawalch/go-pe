# go-pe

go-pe is a Go library for reading Windows Portable Executable (PE) files. It
supports PE32 and PE32+, uses only the Go standard library, and requires
Go 1.26 or later.

The library is in early development. No stable release is available.

## Supported features

- Read headers, sections, standard and delayed imports, and exports.
- Compute import hashes and convert relative virtual addresses (RVAs) to file
  offsets and back.
- Read resources, version information, Rich headers, and CodeView debug records.
- Extract attribute certificates and Authenticode signature metadata.
- Compute Authenticode image digests and verify signatures and timestamps
  offline. Certificate trust checks require caller-supplied roots.

The library doesn't parse external PDB symbol files or resolve bound import
addresses. It doesn't support standalone Common Object File Format (COFF)
objects, ROM images, loaded-memory images, memory-mapped input, or `io.ReaderAt`.

## Install the library

In your Go module, install the development version:

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

`New` parses headers and sections. To read imports, exports, or other metadata,
call the corresponding method with the original bytes. For headers and sections
alone, `Open(path)` reads the entire file and calls `New`.

## Use the parsed metadata

`New` copies header values and section names without retaining the input buffer.
Keep the buffer if you need to read other metadata. A `File` doesn't require a
`Close` call. You can read it from multiple goroutines if you don't modify its
exported fields.

A successful header parse doesn't mean the file is complete or that Windows can
load it. Use `File.InputTruncated` or `File.DeclaredExtent` to check whether the
input is shorter than its declared headers, sections, or certificate directory.
If you have only a stream prefix, use `NewWithLength` to supply the full length.

The [parsing guide](docs/parsing.md) explains ownership, limits, errors, and
address conversion. Use the [API reference](https://pkg.go.dev/github.com/cawalch/go-pe)
for individual types and methods.

| Task | API | Details |
| --- | --- | --- |
| Read standard imports and compute import hashes | `File.Imports`, `File.Imphash`, `Imphash` | [Standard imports](docs/parsing.md#read-standard-imports) |
| Read delayed imports | `File.DelayImports` | [Delayed imports](docs/parsing.md#read-delayed-imports) |
| Read exports and forwarders | `File.Exports` | [Exports](docs/parsing.md#read-standard-exports) |
| Read resources and version information | `File.Resources`, `File.ResourcePayload`, `ParseVersionInfo` | [Version information](docs/parsing.md#parse-version-information-resources) |
| Decode Rich headers | `File.RichHeader` | [Rich headers](docs/parsing.md#decode-rich-headers) |
| Read debug records | `File.Debug` | [Debug records](docs/parsing.md#read-debug-directories-and-codeview-records) |
| Read attribute certificates | `File.Certificates`, `File.CertificatePayload` | [Certificates](docs/parsing.md#read-attribute-certificates) |
| Parse Authenticode signatures | `File.AuthenticodeSignatures`, `ParseAuthenticodeSignatures` | [API reference](https://pkg.go.dev/github.com/cawalch/go-pe#File.AuthenticodeSignatures) |
| Compute Authenticode digests | `File.AuthenticodeDigest`, `File.AuthenticodeDigests`, `File.AuthenticodeDigestRanges` | [Image digests](docs/parsing.md#calculate-authenticode-image-digests) |
| Verify Authenticode signatures and timestamps | `File.VerifyAuthenticode`, `File.VerifyAuthenticodeSignatures` | [Offline verification](docs/parsing.md#verify-authenticode-integrity-and-timestamps-offline) |
| Convert addresses | `File.RVAToOffset`, `File.OffsetToRVA` | [Address conversion](docs/parsing.md#convert-addresses) |

## Integrate with an application

Your application controls file reads, input size limits, cancellation, and cache
lifetime. Parsing is synchronous. `Open` reads the entire file without a size
limit or cancellation support; use `New` if you need to control those reads.

Keep scanner adapters in the consuming project. go-pe is independent of go-yara
and other scanners. YARA fields, undefined values, scan-state reset, and libyara
compatibility belong in the adapter.

## Contribute

See [Contributing](CONTRIBUTING.md) for validation commands, feature scope, and
documentation style. Tests use generated fixtures and Go toolchain PE fixtures.
They require no malware samples, sibling repositories, or network access after
you install Go.

## References

- [API reference](https://pkg.go.dev/github.com/cawalch/go-pe)
- [Parsing guide](docs/parsing.md)
- [Export parser comparisons](benchmarks/exports/README.md)
- [Workload comparisons and parser audit](docs/workloads-and-audit.md)
- [Related libraries](docs/parsing.md#related-libraries)
- [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MIT license](LICENSE)
