# go-pe

go-pe is a Go library for reading Portable Executable (PE) image headers and
sections. It supports PE32 and PE32+ images, uses only the Go standard library,
and requires Go 1.26 or later.

The library is in early development. No stable release is available.

## Supported features

You can use go-pe to read:

- DOS headers and Common Object File Format (COFF) file headers within PE images.
- PE32 and PE32+ optional headers and the first 16 data directory descriptors.
- Section headers and names, including names stored in a COFF string table.

The library also provides section lookup, dynamic-link library (DLL) and format
checks, and conversion between relative virtual addresses (RVAs) and file
offsets. The `SafeReader` utility provides bounds-checked integer and string reads.

go-pe doesn't parse data directory contents, imports, exports, Authenticode
signatures, Rich headers, resources, or version information. It doesn't calculate
imphash values or support standalone COFF objects, ROM images, memory-mapped
input, or `io.ReaderAt`.

## Install the library

To install the development version, run the following command in your Go module:

```sh
go get github.com/cawalch/go-pe@main
```

For reproducible builds, commit the resulting `go.mod` and `go.sum` files. Go
records a version that identifies the selected commit.

## Parse a file

The following program reads a PE file, prints its machine type and section count,
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

	file, err := pe.Open(os.Args[1])
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
}
```

To run the program, replace `sample.exe` with the path to your PE file:

```sh
go run . sample.exe
```

`Open` reads the entire file into memory. If you need to control input size or
I/O, acquire the bytes in your application and pass them to `New(data)`.

## Use the parsed metadata

`New` copies header values and section names without retaining the input buffer.
You can reuse or release the buffer after `New` returns. The returned `File`
doesn't require a `Close` call.

If you don't modify its exported fields, you can read a `File` from multiple
goroutines. `SectionByName` returns a pointer into `File.Sections`, so changes through
that pointer modify the `File`.

Unlike `File`, `SafeReader` retains a reference to its input buffer. Don't modify
that buffer concurrently with reads.

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
documentation style. The tests use generated fixtures and require no malware
samples, sibling repositories, or network access after you install Go.

## References

- [API reference](https://pkg.go.dev/github.com/cawalch/go-pe)
- [Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MIT license](LICENSE)
