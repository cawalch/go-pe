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
- Standard import descriptors, DLL names, and imports by name and hint or ordinal.
- Export directories, address slots, ordinal values, name aliases, and raw forwarders.

The library also provides section lookup, dynamic-link library (DLL) and format
checks, and conversion between relative virtual addresses (RVAs) and file
offsets. The `SafeReader` utility provides bounds-checked integer and string reads.

go-pe doesn't parse delayed imports, Authenticode signatures, Rich
headers, resources, or version information. It doesn't resolve bound import
addresses or calculate imphash values. It doesn't support standalone COFF
objects, ROM images, loaded-memory images, memory-mapped input, or `io.ReaderAt`.

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
You can reuse or release the buffer after `New` returns unless you plan to pass
it to `Imports` or `Exports`. The returned `File` doesn't require a `Close` call.

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

### Read standard exports

Call `file.Exports(data)` with the original bytes passed to `New`. The method
returns an owned `ExportDirectory` or `nil, nil` for a missing directory. It
doesn't retain the input, modify `File`, or cache results. Don't modify the input
or `File` during a call.

`Symbols` follows export address table order and includes unused slots whose
`RVA` is zero. Each symbol has its full ordinal, including the directory's
ordinal base. `Names` preserves all aliases, duplicates, and empty names in name
pointer table order within that symbol. A nil `Names` slice means ordinal-only.
Names preserve their bytes without encoding checks or case folding.

`Forwarded` identifies an RVA within the export directory's declared range.
`Forwarder` contains the raw NUL-terminated string, which can be empty. The
parser doesn't validate its syntax or resolve other DLLs. Ordinary target RVAs
are returned without dereferencing them; they can refer to virtual zero-fill or
unmapped data. A missing DLL-name RVA yields an empty `DLL` string.

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

See [Export parser comparisons](benchmarks/exports/README.md) for the existing
implementations assessed, the comparison scope, and benchmark commands.

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
