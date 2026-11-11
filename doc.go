// Package pe reads Portable Executable (PE) image headers, sections, and imports.
// It supports the PE32 and PE32+ formats and uses only the Go standard library.
//
// Use [New] to parse a byte slice or [Open] to read a file. Both functions return
// a metadata snapshot that retains no reference to the input. They require
// complete headers but don't validate section bodies or data directory contents.
// To read standard imports, pass the original bytes to [File.Imports]. It returns
// owned records and bounds parsing work with descriptor, symbol, and name limits.
//
// [File.RVAToOffset] and [File.OffsetToRVA] convert between relative virtual
// addresses and offsets within the original input. These methods don't emulate
// the Windows loader.
package pe
