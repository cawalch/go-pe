// Package pe reads Portable Executable (PE) image headers, sections, imports,
// exports, and attribute certificate records.
// It supports the PE32 and PE32+ formats and uses only the Go standard library.
//
// Use [New] to parse a byte slice or [Open] to read a file. Both functions return
// a metadata snapshot that retains no reference to the input. They require
// complete headers but don't validate section bodies or data directory contents.
// To read standard imports, pass the original bytes to [File.Imports]. It returns
// owned records and bounds parsing work with descriptor, symbol, and name limits.
// Use [File.Exports] to read export metadata, address slots, aliases, and forwarders
// under separate table and string limits. Use [File.Certificates] and
// [File.CertificatePayload] to enumerate bounded WIN_CERTIFICATE records and copy
// raw certificate payloads. Use [File.AuthenticodeSignatures] and
// [ParseAuthenticodeSignatures] to decode bounded PKCS#7 SignedData signer,
// certificate, attribute, nested-signature, and timestamp metadata without
// verifying signatures or trust chains. Use [File.AuthenticodeDigest],
// [File.AuthenticodeDigests], and [File.AuthenticodeDigestRanges] to inspect
// excluded ranges and compute checked Authenticode PE image digests. Use
// [File.VerifyAuthenticode] and [File.VerifyAuthenticodeSignatures] to check
// image-digest agreement, CMS signed attributes and signatures, PKCS#9/RFC 3161
// timestamps, and optional explicit trust roots offline without ambient OS
// trust or network lookups. None of these methods cache results.
// Use [File.Resources] and [File.ResourcePayload] to read resource directory
// headers, leaf paths, and explicit resource payloads under depth, graph, and
// size bounds. Use [ParseVersionInfo] to decode VS_VERSION_INFO fixed file
// information, ordered StringFileInfo tables, VarFileInfo translations, and
// unrecognized child blocks from a resource payload without flattening keys.
// Use [File.RichHeader] to locate and decode Rich headers between the DOS
// header and PE signature with explicit XOR keys, raw/clear byte spans,
// (@comp.id, count) entries, and checksum status.
//
// [File.RVAToOffset] and [File.OffsetToRVA] convert between relative virtual
// addresses and offsets within the original input. These methods don't emulate
// the Windows loader.
package pe
