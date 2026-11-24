// Package pe reads Portable Executable (PE) image headers, sections, imports,
// exports, and attribute certificate records.
// It supports the PE32 and PE32+ formats and uses only the Go standard library.
//
// Use [New] to parse a byte slice, [Open] to read a file, [NewWithLength]
// to parse a leading stream prefix with a known total stream length, or
// [NewFromReaderAt] (with [File.ImportsFromReaderAt], [File.ExportsFromReaderAt],
// and [File.CertificatesFromReaderAt]) to read bounded headers and directories
// from an [io.ReaderAt] without loading large files into memory. These
// functions return a metadata snapshot that retains no reference to the input.
// They require complete headers but don't validate section bodies or data
// directory contents; inspect [File.FileSize], [File.DeclaredExtent], and
// [File.InputTruncated] to check whether the input covers all declared extents,
// [File.OverlayOffset] and [File.Overlay] to inspect trailing bytes beyond the
// declared extent, [File.LayoutAnomalies] and [File.HasOverlappingSections] to
// detect header or section overlaps, and [File.ComputeCheckSum] and
// [File.VerifyCheckSum] to compute or verify the 16-bit PE header checksum.
// To read standard imports, pass the original bytes to [File.Imports]. It returns
// owned records (including derived IAT slot RVAs when valid) and bounds parsing
// work with descriptor, symbol, and name limits. Use [File.DelayImports] to
// read delayed import descriptors, DLLs, symbols, and IAT slot RVAs with the
// same bounded decoding semantics.
// Call [File.Imphash], [Imphash], [File.DelayAwareImphash], or
// [DelayAwareImphash] to compute the standard or delay-aware MD5 import hash,
// which returns [ErrNoImports] or false rather than md5("") when no symbols exist.
// Use [File.LoadConfig] to read load configuration metadata (SafeSEH,
// SecurityCookie, GuardCF, CHPE) and [File.BaseRelocs] to read base relocation
// blocks. Package detect provides higher-level heuristic anomaly checks outside
// the core parser.
// Use [File.Exports] to read export metadata, address slots, aliases, and forwarders
// under separate table and string limits. Use [File.Certificates] and
// [File.CertificatePayload] to enumerate bounded WIN_CERTIFICATE records and copy
// raw certificate payloads. Use [File.AuthenticodeSignatures] and
// [ParseAuthenticodeSignatures] to decode bounded PKCS#7 SignedData signer,
// certificate, attribute, nested-signature, and timestamp metadata without
// verifying signatures or trust chains. Use [File.AuthenticodeDigest],
// [File.AuthenticodeDigests], and [File.AuthenticodeDigestRanges] to inspect
// excluded ranges and compute checked Authenticode PE image digests. Use
// [File.VerifyAuthenticode] and [File.VerifyAuthenticodeSignatures] check
// image-digest agreement, trailing certificate padding ([AuthenticodeVerifyOptions.StrictPadding]),
// CMS signed attributes and signatures, PKCS#9/RFC 3161 timestamps, embedded or
// caller-supplied CRLs ([AuthenticodeVerifyOptions.CRLs]), and optional explicit
// trust roots offline without ambient OS trust or network lookups. None of these
// methods cache results.
// Use [File.Resources] and [File.ResourcePayload] to read resource directory
// headers, leaf paths, and explicit resource payloads under depth, graph, and
// size bounds. Use [ParseVersionInfo] to decode VS_VERSION_INFO fixed file
// information, ordered StringFileInfo tables, VarFileInfo translations, and
// unrecognized child blocks from a resource payload without flattening keys.
// Use [File.RichHeader] to locate and decode Rich headers between the DOS
// header and PE signature with explicit XOR keys, raw/clear byte spans,
// (@comp.id, count) entries, and checksum status.
// Use [File.Debug] to read bounded IMAGE_DEBUG_DIRECTORY entries in file order
// and decode CodeView RSDS/NB10 records (GUID/signature, age, and raw PDB path
// bytes) while retaining non-CodeView entries as metadata.
//
// [File.RVAToOffset] and [File.OffsetToRVA] convert between relative virtual
// addresses and offsets within the original input. These methods don't emulate
// the Windows loader.
package pe
