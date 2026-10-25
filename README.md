# go-pe

A high-performance, malware-hardened, zero-panic pure-Go Portable Executable (PE) parser.

`go-pe` is designed specifically for high-throughput security scanners, detection engineering, DFIR triage, and EDR agents. It extracts structural metadata, headers, sections, imports, exports, resources, and digital certificates from Windows PE binaries without panics or memory leaks on malformed/adversarial inputs.

## Key Design Principles

- **Zero-Panic Guarantee**: All parsing is executed through an invariant bounds-checked safe reader. Corrupt offsets, integer overflows, and malformed tables gracefully return errors or partial structures without crashing the host process.
- **Low & Zero-Allocation Fast Paths**: Core headers and section headers can be parsed in sub-microsecond time with zero heap allocations.
- **Lazy On-Demand Evaluation**: Expensive structures (Imports, Exports, Authenticode Signatures, Resources) are parsed on-demand rather than eagerly instantiated.
- **Authenticode & ImpHash Parity**: Provides complete digital signature extraction (PKCS#7 / CMS) and canonical `imphash` normalization strictly matching `libyara` and `pefile`.
- **Pure Go**: Zero CGO dependencies. Cross-compiles cleanly to all Go architectures and platforms.

## Architecture

- **`SafeReader`**: Centralized, bounds-checked binary reader providing guaranteed safe primitive extraction with overflow checks.
- **Headers & Sections**: DOS header, PE COFF header, Optional header (PE32 / PE32+), Section table, and RVA-to-offset mapping.
- **Imports & Exports**: Import directory tables, INT/IAT thunks, delayed imports, ordinal mapping, forwarder detection, and canonical `ImpHash()`.
- **Digital Signatures**: Security directory parsing, PKCS#7 / CMS container decoding, certificate extraction (`issuer`, `subject`, `serial`, `thumbprint`, `valid_on`), and Authenticode hash verification.
- **Extended Artifacts**: Rich header (XOR decrypt, checksum validation), Resource directory tree, and `VS_VERSIONINFO` metadata.

## License

MIT License. See [LICENSE](LICENSE) for details.
