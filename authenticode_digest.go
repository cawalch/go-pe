package pe

import (
	"cmp"
	"crypto"
	"crypto/md5"  // #nosec G501 -- Authenticode image digests require legacy MD5 support.
	"crypto/sha1" // #nosec G505 -- Authenticode image digests require legacy SHA-1 support.
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math"
	"slices"
)

// MaxAuthenticodeDigestBytes limits the maximum PE image size accepted by
// [File.AuthenticodeDigest], [File.AuthenticodeDigests], and
// [File.AuthenticodeDigestRanges].
const MaxAuthenticodeDigestBytes = 256 << 20

// ErrUnsupportedDigestAlgorithm indicates that an Authenticode digest caller
// requested a hash algorithm not supported for PE image hashing.
var ErrUnsupportedDigestAlgorithm = errors.New("unsupported authenticode digest algorithm")

// AuthenticodeDigestRange identifies a half-open byte range [Offset, Offset+Length)
// within a PE image that contributes to its Authenticode image digest.
type AuthenticodeDigestRange struct {
	Offset int64
	Length int64
}

type authenticodeSpan struct {
	start uint64
	end   uint64
}

type authenticodeDigestPlan struct {
	fileSize     uint64
	excludeCount int
	excludes     [3]authenticodeSpan
}

// AuthenticodeDigestRanges returns the sorted, non-overlapping byte ranges of
// data that contribute to f's Authenticode PE image digest.
//
// The returned ranges cover the validated image from offset 0 through EOF,
// excluding the 4-byte OptionalHeader.CheckSum field, the 8-byte
// DataDirectory[DataDirectoryCertificate] entry when present, and the
// WIN_CERTIFICATE table bytes when present. Callers should pass the same byte
// slice passed to [New].
func (f *File) AuthenticodeDigestRanges(data []byte) ([]AuthenticodeDigestRange, error) {
	plan, err := buildAuthenticodeDigestPlan(f, data)
	if err != nil {
		return nil, err
	}

	var ranges []AuthenticodeDigestRange
	plan.visitIncluded(func(start, end uint64) {
		ranges = append(ranges, AuthenticodeDigestRange{
			Offset: int64(start),
			Length: int64(end - start),
		})
	})
	return ranges, nil
}

// AuthenticodeDigest calculates the Authenticode PE image digest of data using
// alg. Supported algorithms are crypto.MD5, crypto.SHA1, crypto.SHA256,
// crypto.SHA384, and crypto.SHA512.
//
// Unlike signing tools that pad unaligned unsigned files to 8-byte boundaries,
// AuthenticodeDigest hashes the exact non-excluded bytes present in data and
// returns newly allocated digest bytes without mutating or retaining data.
func (f *File) AuthenticodeDigest(data []byte, alg crypto.Hash) ([]byte, error) {
	h, err := newAuthenticodeHasher(alg)
	if err != nil {
		return nil, err
	}
	plan, err := buildAuthenticodeDigestPlan(f, data)
	if err != nil {
		return nil, err
	}

	plan.visitIncluded(func(start, end uint64) {
		_, _ = h.Write(data[start:end])
	})
	return h.Sum(nil), nil
}

// AuthenticodeDigests calculates Authenticode PE image digests of data across
// all requested algorithms in a single pass. If algs is empty, it returns
// nil, nil without reading data.
func (f *File) AuthenticodeDigests(data []byte, algs ...crypto.Hash) ([][]byte, error) {
	if len(algs) == 0 {
		return nil, nil
	}

	hashers := make([]hash.Hash, len(algs))
	for i, alg := range algs {
		h, err := newAuthenticodeHasher(alg)
		if err != nil {
			return nil, err
		}
		hashers[i] = h
	}

	plan, err := buildAuthenticodeDigestPlan(f, data)
	if err != nil {
		return nil, err
	}

	plan.visitIncluded(func(start, end uint64) {
		chunk := data[start:end]
		for _, h := range hashers {
			_, _ = h.Write(chunk)
		}
	})

	digests := make([][]byte, len(hashers))
	for i, h := range hashers {
		digests[i] = h.Sum(nil)
	}
	return digests, nil
}

func newAuthenticodeHasher(alg crypto.Hash) (hash.Hash, error) {
	switch alg {
	case crypto.MD5:
		return md5.New(), nil // #nosec G401 -- Authenticode image digests require legacy MD5 support.
	case crypto.SHA1:
		return sha1.New(), nil // #nosec G401 -- Authenticode image digests require legacy SHA-1 support.
	case crypto.SHA256:
		return sha256.New(), nil
	case crypto.SHA384:
		return sha512.New384(), nil
	case crypto.SHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedDigestAlgorithm, alg)
	}
}

func buildAuthenticodeDigestPlan(f *File, data []byte) (authenticodeDigestPlan, error) {
	if err := f.validateParsedHeaders(); err != nil {
		return authenticodeDigestPlan{}, err
	}
	if f.fileSize < 0 || int64(len(data)) != f.fileSize {
		return authenticodeDigestPlan{}, fmt.Errorf("%w: input size %d does not match parsed file size %d", ErrOutOfBounds, len(data), f.fileSize)
	}

	fileSize := uint64(len(data))
	if fileSize > MaxAuthenticodeDigestBytes {
		return authenticodeDigestPlan{}, fmt.Errorf("%w: image size %d exceeds %d", ErrAuthenticodeLimit, fileSize, MaxAuthenticodeDigestBytes)
	}

	peOffset := uint64(f.DOSHeader.AddressOfNewEXEHeader)
	optOffset := peOffset + 24
	checksumStart := optOffset + 64
	checksumEnd := checksumStart + 4

	dirTableOffset := uint64(96)
	if f.Is64Bit() {
		dirTableOffset = 112
	}
	hasCertDirEntry := f.OptionalHeader.NumberOfRvaAndSizes > DataDirectoryCertificate
	certDirStart := optOffset + dirTableOffset + uint64(DataDirectoryCertificate)*8
	certDirEnd := certDirStart + 8

	sectionTableEnd := optOffset + uint64(f.FileHeader.SizeOfOptionalHeader) + uint64(len(f.Sections))*40
	sizeOfHeaders := uint64(f.OptionalHeader.SizeOfHeaders)
	if sizeOfHeaders > fileSize {
		return authenticodeDigestPlan{}, fmt.Errorf("%w: SizeOfHeaders %#x exceeds file size %#x", ErrOutOfBounds, sizeOfHeaders, fileSize)
	}
	if sizeOfHeaders < sectionTableEnd {
		return authenticodeDigestPlan{}, fmt.Errorf("%w: SizeOfHeaders %#x is smaller than PE headers ending at %#x", ErrInvalidHeader, sizeOfHeaders, sectionTableEnd)
	}

	dirStart, dirEnd, hasCertTable, err := certificateDirectoryBounds(f, data)
	if err != nil {
		return authenticodeDigestPlan{}, err
	}

	if err := validateDigestSections(f.Sections, sizeOfHeaders, fileSize); err != nil {
		return authenticodeDigestPlan{}, err
	}

	plan := authenticodeDigestPlan{fileSize: fileSize}
	plan.excludes[plan.excludeCount] = authenticodeSpan{start: checksumStart, end: checksumEnd}
	plan.excludeCount++
	if hasCertDirEntry {
		plan.excludes[plan.excludeCount] = authenticodeSpan{start: certDirStart, end: certDirEnd}
		plan.excludeCount++
	}
	if hasCertTable {
		plan.excludes[plan.excludeCount] = authenticodeSpan{start: dirStart, end: dirEnd}
		plan.excludeCount++
	}
	return plan, nil
}

func validateDigestSections(sections []Section, sizeOfHeaders, fileSize uint64) error {
	var spans [MaxSections]authenticodeSpan
	count := 0
	for _, sec := range sections {
		if sec.SizeOfRawData == 0 {
			continue
		}
		secStart := uint64(sec.PointerToRawData)
		secEnd := secStart + uint64(sec.SizeOfRawData)
		if secEnd < secStart || secEnd > uint64(math.MaxUint32)+1 {
			return fmt.Errorf("%w: section %q raw extent overflows 32-bit file space", ErrIntegerOverflow, sec.Name)
		}
		if secEnd > fileSize {
			return fmt.Errorf("%w: section %q [%#x, %#x) exceeds file size %#x", ErrOutOfBounds, sec.Name, secStart, secEnd, fileSize)
		}
		if secStart < sizeOfHeaders {
			return fmt.Errorf("%w: section %q [%#x, %#x) overlaps PE headers ending at %#x", ErrInvalidHeader, sec.Name, secStart, secEnd, sizeOfHeaders)
		}
		spans[count] = authenticodeSpan{start: secStart, end: secEnd}
		count++
	}

	active := spans[:count]
	slices.SortFunc(active, func(a, b authenticodeSpan) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}
		return cmp.Compare(a.end, b.end)
	})
	for i := 1; i < len(active); i++ {
		if active[i].start < active[i-1].end {
			return fmt.Errorf("%w: section range [%#x, %#x) overlaps prior section [%#x, %#x)", ErrInvalidHeader, active[i].start, active[i].end, active[i-1].start, active[i-1].end)
		}
	}
	return nil
}

func (p authenticodeDigestPlan) visitIncluded(fn func(start, end uint64)) {
	cursor := uint64(0)
	for i := 0; i < p.excludeCount; i++ {
		ex := p.excludes[i]
		if ex.start > cursor {
			fn(cursor, ex.start)
		}
		if ex.end > cursor {
			cursor = ex.end
		}
	}
	if cursor < p.fileSize {
		fn(cursor, p.fileSize)
	}
}
