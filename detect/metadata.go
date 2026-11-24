package detect

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cawalch/go-pe"
)

// RichAnomalies reports structural or consistency anomalies in a PE image's
// Rich header.
type RichAnomalies struct {
	InvalidChecksum       bool
	NonZeroPadding        bool
	LinkerVersionMismatch bool
	SpoofedOnNonMSVC      bool
}

// Any reports whether any Rich header anomaly was detected.
func (r RichAnomalies) Any() bool {
	return r.InvalidChecksum || r.NonZeroPadding || r.LinkerVersionMismatch || r.SpoofedOnNonMSVC
}

// Rich inspects [pe.File.RichHeader] for checksum failures, non-zero DanS
// padding, linker-version inconsistencies, and Rich headers embedded in
// non-MSVC (e.g., Go, Rust, Nim, or MinGW DWARF) binaries.
func Rich(f *pe.File, data []byte) (RichAnomalies, error) {
	if f == nil {
		return RichAnomalies{}, fmt.Errorf("%w: nil File", pe.ErrInvalidHeader)
	}
	rh, err := f.RichHeader(data)
	if err != nil {
		return RichAnomalies{}, err
	}
	if rh == nil {
		return RichAnomalies{}, nil
	}

	var out RichAnomalies
	if !rh.ChecksumValid {
		out.InvalidChecksum = true
	}
	if rh.PaddingNonZero {
		out.NonZeroPadding = true
	}
	if f.OptionalHeader.MajorLinkerVersion == 0 && f.OptionalHeader.MinorLinkerVersion == 0 && len(rh.Entries) > 0 {
		out.LinkerVersionMismatch = true
	}

	for i := range f.Sections {
		if strings.HasPrefix(f.Sections[i].Name, ".zdebug_") || strings.HasPrefix(f.Sections[i].Name, ".debug_") {
			out.SpoofedOnNonMSVC = true
			break
		}
	}
	if !out.SpoofedOnNonMSVC {
		if rt, err := Runtime(f, data); err == nil && rt.Language != RuntimeUnknown {
			out.SpoofedOnNonMSVC = true
		}
	}

	return out, nil
}

// PDBAnomalies reports suspicious or privacy-leaking patterns in CodeView PDB
// debug records ([pe.File.Debug]).
type PDBAnomalies struct {
	AllZeroGUID        bool
	ZeroAge            bool
	NonUTF8Path        bool
	ControlCharsInPath bool
	DeveloperPathLeak  bool
	LeakedPaths        []string
}

// Any reports whether any CodeView PDB anomaly was detected.
func (p PDBAnomalies) Any() bool {
	return p.AllZeroGUID || p.ZeroAge || p.NonUTF8Path || p.ControlCharsInPath || p.DeveloperPathLeak
}

var devPathMarkers = []string{
	`\users\`,
	`/users/`,
	`/home/`,
	`\desktop\`,
	`\appdata\`,
	`\temp\`,
}

// PDB inspects CodeView records from [pe.File.Debug] for all-zero GUIDs, zero
// age, non-UTF-8 or control-character paths, and developer build-path leaks.
func PDB(f *pe.File, data []byte) (PDBAnomalies, error) {
	if f == nil {
		return PDBAnomalies{}, fmt.Errorf("%w: nil File", pe.ErrInvalidHeader)
	}
	entries, err := f.Debug(data)
	if err != nil {
		return PDBAnomalies{}, err
	}

	var out PDBAnomalies
	var zeroGUID pe.CodeViewGUID

	for i := range entries {
		cv := entries[i].CodeView
		if cv == nil {
			continue
		}
		if cv.Signature == pe.CodeViewSignatureRSDS && cv.GUID == zeroGUID {
			out.AllZeroGUID = true
		}
		if cv.Age == 0 {
			out.ZeroAge = true
		}
		if len(cv.PDBPath) == 0 {
			continue
		}
		if !utf8.Valid(cv.PDBPath) {
			out.NonUTF8Path = true
		}
		for _, b := range cv.PDBPath {
			if b < 0x20 {
				out.ControlCharsInPath = true
				break
			}
		}
		low := strings.ToLower(string(cv.PDBPath))
		for _, marker := range devPathMarkers {
			if strings.Contains(low, marker) {
				out.DeveloperPathLeak = true
				out.LeakedPaths = append(out.LeakedPaths, string(cv.PDBPath))
				break
			}
		}
	}

	return out, nil
}
