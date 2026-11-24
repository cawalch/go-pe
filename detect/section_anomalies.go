// Package detect implements higher-level PE detection heuristics on top of
// github.com/cawalch/go-pe without adding scanner policy to the core parser.
package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/cawalch/go-pe"
)

// DefaultHighEntropyThreshold is the default Shannon entropy threshold (bits/byte)
// used by [Sections] to flag packed or encrypted sections.
const DefaultHighEntropyThreshold = 7.2

// SectionEntropyInfo identifies a section whose raw byte entropy met or
// exceeded the configured threshold.
type SectionEntropyInfo struct {
	Index   int
	Name    string
	Entropy float64
}

// SectionOptions configures [Sections].
type SectionOptions struct {
	// HighEntropyThreshold sets the Shannon entropy threshold in bits/byte.
	// When <= 0, [DefaultHighEntropyThreshold] (7.2) is used.
	HighEntropyThreshold float64

	// IncludeDebugSections includes compressed/debug sections (such as
	// ".zdebug_*" or ".debug_*") in HighEntropySections checks when true.
	// By default they are excluded to avoid false positives on unstripped Go
	// and MinGW binaries.
	IncludeDebugSections bool

	// VerificationTime pins the reference time for future-timestamp checks.
	// When zero, the future-timestamp check is skipped (0xFFFFFFFF is still
	// flagged unless DebugTypeRepro is present).
	VerificationTime time.Time
}

// SectionAnomalies reports section-level, entry-point, overlay, and timestamp
// heuristics on a PE image.
type SectionAnomalies struct {
	RWXSections             []int
	HighEntropySections     []SectionEntropyInfo
	VirtualSizeAnomalies    []int
	ExecutableZeroRaw       []int
	EntryPointOutsideCode   bool
	EntryPointInWritable    bool
	EntryPointInLastSection bool
	OverlayHighEntropy      bool
	ZeroTimeDateStamp       bool
	SuspiciousTimeDateStamp bool
}

// Any reports whether any behavioral or structural anomaly was flagged.
// ZeroTimeDateStamp is excluded because reproducible builds (such as Go and
// .NET/Mono) routinely emit TimeDateStamp == 0.
func (a SectionAnomalies) Any() bool {
	return len(a.RWXSections) > 0 ||
		len(a.HighEntropySections) > 0 ||
		len(a.VirtualSizeAnomalies) > 0 ||
		len(a.ExecutableZeroRaw) > 0 ||
		a.EntryPointOutsideCode ||
		a.EntryPointInWritable ||
		a.EntryPointInLastSection ||
		a.OverlayHighEntropy ||
		a.SuspiciousTimeDateStamp
}

// Sections inspects f's section headers, entry point, raw section entropies,
// overlay entropy, and COFF timestamp against data.
//
// Built-in false-positive guards:
//   - Compressed DWARF debug sections (".zdebug_*", ".debug_*") are excluded
//     from HighEntropySections unless opts.IncludeDebugSections is true.
//   - VirtualSize >> SizeOfRawData is suppressed on non-executable ".data" /
//     ".bss" sections so large BSS allocations (e.g. Go binaries) do not trigger
//     false positives.
//   - TimeDateStamp == 0 is recorded in ZeroTimeDateStamp but does not set
//     SuspiciousTimeDateStamp or Any().
func Sections(f *pe.File, data []byte, opts *SectionOptions) (SectionAnomalies, error) {
	if f == nil {
		return SectionAnomalies{}, fmt.Errorf("%w: nil File", pe.ErrInvalidHeader)
	}
	threshold := DefaultHighEntropyThreshold
	includeDebug := false
	var verifyTime time.Time
	if opts != nil {
		if opts.HighEntropyThreshold > 0 {
			threshold = opts.HighEntropyThreshold
		}
		includeDebug = opts.IncludeDebugSections
		verifyTime = opts.VerificationTime
	}

	var out SectionAnomalies
	ep := f.OptionalHeader.AddressOfEntryPoint
	epFound := false

	for i := range f.Sections {
		sec := &f.Sections[i]
		isExec := sec.Characteristics&pe.SectionMemExecute != 0
		isWrite := sec.Characteristics&pe.SectionMemWrite != 0
		isRead := sec.Characteristics&pe.SectionMemRead != 0
		isCode := sec.Characteristics&pe.SectionCntCode != 0

		if isRead && isWrite && isExec {
			out.RWXSections = append(out.RWXSections, i)
		}

		if isExec && sec.SizeOfRawData == 0 && sec.VirtualSize > 0 {
			out.ExecutableZeroRaw = append(out.ExecutableZeroRaw, i)
		}

		if isVirtualSizeAnomalous(sec, isExec) {
			out.VirtualSizeAnomalies = append(out.VirtualSizeAnomalies, i)
		}

		if sec.SizeOfRawData > 0 && (includeDebug || !isDebugSectionName(sec.Name)) {
			ent, err := f.SectionEntropy(data, i)
			if err != nil {
				return SectionAnomalies{}, err
			}
			if ent >= threshold {
				out.HighEntropySections = append(out.HighEntropySections, SectionEntropyInfo{
					Index:   i,
					Name:    sec.Name,
					Entropy: ent,
				})
			}
		}

		if ep != 0 && !epFound && rvaInSection(ep, sec) {
			epFound = true
			if !isExec && !isCode {
				out.EntryPointOutsideCode = true
			}
			if isWrite {
				out.EntryPointInWritable = true
			}
			if len(f.Sections) > 1 && i == len(f.Sections)-1 {
				out.EntryPointInLastSection = true
			}
		}
	}

	if ep != 0 && !epFound {
		out.EntryPointOutsideCode = true
	}

	if ovEnt, hasOv, err := f.OverlayEntropy(data); err != nil {
		return SectionAnomalies{}, err
	} else if hasOv && ovEnt >= threshold {
		out.OverlayHighEntropy = true
	}

	ts := f.FileHeader.TimeDateStamp
	if ts == 0 {
		out.ZeroTimeDateStamp = true
	} else if ts == 0xFFFFFFFF || (!verifyTime.IsZero() && int64(ts) > verifyTime.Add(24*time.Hour).Unix()) {
		if !hasReproDebugEntry(f, data) {
			out.SuspiciousTimeDateStamp = true
		}
	}

	return out, nil
}

func isDebugSectionName(name string) bool {
	return strings.HasPrefix(name, ".zdebug_") || strings.HasPrefix(name, ".debug_")
}

func isVirtualSizeAnomalous(sec *pe.Section, isExec bool) bool {
	if sec.VirtualSize <= sec.SizeOfRawData {
		return false
	}
	diff := sec.VirtualSize - sec.SizeOfRawData
	if diff < 4096 {
		return false
	}
	if sec.SizeOfRawData > 0 && uint64(sec.VirtualSize) < uint64(sec.SizeOfRawData)*4 {
		return false
	}
	if !isExec && (sec.Name == ".data" || sec.Name == ".bss") {
		return false
	}
	return true
}

func rvaInSection(rva uint32, sec *pe.Section) bool {
	vSize := max(sec.VirtualSize, sec.SizeOfRawData)
	if vSize == 0 || rva < sec.VirtualAddress {
		return false
	}
	return uint64(rva)-uint64(sec.VirtualAddress) < uint64(vSize)
}

func hasReproDebugEntry(f *pe.File, data []byte) bool {
	entries, err := f.Debug(data)
	if err != nil {
		return false
	}
	for i := range entries {
		if entries[i].Type == pe.DebugTypeRepro {
			return true
		}
	}
	return false
}
