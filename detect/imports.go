package detect

import (
	"fmt"
	"math"
	"strings"

	"github.com/cawalch/go-pe"
)

// ImportAnomalies reports suspicious import, delay-load, API-hashing, and
// export/reflective-DLL indicators.
type ImportAnomalies struct {
	DelayLoadSensitiveAPIs    []string
	MinimalIATWithHighEntropy bool
	SuspiciousAPIClusters     []string
	ReflectiveDLLExports      []string
	UnusualOrdinalBase        bool
	ExportsWithoutDLLFlag     bool
}

// Any reports whether any import or export anomaly was flagged.
func (a ImportAnomalies) Any() bool {
	return len(a.DelayLoadSensitiveAPIs) > 0 ||
		a.MinimalIATWithHighEntropy ||
		len(a.SuspiciousAPIClusters) > 0 ||
		len(a.ReflectiveDLLExports) > 0 ||
		a.UnusualOrdinalBase ||
		a.ExportsWithoutDLLFlag
}

var sensitiveDelayAPIs = map[string]struct{}{
	"virtualallocex":             {},
	"writeprocessmemory":         {},
	"createremotethread":         {},
	"ntunmapviewofsection":       {},
	"ntwritevirtualmemory":       {},
	"queueuserapc":               {},
	"setthreadcontext":           {},
	"minidumpwritedump":          {},
	"isdebuggerpresent":          {},
	"checkremotedebuggerpresent": {},
	"ntqueryinformationprocess":  {},
	"openprocess":                {},
	"virtualprotect":             {},
	"loadlibrarya":               {},
	"loadlibraryw":               {},
	"getprocaddress":             {},
}

// ImportsAndExports inspects standard imports, delayed imports, and exports for
// delay-load API hiding, minimal-IAT API hashing, suspicious API clusters, and
// reflective-DLL / export anomalies.
func ImportsAndExports(f *pe.File, data []byte) (ImportAnomalies, error) {
	if f == nil {
		return ImportAnomalies{}, fmt.Errorf("%w: nil File", pe.ErrInvalidHeader)
	}
	imports, err := f.Imports(data)
	if err != nil {
		return ImportAnomalies{}, err
	}
	delays, err := f.DelayImports(data)
	if err != nil {
		return ImportAnomalies{}, err
	}
	exports, err := f.Exports(data)
	if err != nil {
		return ImportAnomalies{}, err
	}

	var out ImportAnomalies
	stdSet := make(map[string]struct{})
	allSet := make(map[string]struct{})
	stdCount := 0

	for i := range imports {
		for j := range imports[i].Symbols {
			stdCount++
			sym := &imports[i].Symbols[j]
			if !sym.ByOrdinal && sym.Name != "" {
				low := strings.ToLower(sym.Name)
				stdSet[low] = struct{}{}
				allSet[low] = struct{}{}
			}
		}
	}

	delaySeen := make(map[string]struct{})
	for i := range delays {
		for j := range delays[i].Symbols {
			sym := &delays[i].Symbols[j]
			if !sym.ByOrdinal && sym.Name != "" {
				low := strings.ToLower(sym.Name)
				allSet[low] = struct{}{}
				if _, ok := sensitiveDelayAPIs[low]; ok {
					if _, inStd := stdSet[low]; !inStd {
						if _, dup := delaySeen[low]; !dup {
							delaySeen[low] = struct{}{}
							out.DelayLoadSensitiveAPIs = append(out.DelayLoadSensitiveAPIs, sym.Name)
						}
					}
				}
			}
		}
	}

	hasCLR := f.OptionalHeader.NumberOfRvaAndSizes > pe.DataDirectoryCLRRuntime &&
		f.OptionalHeader.DataDirectories[pe.DataDirectoryCLRRuntime].VirtualAddress != 0
	if !hasCLR && stdCount <= 3 && len(delays) == 0 && f.OptionalHeader.AddressOfEntryPoint != 0 {
		if hasHighEntropyNonDebugSection(f, data, 7.0) {
			out.MinimalIATWithHighEntropy = true
		}
	}

	if hasAny(allSet, "virtualallocex", "ntwritevirtualmemory", "writeprocessmemory") &&
		hasAny(allSet, "createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "ntunmapviewofsection") {
		out.SuspiciousAPIClusters = append(out.SuspiciousAPIClusters, "process_injection")
	}
	if hasAny(allSet, "minidumpwritedump") ||
		(hasAny(allSet, "openprocess") && hasAny(allSet, "adjusttokenprivileges", "lookupprivilegevaluea", "lookupprivilegevaluew")) {
		out.SuspiciousAPIClusters = append(out.SuspiciousAPIClusters, "credential_access")
	}
	if hasAny(allSet, "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess") &&
		hasAny(allSet, "virtualprotect", "virtualalloc", "gettickcount", "queryperformancecounter") {
		out.SuspiciousAPIClusters = append(out.SuspiciousAPIClusters, "anti_debug")
	}

	if exports != nil {
		if len(exports.Symbols) > 0 && !f.IsDLL() {
			out.ExportsWithoutDLLFlag = true
		}
		if exports.OrdinalBase != 0 && exports.OrdinalBase != 1 {
			out.UnusualOrdinalBase = true
		}
		for i := range exports.Symbols {
			for _, name := range exports.Symbols[i].Names {
				low := strings.ToLower(name)
				if strings.Contains(low, "reflectiveloader") || low == "reflective_loader" {
					out.ReflectiveDLLExports = append(out.ReflectiveDLLExports, name)
				}
			}
		}
	}

	return out, nil
}

func hasAny(set map[string]struct{}, keys ...string) bool {
	for _, k := range keys {
		if _, ok := set[k]; ok {
			return true
		}
	}
	return false
}

func hasHighEntropyNonDebugSection(f *pe.File, data []byte, threshold float64) bool {
	if int64(len(data)) != f.FileSize() {
		return false
	}
	for i := range f.Sections {
		sec := &f.Sections[i]
		if sec.SizeOfRawData == 0 {
			continue
		}
		if strings.HasPrefix(sec.Name, ".zdebug_") || strings.HasPrefix(sec.Name, ".debug_") {
			continue
		}
		start := uint64(sec.PointerToRawData)
		end := start + uint64(sec.SizeOfRawData)
		if end > uint64(len(data)) {
			continue
		}
		if rawShannonEntropy(data[start:end]) >= threshold {
			return true
		}
	}
	return false
}

func rawShannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]uint64
	for _, v := range b {
		counts[v]++
	}
	total := float64(len(b))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		ent -= p * math.Log2(p)
	}
	return ent
}
