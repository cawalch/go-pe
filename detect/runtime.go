package detect

import (
	"bytes"
	"fmt"

	"github.com/cawalch/go-pe"
)

// MaxRuntimeScanBytes limits the maximum bytes scanned per section by [Runtime].
const MaxRuntimeScanBytes = 32 << 20

// RuntimeLanguage identifies the detected compiled language runtime.
type RuntimeLanguage string

const (
	RuntimeUnknown RuntimeLanguage = ""
	RuntimeGo      RuntimeLanguage = "go"
	RuntimeRust    RuntimeLanguage = "rust"
	RuntimeNim     RuntimeLanguage = "nim"
)

// GoRuntimeInfo holds Go-specific PE runtime metadata and obfuscation signals.
type GoRuntimeInfo struct {
	HasBuildInfo   bool
	Version        string
	HasGoPclntab   bool
	PossibleGarble bool
}

// RuntimeMetadata summarizes detected Go, Rust, or Nim runtime markers.
type RuntimeMetadata struct {
	Language    RuntimeLanguage
	Go          *GoRuntimeInfo
	RustMarkers []string
	NimMarkers  []string
}

var goBuildInfoMagic = []byte("\xff Go buildinf:")

// Runtime scans relevant PE sections (.rdata, .data, .text, .rustc, .gopclntab)
// for Go, Rust, and Nim runtime markers without external dependencies.
func Runtime(f *pe.File, data []byte) (RuntimeMetadata, error) {
	if f == nil {
		return RuntimeMetadata{}, fmt.Errorf("%w: nil File", pe.ErrInvalidHeader)
	}
	if f.FileSize() < 0 || int64(len(data)) != f.FileSize() {
		return RuntimeMetadata{}, fmt.Errorf("%w: input size %d does not match parsed file size %d", pe.ErrOutOfBounds, len(data), f.FileSize())
	}

	var out RuntimeMetadata
	var goInfo GoRuntimeInfo
	var hasGoSymbolHint bool

	for i := range f.Sections {
		sec := &f.Sections[i]
		if sec.SizeOfRawData == 0 {
			continue
		}
		start := uint64(sec.PointerToRawData)
		end := start + uint64(sec.SizeOfRawData)
		if end > uint64(len(data)) {
			continue
		}
		if sec.SizeOfRawData > MaxRuntimeScanBytes {
			end = start + MaxRuntimeScanBytes
		}
		body := data[start:end]

		if sec.Name == ".rustc" {
			out.RustMarkers = appendUnique(out.RustMarkers, ".rustc")
		}
		if sec.Name == ".gopclntab" {
			goInfo.HasGoPclntab = true
		}

		if idx := bytes.Index(body, goBuildInfoMagic); idx >= 0 {
			goInfo.HasBuildInfo = true
			if ver := extractGoVersion(body[idx:]); ver != "" {
				goInfo.Version = ver
			}
		}
		if bytes.Contains(body, []byte("runtime.main")) || bytes.Contains(body, []byte("runtime.gopanic")) {
			hasGoSymbolHint = true
		}
		if bytes.Contains(body, []byte("Go pclntab")) || hasGoPclntabMagic(body) {
			goInfo.HasGoPclntab = true
		}

		if bytes.Contains(body, []byte("panicked at")) {
			out.RustMarkers = appendUnique(out.RustMarkers, "panicked at")
		}
		if bytes.Contains(body, []byte(`library\core\src\`)) || bytes.Contains(body, []byte("library/core/src/")) {
			out.RustMarkers = appendUnique(out.RustMarkers, "library/core/src")
		}
		if bytes.Contains(body, []byte(`.cargo\registry`)) || bytes.Contains(body, []byte(".cargo/registry")) {
			out.RustMarkers = appendUnique(out.RustMarkers, ".cargo/registry")
		}

		if bytes.Contains(body, []byte("nimMain")) {
			out.NimMarkers = appendUnique(out.NimMarkers, "nimMain")
		}
		if bytes.Contains(body, []byte("stdlib_system.nim")) {
			out.NimMarkers = appendUnique(out.NimMarkers, "stdlib_system.nim")
		}
		if bytes.Contains(body, []byte(".nim.c")) {
			out.NimMarkers = appendUnique(out.NimMarkers, ".nim.c")
		}
	}

	if goInfo.HasBuildInfo || goInfo.HasGoPclntab || hasGoSymbolHint {
		if (goInfo.HasGoPclntab || hasGoSymbolHint) && !goInfo.HasBuildInfo {
			goInfo.PossibleGarble = true
		}
		out.Go = &goInfo
		out.Language = RuntimeGo
		return out, nil
	}
	if len(out.RustMarkers) > 0 {
		out.Language = RuntimeRust
		return out, nil
	}
	if len(out.NimMarkers) > 0 {
		out.Language = RuntimeNim
		return out, nil
	}
	return out, nil
}

func extractGoVersion(buildInfo []byte) string {
	if len(buildInfo) < 34 {
		return ""
	}
	if buildInfo[15]&2 != 0 {
		vLen := int(buildInfo[32])
		if vLen > 0 && vLen < 64 && 33+vLen <= len(buildInfo) {
			return string(buildInfo[33 : 33+vLen])
		}
	}
	return ""
}

func hasGoPclntabMagic(b []byte) bool {
	return bytes.Contains(b, []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00}) ||
		bytes.Contains(b, []byte{0xf0, 0xff, 0xff, 0xff, 0x00, 0x00}) ||
		bytes.Contains(b, []byte{0xfa, 0xff, 0xff, 0xff, 0x00, 0x00}) ||
		bytes.Contains(b, []byte{0xfb, 0xff, 0xff, 0xff, 0x00, 0x00})
}

func appendUnique(dst []string, val string) []string {
	for _, existing := range dst {
		if existing == val {
			return dst
		}
	}
	return append(dst, val)
}
