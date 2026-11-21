package exports_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	gope "github.com/cawalch/go-pe"
)

// TestLibYaraDifferential compares go-pe against the local libyara CLI (`yara`)
// on Go toolchain PE fixtures and freshly compiled Windows PE binaries.
// Skips cleanly when `yara` is not installed.
func TestLibYaraDifferential(t *testing.T) {
	if _, err := exec.LookPath("yara"); err != nil {
		t.Skipf("yara CLI not installed: %v", err)
	}

	dir := t.TempDir()
	yarPath := filepath.Join(dir, "pe_diff.yar")
	yarSrc := `
import "pe"
import "console"

rule pe_diff {
	condition:
		console.log("IMPHASH=", pe.imphash()) and
		console.log("CALCSUM=", pe.calculate_checksum()) and
		console.log("MACHINE=", pe.machine) and
		console.log("SECTIONS=", pe.number_of_sections) and
		console.log("IMPORTS=", pe.number_of_imports) and
		console.log("EXPORTS=", pe.number_of_exports) and
		console.log("CHECKSUM=", pe.checksum) and
		console.log("OV_OFF=", pe.overlay.offset) and
		console.log("OV_SIZE=", pe.overlay.size)
}
`
	if err := os.WriteFile(yarPath, []byte(yarSrc), 0600); err != nil {
		t.Fatal(err)
	}

	gorootOut, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	testdataDir := filepath.Join(strings.TrimSpace(string(gorootOut)), "src", "debug", "pe", "testdata")
	targets := []string{
		filepath.Join(testdataDir, "gcc-386-mingw-exec"),
		filepath.Join(testdataDir, "gcc-amd64-mingw-exec"),
		filepath.Join(testdataDir, "gcc-386-mingw-no-symbols-exec"),
	}

	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"libyara diff\") }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64", "arm64"} {
		outExe := filepath.Join(dir, "hello-"+arch+".exe")
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", outExe, source)
		for _, env := range os.Environ() {
			key := strings.SplitN(env, "=", 2)[0]
			switch key {
			case "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOEXPERIMENT":
				continue
			}
			cmd.Env = append(cmd.Env, env)
		}
		cmd.Env = append(cmd.Env, "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOEXPERIMENT=")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", arch, err, out)
		}
		targets = append(targets, outExe)
		if arch == "amd64" {
			raw, err := os.ReadFile(outExe)
			if err != nil {
				t.Fatal(err)
			}
			ovPath := filepath.Join(dir, "hello-amd64-overlay.exe")
			if err := os.WriteFile(ovPath, append(raw, []byte("OVERLAY_TEST_DATA")...), 0600); err != nil {
				t.Fatal(err)
			}
			targets = append(targets, ovPath)
		}
	}

	kvRe := regexp.MustCompile(`(?m)^([A-Z_]+)=(\S+)$`)
	for _, path := range targets {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := gope.New(data)
			if err != nil {
				t.Fatalf("gope.New: %v", err)
			}

			cmd := exec.Command("yara", yarPath, path)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("yara: %v\n%s", err, stderr.String())
			}

			vals := make(map[string]string)
			for _, match := range kvRe.FindAllStringSubmatch(stdout.String()+stderr.String(), -1) {
				vals[match[1]] = match[2]
			}

			yMachine, _ := strconv.ParseUint(vals["MACHINE"], 10, 16)
			if uint16(yMachine) != f.FileHeader.Machine {
				t.Fatalf("machine: yara=%#x go-pe=%#x", yMachine, f.FileHeader.Machine)
			}
			ySecs, _ := strconv.Atoi(vals["SECTIONS"])
			if ySecs != f.NumberOfSections() {
				t.Fatalf("sections: yara=%d go-pe=%d", ySecs, f.NumberOfSections())
			}

			gImports, err := f.Imports(data)
			if err != nil {
				t.Fatalf("Imports: %v", err)
			}
			yImports, _ := strconv.Atoi(vals["IMPORTS"])
			if yImports != len(gImports) {
				t.Fatalf("imports: yara=%d go-pe=%d", yImports, len(gImports))
			}

			gExports, err := f.Exports(data)
			if err != nil {
				t.Fatalf("Exports: %v", err)
			}
			gExportCount := 0
			if gExports != nil {
				for _, s := range gExports.Symbols {
					if s.RVA != 0 {
						gExportCount++
					}
				}
			}
			yExports, _ := strconv.Atoi(vals["EXPORTS"])
			if yExports != gExportCount {
				t.Fatalf("exports: yara=%d go-pe=%d", yExports, gExportCount)
			}

			gImphash, err := f.Imphash(data)
			if errors.Is(err, gope.ErrNoImports) {
				gImphash = ""
			} else if err != nil {
				t.Fatalf("Imphash: %v", err)
			}
			if vals["IMPHASH"] != gImphash {
				t.Fatalf("imphash: yara=%q go-pe=%q", vals["IMPHASH"], gImphash)
			}

			yChecksum, _ := strconv.ParseUint(vals["CHECKSUM"], 10, 32)
			if uint32(yChecksum) != f.OptionalHeader.CheckSum {
				t.Fatalf("checksum: yara=%#x go-pe=%#x", yChecksum, f.OptionalHeader.CheckSum)
			}

			gCalcSum, err := f.ComputeCheckSum(data)
			if err != nil {
				t.Fatalf("ComputeCheckSum: %v", err)
			}
			yCalcSum, _ := strconv.ParseUint(vals["CALCSUM"], 10, 32)
			if uint32(yCalcSum) != gCalcSum {
				t.Fatalf("calculate_checksum: yara=%#x go-pe=%#x", yCalcSum, gCalcSum)
			}

			yOvOff, _ := strconv.ParseInt(vals["OV_OFF"], 10, 64)
			yOvSize, _ := strconv.ParseInt(vals["OV_SIZE"], 10, 64)
			gOvOff, gHasOv := f.OverlayOffset()
			if yOvSize > 0 {
				if !gHasOv || gOvOff != yOvOff || int64(len(data))-gOvOff != yOvSize {
					t.Fatalf("overlay: yara=(%d, %d) go-pe=(%d, %t, %d)", yOvOff, yOvSize, gOvOff, gHasOv, int64(len(data))-gOvOff)
				}
			} else if gHasOv {
				t.Fatalf("overlay: yara=(%d, %d) go-pe=(%d, true)", yOvOff, yOvSize, gOvOff)
			}
		})
	}
}
