package detect

import (
	"fmt"

	"github.com/cawalch/go-pe"
)

// MitigationAnomalies reports inconsistencies between declared DLL mitigation
// flags and their supporting LoadConfig / BaseReloc directories.
type MitigationAnomalies struct {
	GuardCFMissingTable       bool
	DynamicBaseRelocsStripped bool
	DynamicBaseEmptyRelocs    bool
}

// Any reports whether any mitigation anomaly was detected.
func (m MitigationAnomalies) Any() bool {
	return m.GuardCFMissingTable || m.DynamicBaseRelocsStripped || m.DynamicBaseEmptyRelocs
}

// Mitigations checks GuardCF and ASLR (DynamicBase) consistency against
// [pe.File.LoadConfig] and [pe.File.BaseRelocs].
func Mitigations(f *pe.File, data []byte) (MitigationAnomalies, error) {
	if f == nil {
		return MitigationAnomalies{}, fmt.Errorf("%w: nil File", pe.ErrInvalidHeader)
	}
	var out MitigationAnomalies
	dllChars := f.OptionalHeader.DllCharacteristics

	if dllChars&pe.DllCharacteristicsGuardCF != 0 {
		lc, err := f.LoadConfig(data)
		if err != nil {
			return MitigationAnomalies{}, err
		}
		if lc == nil || lc.GuardCFFunctionTable == 0 {
			out.GuardCFMissingTable = true
		}
	}

	if dllChars&pe.DllCharacteristicsDynamicBase != 0 {
		if f.FileHeader.Characteristics&pe.CharacteristicsRelocsStripped != 0 {
			out.DynamicBaseRelocsStripped = true
		}
		relocs, err := f.BaseRelocs(data)
		if err != nil {
			return MitigationAnomalies{}, err
		}
		if relocs == nil || relocs.ActiveEntries == 0 {
			out.DynamicBaseEmptyRelocs = true
		}
	}

	return out, nil
}
