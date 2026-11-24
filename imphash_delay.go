package pe

// DelayAwareImphash computes an MD5 import hash combining standard imports
// and delayed imports in order. Returns ("", false) when both slices contain
// zero symbols.
func DelayAwareImphash(imports []ImportLibrary, delayImports []DelayImportLibrary) (string, bool) {
	b := newImphashBuilder()
	for i := range imports {
		lib := &imports[i]
		dll := imphashCString(lib.DLL)
		libName := imphashLibraryName(dll)
		for j := range lib.Symbols {
			sym := &lib.Symbols[j]
			funcName := imphashCString(sym.Name)
			if sym.ByOrdinal {
				funcName = imphashOrdinalName(dll, sym.Ordinal)
			}
			b.add(libName, funcName)
		}
	}
	for i := range delayImports {
		lib := &delayImports[i]
		dll := imphashCString(lib.DLL)
		libName := imphashLibraryName(dll)
		for j := range lib.Symbols {
			sym := &lib.Symbols[j]
			funcName := imphashCString(sym.Name)
			if sym.ByOrdinal {
				funcName = imphashOrdinalName(dll, sym.Ordinal)
			}
			b.add(libName, funcName)
		}
	}
	if b.first {
		return "", false
	}
	return b.sum(), true
}

// DelayAwareImphash reads standard and delayed imports via [File.Imports] and
// [File.DelayImports] and computes their combined MD5 import hash. Returns
// ("", [ErrNoImports]) when no imported symbols exist in either directory.
func (f *File) DelayAwareImphash(data []byte) (string, error) {
	imports, err := f.Imports(data)
	if err != nil {
		return "", err
	}
	delays, err := f.DelayImports(data)
	if err != nil {
		return "", err
	}
	digest, ok := DelayAwareImphash(imports, delays)
	if !ok {
		return "", ErrNoImports
	}
	return digest, nil
}
