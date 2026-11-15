package testfixture

import "encoding/binary"

// DelayImports builds a PE32 or PE32+ image containing RVA-based
// (Attributes = 1) delayed import descriptors in a single .didat section.
func DelayImports(is64 bool, libraries, symbols int) []byte {
	return DelayImportsWithAttributes(is64, 1, libraries, symbols)
}

// DelayImportsWithAttributes builds a PE32 or PE32+ image containing delayed
// import descriptors using attrs (for example 1 for RVA-based or 0 for legacy
// VA-based PE32 descriptors).
func DelayImportsWithAttributes(is64 bool, attrs uint32, libraries, symbols int) []byte {
	data := Minimal(is64, 1)
	section, directory, width := 376, 248+13*8, 4
	imageBase := uint64(0x400000)
	if is64 {
		section, directory, width = 392, 264+13*8, 8
		imageBase = 0x140000000
	}

	const secFileStart = 512
	const secRVAStart = 0x1000
	const descSize = 32

	thunks := (secFileStart + (libraries+1)*descSize + 7) &^ 7
	// Reserve both INT and IAT per library so callers/comparisons see both tables.
	intSize := (symbols + 1) * width
	iats := thunks + libraries*intSize
	dlls := iats + libraries*intSize
	names := dlls + libraries*16
	size := (names + symbols*16 + 511) &^ 511
	data = append(data[:secFileStart], make([]byte, size-secFileStart)...)

	copy(data[section:section+8], ".didat\x00\x00")
	binary.LittleEndian.PutUint32(data[section+8:], uint32(size-secFileStart))
	binary.LittleEndian.PutUint32(data[section+12:], secRVAStart)
	binary.LittleEndian.PutUint32(data[section+16:], uint32(size-secFileStart))
	binary.LittleEndian.PutUint32(data[section+20:], secFileStart)
	binary.LittleEndian.PutUint32(data[152+56:], secRVAStart+((uint32(size-secFileStart)+0xfff)&^0xfff))

	if libraries > 0 || symbols > 0 {
		binary.LittleEndian.PutUint32(data[directory:], secRVAStart)
		binary.LittleEndian.PutUint32(data[directory+4:], uint32((libraries+1)*descSize))
	}

	vaBias := uint64(0)
	if attrs&1 == 0 {
		vaBias = imageBase
	}
	dllSuffix := ".dll"
	for i := range libraries {
		desc := data[secFileStart+i*descSize:]
		intRVA := uint32(thunks+i*intSize-secFileStart) + secRVAStart
		iatRVA := uint32(iats+i*intSize-secFileStart) + secRVAStart
		dllRVA := uint32(dlls+i*16-secFileStart) + secRVAStart

		binary.LittleEndian.PutUint32(desc[0:4], attrs)
		binary.LittleEndian.PutUint32(desc[4:8], uint32(uint64(dllRVA)+vaBias))
		binary.LittleEndian.PutUint32(desc[12:16], uint32(uint64(iatRVA)+vaBias))
		binary.LittleEndian.PutUint32(desc[16:20], uint32(uint64(intRVA)+vaBias))

		nameBytes := []byte{byte('a' + (i % 26)), byte('0' + (i/26)%10), byte('0' + (i/260)%10)}
		copy(data[dlls+i*16:], append(nameBytes, dllSuffix...))

		for j := range symbols {
			hintNameRVA := uint64(names+j*16-secFileStart) + secRVAStart + vaBias
			intOff := thunks + i*intSize + j*width
			iatOff := iats + i*intSize + j*width
			if is64 {
				binary.LittleEndian.PutUint64(data[intOff:], hintNameRVA)
				binary.LittleEndian.PutUint64(data[iatOff:], hintNameRVA)
			} else {
				binary.LittleEndian.PutUint32(data[intOff:], uint32(hintNameRVA))
				binary.LittleEndian.PutUint32(data[iatOff:], uint32(hintNameRVA))
			}
		}
	}
	for j := range symbols {
		binary.LittleEndian.PutUint16(data[names+j*16:], uint16(j))
		fn := []byte{'D', 'e', 'l', 'a', 'y', byte('0' + (j/100)%10), byte('0' + (j/10)%10), byte('0' + j%10)}
		copy(data[names+j*16+2:], fn)
	}
	return data
}
