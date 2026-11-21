package pe

import "fmt"

// ASN.1 / BER parser bounds enforced during Authenticode decoding.
const (
	// MaxASN1Depth limits constructed BER/DER nesting depth.
	MaxASN1Depth = 256
	// MaxASN1Elements limits the total number of ASN.1 TLV elements visited.
	MaxASN1Elements = 65536
)

type berState struct {
	elements int
	lengths  []int
}

// berToDER converts definite or indefinite-length BER input into a freshly
// allocated canonical DER slice without retaining references to input.
//
// It allows trailing NUL padding after the root TLV, which some PE signers
// append inside WIN_CERTIFICATE dwLength, and rejects non-zero trailing bytes,
// unbounded nesting, element count floods, primitive indefinite lengths, and
// child extents exceeding their parent container.
func berToDER(input []byte) ([]byte, error) {
	der, _, err := berToDERWithTrailing(input)
	return der, err
}

func berToDERWithTrailing(input []byte) ([]byte, int, error) {
	if len(input) == 0 {
		return nil, 0, fmt.Errorf("%w: empty ASN.1 input", ErrInvalidAuthenticode)
	}
	if len(input) > MaxCertificateBytes {
		return nil, 0, fmt.Errorf("%w: ASN.1 input size %d exceeds %d", ErrAuthenticodeLimit, len(input), MaxCertificateBytes)
	}

	var st berState
	end, derLen, err := measureBERElement(input, 0, len(input), 1, &st)
	if err != nil {
		return nil, 0, err
	}
	for i := end; i < len(input); i++ {
		if input[i] != 0 {
			return nil, 0, fmt.Errorf("%w: trailing non-zero data at offset %d", ErrInvalidAuthenticode, i)
		}
	}

	out := make([]byte, 0, derLen)
	lenIdx := 0
	emitBERElement(input, 0, st.lengths, &lenIdx, &out)
	return out, len(input) - end, nil
}

func measureBERElement(src []byte, offset, parentEnd, depth int, st *berState) (nextOffset int, derSize int, err error) {
	if depth > MaxASN1Depth {
		return 0, 0, fmt.Errorf("%w: ASN.1 nesting depth exceeds %d", ErrAuthenticodeLimit, MaxASN1Depth)
	}
	st.elements++
	if st.elements > MaxASN1Elements {
		return 0, 0, fmt.Errorf("%w: ASN.1 element count exceeds %d", ErrAuthenticodeLimit, MaxASN1Elements)
	}
	if offset >= parentEnd {
		return 0, 0, fmt.Errorf("%w: unexpected end of ASN.1 data", ErrInvalidAuthenticode)
	}

	tagStart := offset
	first := src[offset]
	offset++
	constructed := first&0x20 != 0

	if first&0x1f == 0x1f {
		// Multi-octet high tag number form (X.690 section 8.1.2.4).
		const maxHighTagOctets = 5
		count := 0
		for {
			if offset >= parentEnd {
				return 0, 0, fmt.Errorf("%w: truncated ASN.1 high-tag identifier", ErrInvalidAuthenticode)
			}
			count++
			if count > maxHighTagOctets {
				return 0, 0, fmt.Errorf("%w: ASN.1 tag identifier too large", ErrInvalidAuthenticode)
			}
			b := src[offset]
			offset++
			if count == 1 && b == 0x80 {
				return 0, 0, fmt.Errorf("%w: non-minimal ASN.1 high-tag identifier", ErrInvalidAuthenticode)
			}
			if b&0x80 == 0 {
				break
			}
		}
	}
	tagLen := offset - tagStart

	if offset >= parentEnd {
		return 0, 0, fmt.Errorf("%w: truncated ASN.1 length", ErrInvalidAuthenticode)
	}
	lenOctet := src[offset]
	offset++

	if lenOctet == 0x80 {
		if !constructed {
			return 0, 0, fmt.Errorf("%w: primitive ASN.1 tag cannot use indefinite length", ErrInvalidAuthenticode)
		}
		lenPos := len(st.lengths)
		st.lengths = append(st.lengths, 0)

		childDERLen := 0
		for {
			if offset+2 > parentEnd {
				return 0, 0, fmt.Errorf("%w: unterminated indefinite-length ASN.1 container", ErrInvalidAuthenticode)
			}
			if src[offset] == 0 && src[offset+1] == 0 {
				offset += 2
				break
			}
			next, cLen, err := measureBERElement(src, offset, parentEnd, depth+1, st)
			if err != nil {
				return 0, 0, err
			}
			offset = next
			childDERLen += cLen
		}

		st.lengths[lenPos] = childDERLen
		return offset, tagLen + derLengthSize(childDERLen) + childDERLen, nil
	}

	var length int
	if lenOctet < 0x80 {
		length = int(lenOctet)
	} else {
		numBytes := int(lenOctet & 0x7f)
		if numBytes == 0 || numBytes > 4 {
			return 0, 0, fmt.Errorf("%w: unsupported ASN.1 length octet count %d", ErrInvalidAuthenticode, numBytes)
		}
		if offset+numBytes > parentEnd {
			return 0, 0, fmt.Errorf("%w: truncated ASN.1 long-form length", ErrInvalidAuthenticode)
		}
		if numBytes == 4 && src[offset] > 0x7f {
			return 0, 0, fmt.Errorf("%w: ASN.1 length overflows 31-bit bound", ErrInvalidAuthenticode)
		}
		var ulen uint64
		for i := range numBytes {
			ulen = (ulen << 8) | uint64(src[offset+i])
		}
		offset += numBytes
		if ulen > uint64(parentEnd-offset) {
			return 0, 0, fmt.Errorf("%w: ASN.1 length %d exceeds container bounds %d", ErrInvalidAuthenticode, ulen, parentEnd-offset)
		}
		length = int(ulen)
	}
	if length > parentEnd-offset {
		return 0, 0, fmt.Errorf("%w: ASN.1 length %d exceeds container bounds %d", ErrInvalidAuthenticode, length, parentEnd-offset)
	}

	contentEnd := offset + length
	if !constructed {
		return contentEnd, tagLen + derLengthSize(length) + length, nil
	}

	lenPos := len(st.lengths)
	st.lengths = append(st.lengths, 0)
	childDERLen := 0
	cursor := offset
	for cursor < contentEnd {
		next, cLen, err := measureBERElement(src, cursor, contentEnd, depth+1, st)
		if err != nil {
			return 0, 0, err
		}
		cursor = next
		childDERLen += cLen
	}
	st.lengths[lenPos] = childDERLen
	return contentEnd, tagLen + derLengthSize(childDERLen) + childDERLen, nil
}

func emitBERElement(src []byte, offset int, lengths []int, lenIdx *int, dst *[]byte) int {
	tagStart := offset
	first := src[offset]
	offset++
	constructed := first&0x20 != 0

	if first&0x1f == 0x1f {
		for src[offset]&0x80 != 0 {
			offset++
		}
		offset++
	}
	*dst = append(*dst, src[tagStart:offset]...)

	lenOctet := src[offset]
	offset++

	if lenOctet == 0x80 {
		childDERLen := lengths[*lenIdx]
		*lenIdx++
		appendDERLength(dst, childDERLen)
		for src[offset] != 0 || src[offset+1] != 0 {
			offset = emitBERElement(src, offset, lengths, lenIdx, dst)
		}
		return offset + 2
	}

	var length int
	if lenOctet < 0x80 {
		length = int(lenOctet)
	} else {
		numBytes := int(lenOctet & 0x7f)
		for range numBytes {
			length = (length << 8) | int(src[offset])
			offset++
		}
	}

	contentEnd := offset + length
	if !constructed {
		appendDERLength(dst, length)
		*dst = append(*dst, src[offset:contentEnd]...)
		return contentEnd
	}

	childDERLen := lengths[*lenIdx]
	*lenIdx++
	appendDERLength(dst, childDERLen)
	cursor := offset
	for cursor < contentEnd {
		cursor = emitBERElement(src, cursor, lengths, lenIdx, dst)
	}
	return contentEnd
}

func derLengthSize(n int) int {
	switch {
	case n < 0x80:
		return 1
	case n <= 0xff:
		return 2
	case n <= 0xffff:
		return 3
	case n <= 0xffffff:
		return 4
	default:
		return 5
	}
}

func appendDERLength(dst *[]byte, n int) {
	var enc [5]byte
	m := encodeDERLength(&enc, n)
	*dst = append(*dst, enc[:m]...)
}

func encodeDERLength(buf *[5]byte, n int) int {
	if n < 0x80 {
		buf[0] = byte(n)
		return 1
	}
	switch {
	case n <= 0xff:
		buf[0] = 0x81
		buf[1] = byte(n)
		return 2
	case n <= 0xffff:
		buf[0] = 0x82
		buf[1] = byte(n >> 8)
		buf[2] = byte(n)
		return 3
	case n <= 0xffffff:
		buf[0] = 0x83
		buf[1] = byte(n >> 16)
		buf[2] = byte(n >> 8)
		buf[3] = byte(n)
		return 4
	default:
		buf[0] = 0x84
		buf[1] = byte(n >> 24)
		buf[2] = byte(n >> 16)
		buf[3] = byte(n >> 8)
		buf[4] = byte(n)
		return 5
	}
}
