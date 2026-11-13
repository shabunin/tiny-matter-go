package credentials

// Minimal DER encoding for the X.509 structures Matter needs.

const (
	derBoolean     = 0x01
	derInteger     = 0x02
	derBitString   = 0x03
	derOctetString = 0x04
	derOID         = 0x06
	derUTF8String  = 0x0C
	derPrintable   = 0x13
	derIA5String   = 0x16
	derUTCTime     = 0x17
	derGenTime     = 0x18
	derSequence    = 0x30
	derSet         = 0x31
)

// der returns the DER element with the given tag and concatenated content.
func der(tag byte, content ...[]byte) []byte {
	n := 0
	for _, c := range content {
		n += len(c)
	}
	b := make([]byte, 0, n+6)
	b = append(b, tag)
	switch {
	case n < 0x80:
		b = append(b, byte(n))
	case n < 0x100:
		b = append(b, 0x81, byte(n))
	case n < 0x10000:
		b = append(b, 0x82, byte(n>>8), byte(n))
	default:
		b = append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	for _, c := range content {
		b = append(b, c...)
	}
	return b
}

// derUint encodes a non-negative big-endian integer, minimally.
func derUint(v []byte) []byte {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) > 0 && v[0]&0x80 != 0 {
		return der(derInteger, []byte{0}, v)
	}
	return der(derInteger, v)
}

// derRead parses one element at the start of b, returning its tag, content
// and the remaining bytes.
func derRead(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return
	}
	tag, n, i := b[0], int(b[1]), 2
	if n >= 0x80 {
		k := n & 0x7F
		if k == 0 || k > 3 || len(b) < 2+k {
			return
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		i += k
	}
	if len(b)-i < n {
		return
	}
	return tag, b[i : i+n], b[i+n:], true
}

// SignatureToDER converts a raw r||s P-256 signature to DER
// (ECDSA-Sig-Value).
func SignatureToDER(sig []byte) []byte {
	if len(sig) != 64 {
		return nil
	}
	return der(derSequence, derUint(sig[:32]), derUint(sig[32:]))
}

// SignatureFromDER converts a DER ECDSA-Sig-Value to raw r||s.
func SignatureFromDER(b []byte) ([]byte, bool) {
	tag, seq, rest, ok := derRead(b)
	if !ok || tag != derSequence || len(rest) != 0 {
		return nil, false
	}
	out := make([]byte, 64)
	for i := 0; i < 2; i++ {
		var v []byte
		if tag, v, seq, ok = derRead(seq); !ok || tag != derInteger || len(v) == 0 || v[0]&0x80 != 0 {
			return nil, false
		}
		for len(v) > 1 && v[0] == 0 {
			v = v[1:]
		}
		if len(v) > 32 {
			return nil, false
		}
		copy(out[32*i+32-len(v):32*i+32], v)
	}
	return out, len(seq) == 0
}
