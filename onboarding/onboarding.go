// Package onboarding encodes and decodes Matter onboarding payloads (spec
// 5.1): the QR code ("MT:" followed by base-38 text) and the 11- or
// 21-digit manual pairing code. Both carry the setup passcode and the
// discriminator a commissioner needs to find and commission a device.
package onboarding

import (
	"errors"
	"strconv"
	"strings"
)

// Commissioning flows.
const (
	FlowStandard   = 0 // commissionable as soon as powered
	FlowUserIntent = 1 // after a user action, such as a button press
	FlowCustom     = 2 // per the vendor's instructions
)

// Discovery capabilities (the QR code's rendezvous bitmask).
const (
	DiscoverySoftAP    = 1 << 0
	DiscoveryBLE       = 1 << 1
	DiscoveryOnNetwork = 1 << 2
	DiscoveryWiFiPAF   = 1 << 3
)

// Payload is the content of an onboarding code.
type Payload struct {
	Version   uint8
	VendorID  uint16 // zero if unknown (a short manual code)
	ProductID uint16
	Flow      uint8
	// Discovery is the discovery capabilities bitmask (QR code only).
	Discovery uint8
	// Discriminator is the 12-bit discriminator. A manual code carries only
	// its upper 4 bits, the short discriminator; ShortOnly is then set and
	// the lower 8 bits are zero.
	Discriminator uint16
	ShortOnly     bool
	Passcode      uint32
	// Extra holds the optional TLV data after the fixed QR code fields.
	Extra []byte
}

// ShortDiscriminator returns the upper 4 bits of the discriminator, which
// is what a manual code carries.
func (p *Payload) ShortDiscriminator() uint8 { return uint8(p.Discriminator >> 8) }

// Errors.
var (
	ErrFormat   = errors.New("onboarding: malformed code")
	ErrCheck    = errors.New("onboarding: check digit mismatch")
	ErrPasscode = errors.New("onboarding: invalid passcode")
	ErrRange    = errors.New("onboarding: field out of range")
)

// ValidPasscode reports whether a setup passcode is allowed (spec 5.1.7):
// 1 to 99999998, except trivial values.
func ValidPasscode(pin uint32) bool {
	switch pin {
	case 0, 11111111, 22222222, 33333333, 44444444, 55555555,
		66666666, 77777777, 88888888, 99999999, 12345678, 87654321:
		return false
	}
	return pin <= 99999998
}

func (p *Payload) check() error {
	if !ValidPasscode(p.Passcode) {
		return ErrPasscode
	}
	if p.Discriminator > 0xFFF || p.Version > 7 || p.Flow > 3 {
		return ErrRange
	}
	return nil
}

// Parse decodes a QR code ("MT:...") or a manual pairing code, which may
// contain dashes or spaces.
func Parse(code string) (*Payload, error) {
	code = strings.TrimSpace(code)
	if strings.HasPrefix(code, "MT:") {
		return ParseQR(code)
	}
	return ParseManual(code)
}

// QR code layout (spec 5.1.3), packed least significant bit first.
const (
	qrVersionBits       = 3
	qrVendorBits        = 16
	qrProductBits       = 16
	qrFlowBits          = 2
	qrDiscoveryBits     = 8
	qrDiscriminatorBits = 12
	qrPasscodeBits      = 27
	qrPaddingBits       = 4
	qrFixedBytes        = 11 // 88 bits
)

// ParseQR decodes a QR code payload ("MT:" and base-38 text).
func ParseQR(s string) (*Payload, error) {
	if !strings.HasPrefix(s, "MT:") {
		return nil, ErrFormat
	}
	b, err := base38Decode(s[3:])
	if err != nil {
		return nil, err
	}
	if len(b) < qrFixedBytes {
		return nil, ErrFormat
	}
	r := bitReader{b: b}
	p := &Payload{
		Version:       uint8(r.read(qrVersionBits)),
		VendorID:      uint16(r.read(qrVendorBits)),
		ProductID:     uint16(r.read(qrProductBits)),
		Flow:          uint8(r.read(qrFlowBits)),
		Discovery:     uint8(r.read(qrDiscoveryBits)),
		Discriminator: uint16(r.read(qrDiscriminatorBits)),
		Passcode:      uint32(r.read(qrPasscodeBits)),
	}
	if r.read(qrPaddingBits) != 0 || p.Version != 0 {
		return nil, ErrFormat
	}
	if len(b) > qrFixedBytes {
		p.Extra = b[qrFixedBytes:]
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return p, nil
}

// QRCode encodes the payload as a QR code payload string.
func (p *Payload) QRCode() (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	if p.ShortOnly {
		return "", ErrRange // a QR code needs the full discriminator
	}
	b := make([]byte, qrFixedBytes, qrFixedBytes+len(p.Extra))
	w := bitWriter{b: b}
	w.write(uint64(p.Version), qrVersionBits)
	w.write(uint64(p.VendorID), qrVendorBits)
	w.write(uint64(p.ProductID), qrProductBits)
	w.write(uint64(p.Flow), qrFlowBits)
	w.write(uint64(p.Discovery), qrDiscoveryBits)
	w.write(uint64(p.Discriminator), qrDiscriminatorBits)
	w.write(uint64(p.Passcode), qrPasscodeBits)
	b = append(b, p.Extra...)
	return "MT:" + base38Encode(b), nil
}

type bitReader struct {
	b   []byte
	off int
}

func (r *bitReader) read(n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		if r.b[r.off/8]>>(r.off%8)&1 != 0 {
			v |= 1 << i
		}
		r.off++
	}
	return v
}

type bitWriter struct {
	b   []byte
	off int
}

func (w *bitWriter) write(v uint64, n int) {
	for i := 0; i < n; i++ {
		if v>>i&1 != 0 {
			w.b[w.off/8] |= 1 << (w.off % 8)
		}
		w.off++
	}
}

const base38Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."

// base38Encode encodes 3-byte groups (little endian) as 5 characters, a
// final 2 bytes as 4 and a final byte as 2, least significant digit first.
func base38Encode(b []byte) string {
	out := make([]byte, 0, (len(b)+2)/3*5)
	for len(b) > 0 {
		n := min(len(b), 3)
		var v uint32
		for i := n - 1; i >= 0; i-- {
			v = v<<8 | uint32(b[i])
		}
		digits := [4]int{0, 2, 4, 5}[n]
		for i := 0; i < digits; i++ {
			out = append(out, base38Chars[v%38])
			v /= 38
		}
		b = b[n:]
	}
	return string(out)
}

func base38Decode(s string) ([]byte, error) {
	var out []byte
	for len(s) > 0 {
		var digits, n int
		switch {
		case len(s) >= 5:
			digits, n = 5, 3
		case len(s) == 4:
			digits, n = 4, 2
		case len(s) == 2:
			digits, n = 2, 1
		default:
			return nil, ErrFormat
		}
		var v uint64
		for i := digits - 1; i >= 0; i-- {
			d := strings.IndexByte(base38Chars, s[i])
			if d < 0 {
				return nil, ErrFormat
			}
			v = v*38 + uint64(d)
		}
		if v >= 1<<(8*n) {
			return nil, ErrFormat
		}
		for i := 0; i < n; i++ {
			out = append(out, byte(v>>(8*i)))
		}
		s = s[digits:]
	}
	return out, nil
}

// ParseManual decodes an 11- or 21-digit manual pairing code (spec
// 5.1.4). Dashes and spaces are ignored.
func ParseManual(s string) (*Payload, error) {
	digits := make([]byte, 0, 21)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		case c == '-' || c == ' ':
		default:
			return nil, ErrFormat
		}
	}
	if len(digits) != 11 && len(digits) != 21 {
		return nil, ErrFormat
	}
	body := string(digits[:len(digits)-1])
	if verhoeff(body) != digits[len(digits)-1] {
		return nil, ErrCheck
	}
	num := func(from, n int) uint32 {
		v, _ := strconv.ParseUint(body[from:from+n], 10, 32)
		return uint32(v)
	}
	c1, c2, c3 := num(0, 1), num(1, 5), num(6, 4)
	long := c1&4 != 0
	if c1 > 7 || c2 > 0xFFFF || c3 > 0x1FFF || long != (len(digits) == 21) {
		return nil, ErrFormat
	}
	short := (c1&3)<<2 | c2>>14
	p := &Payload{
		Discriminator: uint16(short) << 8,
		ShortOnly:     true,
		Passcode:      c3<<14 | c2&0x3FFF,
	}
	if long {
		vid, pid := num(10, 5), num(15, 5)
		if vid > 0xFFFF || pid > 0xFFFF {
			return nil, ErrFormat
		}
		p.VendorID, p.ProductID = uint16(vid), uint16(pid)
		p.Flow = FlowCustom
	}
	if !ValidPasscode(p.Passcode) {
		return nil, ErrPasscode
	}
	return p, nil
}

// ManualCode encodes the payload as a manual pairing code: 21 digits with
// the vendor and product IDs for a non-standard commissioning flow, 11
// digits otherwise.
func (p *Payload) ManualCode() (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	short := uint32(p.ShortDiscriminator())
	long := p.Flow != FlowStandard
	c1 := short >> 2
	if long {
		c1 |= 4
	}
	c2 := p.Passcode&0x3FFF | (short&3)<<14
	c3 := p.Passcode >> 14
	s := strconv.Itoa(int(c1)) + pad(c2, 5) + pad(c3, 4)
	if long {
		s += pad(uint32(p.VendorID), 5) + pad(uint32(p.ProductID), 5)
	}
	return s + string(verhoeff(s)), nil
}

func pad(v uint32, n int) string {
	s := strconv.FormatUint(uint64(v), 10)
	return strings.Repeat("0", n-len(s)) + s
}

// Verhoeff check digit tables.
var (
	verhoeffD = [10][10]byte{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]byte{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	verhoeffInv = [10]byte{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
)

// verhoeff returns the Verhoeff check digit of a decimal string.
func verhoeff(s string) byte {
	var c byte
	for i := 0; i < len(s); i++ {
		d := s[len(s)-1-i] - '0'
		c = verhoeffD[c][verhoeffP[(i+1)%8][d]]
	}
	return '0' + verhoeffInv[c]
}
