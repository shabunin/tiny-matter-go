package p256

import (
	"io"

	"github.com/shabunin/tiny-matter-go/crypto/internal/bigmod"
	"github.com/shabunin/tiny-matter-go/crypto/internal/nistec"
)

// Point is a P-256 point, including the point at infinity. The zero value is
// not usable; use NewPoint, Generator or SetBytes. Operations are constant
// time. It exists for protocols such as SPAKE2+ that need raw group
// arithmetic.
type Point struct {
	p nistec.P256Point
}

// NewPoint returns the point at infinity.
func NewPoint() *Point {
	q := &Point{}
	q.p.Set(nistec.NewP256Point())
	return q
}

// Generator returns the canonical generator G.
func Generator() *Point {
	q := &Point{}
	q.p.SetGenerator()
	return q
}

// SetBytes sets p to the uncompressed (or compressed) SEC 1 encoding b,
// validating that it is on the curve.
func (p *Point) SetBytes(b []byte) (*Point, error) {
	if _, err := p.p.SetBytes(b); err != nil {
		return nil, err
	}
	return p, nil
}

// Set sets p = q and returns p.
func (p *Point) Set(q *Point) *Point { p.p.Set(&q.p); return p }

// Bytes returns the 65-byte uncompressed encoding of p, or the single byte
// 0x00 for the point at infinity.
func (p *Point) Bytes() []byte { return p.p.Bytes() }

// Add sets p = a + b and returns p.
func (p *Point) Add(a, b *Point) *Point { p.p.Add(&a.p, &b.p); return p }

// Negate sets p = -q and returns p.
func (p *Point) Negate(q *Point) *Point {
	p.p.Set(&q.p)
	p.p.Negate(1)
	return p
}

// ScalarMult sets p = s*q, where s is a 32-byte big-endian scalar reduced
// modulo the group order, and returns p.
func (p *Point) ScalarMult(q *Point, s []byte) (*Point, error) {
	if _, err := p.p.ScalarMult(&q.p, s); err != nil {
		return nil, err
	}
	return p, nil
}

// ScalarBaseMult sets p = s*G, where s is a 32-byte big-endian scalar reduced
// modulo the group order, and returns p.
func (p *Point) ScalarBaseMult(s []byte) (*Point, error) {
	if _, err := p.p.ScalarBaseMult(s); err != nil {
		return nil, err
	}
	return p, nil
}

// ReduceScalar returns b, a big-endian integer of any length, reduced modulo
// the group order as a 32-byte scalar. SPAKE2+ uses it to derive w0 and w1
// from the 40-byte PBKDF2 halves.
func ReduceScalar(b []byte) []byte {
	N := n()
	x := bigmod.NewNat().SetBytesWide(b)
	return bigmod.NewNat().Mod(x, N).Bytes(N)
}

// RandomScalar returns a uniformly random scalar in [1, n-1].
func RandomScalar(rand io.Reader) ([]byte, error) {
	var b [ScalarSize]byte
	for {
		if err := readFull(rand)(b[:]); err != nil {
			return nil, err
		}
		k, err := bigmod.NewNat().SetBytes(b[:], n())
		if err == nil && k.IsZero() == 0 {
			return k.Bytes(n()), nil
		}
	}
}
