// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the crypto/internal/LICENSE-GO file.

// P256Scalar was added for tiny-matter-go. Its inversion chain is from Go's
// crypto/internal/fips140/nistec/p256_ordinv.go.

package fiat

import (
	"errors"
	"math/bits"
)

// Only fiat's Mul is used (for squaring and for entering and leaving the
// Montgomery domain too): on 32-bit targets each fiat function is about
// 8 KB of code, and the specialised ones are hardly faster here.

// P256Scalar is an integer modulo n, the order of the P-256 group, in
// constant time and fixed size: ECDSA's scalar arithmetic without the heap
// allocations of bigmod (which TinyGo makes for its multiplication scratch).
//
// The zero value is a valid zero element.
type P256Scalar struct {
	// x is the Montgomery-domain value (R = 2^256).
	x p256ScalarMontgomeryDomainFieldElement
}

// n as little-endian 64-bit limbs.
var p256ScalarN = [4]uint64{0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000}

// p256ScalarRR is R^2 mod n: Mul(x, RR) = x*R, x in the Montgomery domain.
var p256ScalarRR = p256ScalarMontgomeryDomainFieldElement{0x83244c95be79eea2, 0x4699799c49bd6fa6,
	0x2845b2392b6bec59, 0x66e12d94f3d95620}

// limbs loads big-endian v as little-endian limbs and subtracts n from them,
// returning the difference and the borrow (1 if v < n).
func p256ScalarLimbs(v *[32]byte) (l, d [4]uint64, borrow uint64) {
	for i := range l {
		o := 24 - 8*i
		l[i] = uint64(v[o])<<56 | uint64(v[o+1])<<48 | uint64(v[o+2])<<40 | uint64(v[o+3])<<32 |
			uint64(v[o+4])<<24 | uint64(v[o+5])<<16 | uint64(v[o+6])<<8 | uint64(v[o+7])
	}
	d[0], borrow = bits.Sub64(l[0], p256ScalarN[0], 0)
	d[1], borrow = bits.Sub64(l[1], p256ScalarN[1], borrow)
	d[2], borrow = bits.Sub64(l[2], p256ScalarN[2], borrow)
	d[3], borrow = bits.Sub64(l[3], p256ScalarN[3], borrow)
	return
}

// setLimbs sets e to l, which must be below n.
func (e *P256Scalar) setLimbs(l *[4]uint64) {
	p256ScalarMul(&e.x, (*p256ScalarMontgomeryDomainFieldElement)(l), &p256ScalarRR)
}

// SetBytes sets e to the 32-byte big-endian v, which must be below n.
func (e *P256Scalar) SetBytes(v []byte) (*P256Scalar, error) {
	if len(v) != 32 {
		return nil, errors.New("invalid P256Scalar encoding")
	}
	l, _, borrow := p256ScalarLimbs((*[32]byte)(v))
	if borrow == 0 {
		return nil, errors.New("invalid P256Scalar encoding")
	}
	e.setLimbs(&l)
	return e, nil
}

// SetReducedBytes sets e to the 32-byte big-endian v modulo n. Any 256-bit
// value is accepted: 2^256 < 2n, so at most one n is subtracted.
func (e *P256Scalar) SetReducedBytes(v *[32]byte) *P256Scalar {
	l, d, borrow := p256ScalarLimbs(v)
	var r [4]uint64
	p256ScalarSelectznz(&r, p256ScalarUint1(borrow), &d, &l)
	e.setLimbs(&r)
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *P256Scalar) Bytes() [32]byte {
	// Mul(x, 1) = x/R leaves the Montgomery domain.
	one := p256ScalarMontgomeryDomainFieldElement{1}
	var l p256ScalarMontgomeryDomainFieldElement
	p256ScalarMul(&l, &e.x, &one)
	var out [32]byte
	for i, v := range l {
		o := 24 - 8*i
		for j := 0; j < 8; j++ {
			out[o+7-j] = byte(v >> (8 * j))
		}
	}
	return out
}

// Set sets e = t, and returns e.
func (e *P256Scalar) Set(t *P256Scalar) *P256Scalar {
	e.x = t.x
	return e
}

// Add sets e = t1 + t2, and returns e.
func (e *P256Scalar) Add(t1, t2 *P256Scalar) *P256Scalar {
	p256ScalarAdd(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *P256Scalar) Mul(t1, t2 *P256Scalar) *P256Scalar {
	p256ScalarMul(&e.x, &t1.x, &t2.x)
	return e
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *P256Scalar) IsZero() int {
	var nz uint64
	p256ScalarNonzero(&nz, (*[4]uint64)(&e.x))
	return int(1 ^ ((nz | -nz) >> 63))
}

// Equal returns 1 if e and t are equal, and zero otherwise.
func (e *P256Scalar) Equal(t *P256Scalar) int {
	var d P256Scalar
	p256ScalarSub(&d.x, &e.x, &t.x)
	return d.IsZero()
}

func (e *P256Scalar) sqr(x *P256Scalar, n int) {
	p256ScalarMul(&e.x, &x.x, &x.x)
	for i := 1; i < n; i++ {
		p256ScalarMul(&e.x, &e.x, &e.x)
	}
}

// Invert sets e = 1/t mod n, and returns e. If t == 0, Invert returns 0.
func (e *P256Scalar) Invert(t *P256Scalar) *P256Scalar {
	// Exponentiation by n - 2 (Fermat's little theorem) with the chain of 38
	// multiplications and 254 squarings from
	// https://briansmith.org/ecc-inversion-addition-chains-01#p256_scalar_inversion,
	// as in Go's p256_ordinv.go. Montgomery multiplication keeps values in
	// the domain, so the input and output need no conversion.
	// The chain's odd powers live in one table, indexed below, rather than
	// behind an array of pointers, which TinyGo could move to the heap.
	const (
		_1 = iota
		_11
		_101
		_111
		_1111
		_10101
		_101111
	)
	var p [7]P256Scalar
	var x, t2 P256Scalar
	p[_1].Set(t)
	x.sqr(&p[_1], 1)             // _10
	p[_11].Mul(&x, &p[_1])       // _11
	p[_101].Mul(&x, &p[_11])     // _101
	p[_111].Mul(&x, &p[_101])    // _111
	x.sqr(&p[_101], 1)           // _1010
	p[_1111].Mul(&p[_101], &x)   // _1111
	t2.sqr(&x, 1)                // _10100
	p[_10101].Mul(&t2, &p[_1])   // _10101
	x.sqr(&p[_10101], 1)         // _101010
	p[_101111].Mul(&p[_101], &x) // _101111
	x.Mul(&p[_10101], &x)        // _111111 = x6
	t2.sqr(&x, 2)                // _11111100
	t2.Mul(&t2, &p[_11])         // _11111111 = x8
	x.sqr(&t2, 8)                // _ff00
	x.Mul(&x, &t2)               // _ffff = x16
	t2.sqr(&x, 16)               // _ffff0000
	t2.Mul(&t2, &x)              // _ffffffff = x32

	x.sqr(&t2, 64)
	x.Mul(&x, &t2)
	x.sqr(&x, 32)
	x.Mul(&x, &t2)

	sqrs := [...]uint8{
		6, 5, 4, 5, 5,
		4, 3, 3, 5, 9,
		6, 2, 5, 6, 5,
		4, 5, 5, 3, 10,
		2, 5, 5, 3, 7, 6}
	muls := [...]uint8{
		_101111, _111, _11, _1111, _10101,
		_101, _101, _101, _111, _101111,
		_1111, _1, _1, _1111, _111,
		_111, _111, _101, _11, _101111,
		_11, _11, _11, _1, _10101, _1111}
	for i, s := range sqrs {
		x.sqr(&x, int(s))
		x.Mul(&x, &p[muls[i]])
	}
	return e.Set(&x)
}
