// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

package nistec

import "crypto/subtle"

// p256SelectBase sets p to the n-th multiple (1-based) stored in base table
// t, in constant time. Like p256AffineTable.Select, p is undefined if n is 0.
// It replaces upstream's unsafe aliasing of the table bytes so the table can
// live in flash on microcontrollers.
func p256SelectBase(p *p256AffinePoint, t int, n uint8) {
	if n > 32 {
		panic("nistec: internal error: p256SelectBase called with out-of-bounds value")
	}
	var x, y [4]uint64
	base := t * 32 * 8
	for i := uint8(1); i <= 32; i++ {
		mask := -uint64(subtle.ConstantTimeByteEq(i, n))
		e := p256Precomputed[base+int(i-1)*8 : base+int(i)*8]
		x[0] |= e[0] & mask
		x[1] |= e[1] & mask
		x[2] |= e[2] & mask
		x[3] |= e[3] & mask
		y[0] |= e[4] & mask
		y[1] |= e[5] & mask
		y[2] |= e[6] & mask
		y[3] |= e[7] & mask
	}
	p.x.SetMontgomeryLimbs(&x)
	p.y.SetMontgomeryLimbs(&y)
}
