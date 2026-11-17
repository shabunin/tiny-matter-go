package fiat

import (
	"bytes"
	"math/big"
	"math/rand/v2"
	"testing"
)

// The field arithmetic, whichever backend is built (64-bit limbs, or 32-bit
// on 386/arm/mips; `GOARCH=386 go test` runs the latter), against math/big.

var (
	p, _ = new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	rInv = new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), 256), p)
)

func enc(v *big.Int) []byte { return v.FillBytes(make([]byte, 32)) }

func elem(t *testing.T, v *big.Int) *P256Element {
	t.Helper()
	e, err := new(P256Element).SetBytes(enc(v))
	if err != nil {
		t.Fatalf("SetBytes(%x): %v", v, err)
	}
	return e
}

func check(t *testing.T, op string, got *P256Element, want *big.Int, a, b *big.Int) {
	t.Helper()
	if w := enc(new(big.Int).Mod(want, p)); !bytes.Equal(got.Bytes(), w) {
		t.Fatalf("%s(%x, %x) = %x, want %x", op, a, b, got.Bytes(), w)
	}
}

// rnd makes the random values: seeded, so a failure can be reproduced
// (and the tests run where crypto/rand is missing).
var rnd = rand.New(rand.NewPCG(1, 2))

// values are edge cases around 0, p, the limb boundaries and powers of two,
// then random field elements.
func values(t *testing.T, random int) []*big.Int {
	one := big.NewInt(1)
	vs := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	for _, k := range []int{31, 32, 33, 63, 64, 65, 95, 96, 127, 128, 160, 191, 192, 223, 224, 254, 255} {
		x := new(big.Int).Lsh(one, uint(k))
		vs = append(vs, x, new(big.Int).Sub(x, one))
	}
	vs = append(vs, new(big.Int).Sub(p, one), new(big.Int).Sub(p, big.NewInt(2)),
		new(big.Int).Rsh(p, 1), new(big.Int).Add(new(big.Int).Rsh(p, 1), one))
	for i := 0; i < random; i++ {
		var b [32]byte
		for j := range b {
			b[j] = byte(rnd.Uint32())
		}
		vs = append(vs, new(big.Int).SetBytes(b[:]))
	}
	for _, v := range vs {
		v.Mod(v, p)
	}
	return vs
}

func TestP256FieldOps(t *testing.T) {
	vs := values(t, 40)
	for _, a := range vs {
		ea := elem(t, a)
		check(t, "Square", new(P256Element).Square(ea), new(big.Int).Mul(a, a), a, a)
		if a.Sign() != 0 {
			check(t, "Invert", new(P256Element).Invert(ea), new(big.Int).ModInverse(a, p), a, a)
		}
		if got, want := ea.IsZero(), a.Sign() == 0; (got == 1) != want {
			t.Fatalf("IsZero(%x) = %d", a, got)
		}
		for _, b := range vs {
			eb := elem(t, b)
			check(t, "Add", new(P256Element).Add(ea, eb), new(big.Int).Add(a, b), a, b)
			check(t, "Sub", new(P256Element).Sub(ea, eb), new(big.Int).Sub(a, b), a, b)
			check(t, "Mul", new(P256Element).Mul(ea, eb), new(big.Int).Mul(a, b), a, b)
			if got := ea.Equal(eb); (got == 1) != (a.Cmp(b) == 0) {
				t.Fatalf("Equal(%x, %x) = %d", a, b, got)
			}
			check(t, "Select1", new(P256Element).Select(ea, eb, 1), a, a, b)
			check(t, "Select0", new(P256Element).Select(ea, eb, 0), b, a, b)
		}
	}
}

func TestP256FieldEncoding(t *testing.T) {
	one := big.NewInt(1)
	for _, bad := range []*big.Int{p, new(big.Int).Add(p, one), new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)} {
		if _, err := new(P256Element).SetBytes(enc(bad)); err == nil {
			t.Fatalf("SetBytes accepted %x, not below p", bad)
		}
	}
	if _, err := new(P256Element).SetBytes(make([]byte, 31)); err == nil {
		t.Fatal("SetBytes accepted 31 bytes")
	}
	check(t, "One", new(P256Element).One(), one, one, one)
	// SetMontgomeryLimbs takes a Montgomery-domain value as 64-bit limbs
	// (the flash table's form): the element is l / 2^256 mod p.
	for _, l := range values(t, 200) {
		var limbs [4]uint64
		b := enc(l)
		for i := range limbs {
			for j := 0; j < 8; j++ {
				limbs[i] |= uint64(b[31-8*i-j]) << (8 * j)
			}
		}
		check(t, "SetMontgomeryLimbs", new(P256Element).SetMontgomeryLimbs(&limbs), new(big.Int).Mul(l, rInv), l, l)
	}
}
