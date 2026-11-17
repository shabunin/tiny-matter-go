package fiat

import (
	"bytes"
	"math/big"
	"testing"
)

var n, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// scalarValues are 256-bit values, not necessarily below n: edge cases
// around 0, n, 2^256 and the limb boundaries, then random ones.
func scalarValues(random int) []*big.Int {
	one := big.NewInt(1)
	two256 := new(big.Int).Lsh(one, 256)
	vs := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3),
		new(big.Int).Sub(n, one), new(big.Int).Sub(n, big.NewInt(2)), n,
		new(big.Int).Add(n, one), new(big.Int).Sub(two256, one), new(big.Int).Sub(two256, n),
		new(big.Int).Rsh(n, 1)}
	for _, k := range []int{32, 63, 64, 65, 127, 128, 192, 224, 255} {
		x := new(big.Int).Lsh(one, uint(k))
		vs = append(vs, x, new(big.Int).Sub(x, one))
	}
	for i := 0; i < random; i++ {
		var b [32]byte
		for j := range b {
			b[j] = byte(rnd.Uint32())
		}
		vs = append(vs, new(big.Int).SetBytes(b[:]))
	}
	return vs
}

func scalar(t *testing.T, v *big.Int) *P256Scalar {
	t.Helper()
	b := [32]byte(enc(new(big.Int).Mod(v, n)))
	return new(P256Scalar).SetReducedBytes(&b)
}

func checkScalar(t *testing.T, op string, got *P256Scalar, want *big.Int, a, b *big.Int) {
	t.Helper()
	w := enc(new(big.Int).Mod(want, n))
	if g := got.Bytes(); !bytes.Equal(g[:], w) {
		t.Fatalf("%s(%x, %x) = %x, want %x", op, a, b, g, w)
	}
}

func TestP256ScalarEncoding(t *testing.T) {
	for _, v := range scalarValues(200) {
		b := [32]byte(enc(v))
		checkScalar(t, "SetReducedBytes", new(P256Scalar).SetReducedBytes(&b), v, v, v)
		s, err := new(P256Scalar).SetBytes(b[:])
		if below := v.Cmp(n) < 0; below != (err == nil) {
			t.Fatalf("SetBytes(%x): err %v", v, err)
		} else if below {
			checkScalar(t, "SetBytes", s, v, v, v)
		}
	}
	if _, err := new(P256Scalar).SetBytes(make([]byte, 31)); err == nil {
		t.Fatal("SetBytes accepted 31 bytes")
	}
	var zero P256Scalar
	if zero.IsZero() != 1 || zero.Bytes() != [32]byte{} {
		t.Fatal("zero value is not 0")
	}
}

func TestP256ScalarOps(t *testing.T) {
	vs := scalarValues(40)
	for _, a := range vs {
		sa := scalar(t, a)
		am := new(big.Int).Mod(a, n)
		if got := sa.IsZero(); (got == 1) != (am.Sign() == 0) {
			t.Fatalf("IsZero(%x) = %d", a, got)
		}
		if am.Sign() != 0 {
			checkScalar(t, "Invert", new(P256Scalar).Invert(sa), new(big.Int).ModInverse(am, n), a, a)
		} else if new(P256Scalar).Invert(sa).IsZero() != 1 {
			t.Fatal("Invert(0) != 0")
		}
		inPlace := new(P256Scalar).Set(sa)
		checkScalar(t, "Invert in place", inPlace.Invert(inPlace), new(P256Scalar).Invert(sa).bigInt(), a, a)
		for _, b := range vs {
			sb := scalar(t, b)
			bm := new(big.Int).Mod(b, n)
			checkScalar(t, "Add", new(P256Scalar).Add(sa, sb), new(big.Int).Add(a, b), a, b)
			checkScalar(t, "Mul", new(P256Scalar).Mul(sa, sb), new(big.Int).Mul(a, b), a, b)
			if got := sa.Equal(sb); (got == 1) != (am.Cmp(bm) == 0) {
				t.Fatalf("Equal(%x, %x) = %d", a, b, got)
			}
		}
	}
}

func (e *P256Scalar) bigInt() *big.Int {
	b := e.Bytes()
	return new(big.Int).SetBytes(b[:])
}
