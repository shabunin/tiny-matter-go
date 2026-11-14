package p256

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 6979, Appendix A.2.5 (P-256, SHA-256).
func TestRFC6979(t *testing.T) {
	priv, err := NewPrivateKey(unhex(t, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"))
	if err != nil {
		t.Fatal(err)
	}
	wantPub := "04" + "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" +
		"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	if got := priv.PublicKey().Bytes(); !bytes.Equal(got, unhex(t, wantPub)) {
		t.Fatalf("public key = %x", got)
	}
	for _, tc := range []struct{ msg, r, s string }{
		{"sample",
			"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"},
		{"test",
			"F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"},
	} {
		h := sha256.Sum256([]byte(tc.msg))
		sig, err := priv.SignDeterministic(h[:])
		if err != nil {
			t.Fatal(err)
		}
		if want := unhex(t, tc.r+tc.s); !bytes.Equal(sig, want) {
			t.Errorf("%s: sig = %x, want %x", tc.msg, sig, want)
		}
		if !priv.PublicKey().Verify(h[:], sig) {
			t.Errorf("%s: own signature does not verify", tc.msg)
		}
	}
}

func stdKey(t *testing.T, k *PrivateKey) *ecdsa.PrivateKey {
	t.Helper()
	sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestECDSAInterop(t *testing.T) {
	for i := 0; i < 20; i++ {
		k, err := GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sk := stdKey(t, k)
		pub, _ := sk.PublicKey.Bytes()
		if !bytes.Equal(pub, k.PublicKey().Bytes()) {
			t.Fatal("public key mismatch with stdlib")
		}
		msg := []byte{byte(i), 'm', 's', 'g'}
		h := sha256.Sum256(msg)

		// ours -> stdlib
		sig, err := k.SignMessage(rand.Reader, msg)
		if err != nil {
			t.Fatal(err)
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(&sk.PublicKey, h[:], r, s) {
			t.Fatal("stdlib rejects our signature")
		}
		// stdlib -> ours
		r, s, err = ecdsa.Sign(rand.Reader, sk, h[:])
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		if !k.PublicKey().VerifyMessage(msg, raw) {
			t.Fatal("we reject stdlib signature")
		}
		raw[10] ^= 1
		if k.PublicKey().VerifyMessage(msg, raw) {
			t.Fatal("tampered signature verified")
		}
	}
}

func TestECDHInterop(t *testing.T) {
	a, _ := GenerateKey(rand.Reader)
	b, _ := ecdh.P256().GenerateKey(rand.Reader)
	bPub, err := NewPublicKey(b.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ours, err := a.ECDH(bPub)
	if err != nil {
		t.Fatal(err)
	}
	aStd, _ := ecdh.P256().NewPrivateKey(a.Bytes())
	theirs, _ := b.ECDH(aStd.PublicKey())
	if !bytes.Equal(ours, theirs) {
		t.Fatalf("ECDH mismatch: %x vs %x", ours, theirs)
	}
}

func TestPointOps(t *testing.T) {
	c := elliptic.P256()
	k1, _ := RandomScalar(rand.Reader)
	k2, _ := RandomScalar(rand.Reader)

	P, err := NewPoint().ScalarBaseMult(k1)
	if err != nil {
		t.Fatal(err)
	}
	x1, y1 := c.ScalarBaseMult(k1)
	if !bytes.Equal(P.Bytes(), elliptic.Marshal(c, x1, y1)) {
		t.Fatal("ScalarBaseMult mismatch")
	}
	Q, _ := NewPoint().ScalarMult(P, k2)
	x2, y2 := c.ScalarMult(x1, y1, k2)
	if !bytes.Equal(Q.Bytes(), elliptic.Marshal(c, x2, y2)) {
		t.Fatal("ScalarMult mismatch")
	}
	S := NewPoint().Add(P, Q)
	x3, y3 := c.Add(x1, y1, x2, y2)
	if !bytes.Equal(S.Bytes(), elliptic.Marshal(c, x3, y3)) {
		t.Fatal("Add mismatch")
	}
	// P + (-P) = infinity, and Q + (-P) + P = Q
	if got := NewPoint().Add(P, NewPoint().Negate(P)).Bytes(); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("P - P = %x", got)
	}
	R := NewPoint().Add(Q, NewPoint().Negate(P))
	if !bytes.Equal(R.Add(R, P).Bytes(), Q.Bytes()) {
		t.Fatal("Negate mismatch")
	}
	if g := Generator().Bytes(); !bytes.Equal(g, elliptic.Marshal(c, c.Params().Gx, c.Params().Gy)) {
		t.Fatal("generator mismatch")
	}
	bad := P.Bytes()
	bad[64] ^= 1
	if _, err := NewPoint().SetBytes(bad); err == nil {
		t.Fatal("off-curve point accepted")
	}
	if _, err := NewPublicKey(bad); err == nil {
		t.Fatal("off-curve public key accepted")
	}
}

func TestReduceScalar(t *testing.T) {
	N := elliptic.P256().Params().N
	for _, size := range []int{1, 31, 32, 33, 40, 64} {
		b := make([]byte, size)
		rand.Read(b)
		b[0] |= 0x80
		want := new(big.Int).Mod(new(big.Int).SetBytes(b), N).FillBytes(make([]byte, 32))
		if got := ReduceScalar(b); !bytes.Equal(got, want) {
			t.Errorf("size %d: got %x want %x", size, got, want)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

// A broken RNG must not make signatures repeat nonces across messages
// (the nonce is hedged with the key and digest).
func TestHedgedNonceWithBadRNG(t *testing.T) {
	k, _ := GenerateKey(rand.Reader)
	s1, _ := k.SignMessage(zeroReader{}, []byte("a"))
	s2, _ := k.SignMessage(zeroReader{}, []byte("b"))
	if bytes.Equal(s1[:32], s2[:32]) {
		t.Fatal("nonce reuse with constant RNG")
	}
}

func BenchmarkSign(b *testing.B) {
	k, _ := GenerateKey(rand.Reader)
	h := sha256.Sum256(nil)
	for b.Loop() {
		k.Sign(rand.Reader, h[:])
	}
}

func BenchmarkVerify(b *testing.B) {
	k, _ := GenerateKey(rand.Reader)
	h := sha256.Sum256(nil)
	sig, _ := k.Sign(rand.Reader, h[:])
	for b.Loop() {
		k.PublicKey().Verify(h[:], sig)
	}
}

func TestYield(t *testing.T) {
	n := 0
	SetYield(func() { n++ })
	defer SetYield(nil)
	k, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if n < 40 {
		t.Fatalf("ScalarBaseMult yielded %d times", n)
	}
	n = 0
	sig, _ := k.SignMessage(rand.Reader, []byte("m"))
	if !k.PublicKey().VerifyMessage([]byte("m"), sig) || n < 100 {
		t.Fatalf("sign+verify yielded %d times", n)
	}
}
