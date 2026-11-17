// Time tiny-matter-go/crypto/p256 on a real board (wall clock, printed to
// the serial console), e.g.
//
//	tinygo flash -target m5stack -monitor ./p256time
package main

import (
	"crypto/sha256"
	"runtime"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// NOT secure: a deterministic stand-in for a hardware TRNG, so runs are
// comparable.
type xr struct{ s uint32 }

func (x *xr) Read(b []byte) (int, error) {
	for i := range b {
		x.s = x.s*1664525 + 1013904223
		b[i] = byte(x.s >> 24)
	}
	return len(b), nil
}

func t(name string, n int, f func()) {
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	for i := 0; i < n; i++ {
		f()
	}
	d := time.Since(start)
	runtime.ReadMemStats(&m1)
	println(name, ":", d.Microseconds()/int64(n), "us each,", (m1.Mallocs-m0.Mallocs)/uint64(n), "allocs,",
		(m1.TotalAlloc-m0.TotalAlloc)/uint64(n), "bytes")
}

func main() {
	time.Sleep(2 * time.Second) // let the console attach
	rng := &xr{1}
	h := sha256.Sum256([]byte("hello"))
	var k *p256.PrivateKey
	t("GenerateKey", 5, func() { k, _ = p256.GenerateKey(rng) })
	var sig []byte
	t("Sign", 5, func() { sig, _ = k.Sign(rng, h[:]) })
	ok := false
	t("Verify", 5, func() { ok = k.PublicKey().Verify(h[:], sig) })
	println("verify ok:", ok)
	k2, _ := p256.GenerateKey(rng)
	var shared []byte
	t("ECDH", 5, func() { shared, _ = k.ECDH(k2.PublicKey()) })
	s, _ := p256.RandomScalar(rng)
	P := p256.Generator()
	var Q *p256.Point
	t("ScalarMult", 5, func() { Q, _ = p256.NewPoint().ScalarMult(P, s) })
	t("ScalarBaseMult", 5, func() { p256.NewPoint().ScalarBaseMult(s) })
	// Results, to compare backends: they must not change.
	println("sig", hexs(sig))
	println("ecdh", hexs(shared))
	println("Q", hexs(Q.Bytes()))
	println("done")
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}
