// Benchmark tinymatter/crypto/p256 on emulated Cortex-M (QEMU -icount shift=0):
// SysTick fires every 1M executed instructions.
package main

import (
	"crypto/sha256"
	"device/arm"
	"runtime/volatile"

	"tinymatter/crypto/p256"
)

var mi volatile.Register32

//export SysTick_Handler
func sysTick() { mi.Set(mi.Get() + 1) }

// NOT secure: deterministic stand-in for a hardware TRNG in the emulator.
type xr struct{ s uint32 }

func (x *xr) Read(b []byte) (int, error) {
	for i := range b {
		x.s = x.s*1664525 + 1013904223
		b[i] = byte(x.s >> 24)
	}
	return len(b), nil
}

func t(name string, n int, f func()) {
	s := mi.Get()
	for i := 0; i < n; i++ {
		f()
	}
	d := mi.Get() - s
	println(name, "x", n, ":", d*1000/uint32(n), "Kinsn each")
}

func main() {
	arm.SYST.SYST_RVR.Set(25000 - 1)
	arm.SYST.SYST_CVR.Set(0)
	arm.SYST.SYST_CSR.Set(7)
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
	t("ECDH", 5, func() { k.ECDH(k2.PublicKey()) })
	s, _ := p256.RandomScalar(rng)
	P := p256.Generator()
	t("ScalarMult", 5, func() { p256.NewPoint().ScalarMult(P, s) })
	t("ScalarBaseMult", 5, func() { p256.NewPoint().ScalarBaseMult(s) })
	println("done")
}
