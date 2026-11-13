// Benchmark Matter crypto primitives on emulated Cortex-M (QEMU -icount shift=0):
// SysTick fires every 1M executed instructions, so "Minsn" = millions of instructions.
package main

import (
	"crypto/aes"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"device/arm"
	"math/big"
	"runtime/volatile"
)

var mi volatile.Register32

//export SysTick_Handler
func sysTick() { mi.Set(mi.Get() + 1) }

func t(name string, n int, f func()) {
	s := mi.Get()
	for i := 0; i < n; i++ {
		f()
	}
	d := mi.Get() - s
	println(name, "x", n, ":", d, "Minsn total,", d*1000/uint32(n), "Kinsn each")
}

func main() {
	arm.SYST.SYST_RVR.Set(25000 - 1) // mps2 sysclk 25 MHz -> 1 ms virtual = 1M insns with icount shift=0
	arm.SYST.SYST_CVR.Set(0)
	arm.SYST.SYST_CSR.Set(7)
	buf := make([]byte, 1024)
	t("sha256-1KB", 100, func() { sha256.Sum256(buf) })
	t("hmac-sha256-64B", 100, func() { m := hmac.New(sha256.New, buf[:32]); m.Write(buf[:64]); m.Sum(nil) })
	t("hkdf-48B", 100, func() { hkdf.Key(sha256.New, buf[:32], nil, "SessionKeys", 48) })
	t("pbkdf2-1000it", 1, func() { pbkdf2.Key(sha256.New, "20202021", buf[:16], 1000, 80) })
	b, _ := aes.NewCipher(buf[:16])
	t("aes128-block", 1000, func() { b.Encrypt(buf[:16], buf[:16]) })
	c := elliptic.P256()
	h := sha256.Sum256(buf)
	k := new(big.Int).SetBytes(h[:]).Bytes()
	x, y := c.ScalarBaseMult(k)
	t("p256-ScalarBaseMult", 5, func() { c.ScalarBaseMult(k) })
	t("p256-ScalarMult", 5, func() { c.ScalarMult(x, y, k) })
	t("p256-Add", 50, func() { c.Add(x, y, x, y) })
	println("done")
}
