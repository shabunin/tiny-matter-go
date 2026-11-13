// Probe: exercise every crypto primitive Matter needs, using only stdlib.
//
//go:debug cryptocustomrand=1
package main

import (
	"crypto/aes"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"math/big"
	"time"
)

func t(name string, f func()) {
	s := time.Now()
	f()
	println(name, time.Since(s).Milliseconds(), "ms")
}

func main() {
	println("start")
	msg := []byte("matter probe")
	t("sha256", func() { sha256.Sum256(msg) })
	t("hmac", func() { m := hmac.New(sha256.New, msg); m.Write(msg); m.Sum(nil) })
	t("hkdf", func() { _, err := hkdf.Key(sha256.New, msg, nil, "SessionKeys", 48); chk(err) })
	t("pbkdf2-1000", func() { _, err := pbkdf2.Key(sha256.New, "20202021", msg, 1000, 80); chk(err) })
	t("aes-block", func() { b, err := aes.NewCipher(make([]byte, 16)); chk(err); o := make([]byte, 16); b.Encrypt(o, o) })

	h := sha256.Sum256(msg)
	// SPAKE2+ needs raw point mult/add (X = x*G + w0*M)
	t("spake-pointops", func() {
		c := elliptic.P256()
		k := new(big.Int).SetBytes(h[:]).Bytes()
		x1, y1 := c.ScalarBaseMult(k)
		x2, y2 := c.ScalarMult(x1, y1, k)
		c.Add(x1, y1, x2, y2)
		for i := 0; i < 9; i++ {
			c.ScalarMult(x1, y1, k)
		}
	})
	println("done")
}

func chk(err error) {
	if err != nil {
		panic(err.Error())
	}
}

// stub RNG for the emulator (NOT secure) — real targets need a HW TRNG driver
type xr struct{ s uint32 }

func (x *xr) Read(b []byte) (int, error) {
	for i := range b {
		x.s = x.s*1664525 + 1013904223
		b[i] = byte(x.s >> 24)
	}
	return len(b), nil
}

var rand = struct{ Reader *xr }{&xr{1}}
