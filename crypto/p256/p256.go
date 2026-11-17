// Package p256 provides the NIST P-256 operations Matter needs (ECDSA with
// SHA-256, ECDH, and raw point arithmetic for SPAKE2+), built on Go's
// constant-time fiat-crypto implementation vendored under crypto/internal.
//
// Unlike the standard library, every operation that needs randomness takes an
// explicit io.Reader, so it works on bare-metal TinyGo targets where the
// standard library's crypto ignores the caller's reader and reads the OS.
// Signatures are raw r||s (64 bytes), the encoding Matter uses on the wire and
// in Matter TLV certificates.
package p256

import (
	"errors"
	"io"
	"sync"

	"github.com/shabunin/tiny-matter-go/crypto/internal/bigmod"
	"github.com/shabunin/tiny-matter-go/crypto/internal/nistec"
	"github.com/shabunin/tiny-matter-go/crypto/internal/nistec/fiat"
)

const (
	// ScalarSize is the size of a private key or scalar in bytes.
	ScalarSize = 32
	// PointSize is the size of an uncompressed SEC 1 point (0x04 || X || Y).
	PointSize = 65
	// SignatureSize is the size of a raw r||s ECDSA signature.
	SignatureSize = 64
	// SharedSecretSize is the size of an ECDH shared secret (the X coordinate).
	SharedSecretSize = 32
)

var orderBytes = []byte{
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
	0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
}

var (
	orderOnce sync.Once
	order     *bigmod.Modulus
)

// n returns the group order as a bigmod.Modulus.
func n() *bigmod.Modulus {
	orderOnce.Do(func() {
		var err error
		order, err = bigmod.NewModulus(orderBytes)
		if err != nil {
			panic("p256: invalid order")
		}
	})
	return order
}

var (
	errInvalidScalar = errors.New("p256: invalid scalar")
	errInvalidKey    = errors.New("p256: invalid key")
)

// randomScalar returns a uniformly random non-zero scalar k and k*G, using
// rejection sampling over bytes produced by generate.
func randomScalar(generate func([]byte) error) (*fiat.P256Scalar, *nistec.P256Point, error) {
	var b [ScalarSize]byte
	for {
		if err := generate(b[:]); err != nil {
			return nil, nil, err
		}
		k, err := new(fiat.P256Scalar).SetBytes(b[:])
		if err == nil && k.IsZero() == 0 {
			p, err := nistec.NewP256Point().ScalarBaseMult(b[:])
			return k, p, err
		}
	}
}

func readFull(r io.Reader) func([]byte) error {
	return func(b []byte) error {
		if r == nil {
			return errors.New("p256: nil random source")
		}
		_, err := io.ReadFull(r, b)
		return err
	}
}

// SetYield installs f to be called periodically during scalar
// multiplications and modular exponentiations, so that on a cooperative
// scheduler other tasks (a radio controller, say) keep running during the
// tens to hundreds of milliseconds these take on a microcontroller. Nil
// removes it. It is not safe to change while computations run.
func SetYield(f func()) {
	nistec.Yield = f
	bigmod.Yield = f
}
