package p256

import (
	"errors"
	"io"

	"github.com/shabunin/tiny-matter-go/crypto/internal/bigmod"
	"github.com/shabunin/tiny-matter-go/crypto/internal/nistec"
)

// PrivateKey is a P-256 private key, usable for both ECDSA and ECDH.
type PrivateKey struct {
	d   [ScalarSize]byte
	pub PublicKey
}

// PublicKey is a validated P-256 public key.
type PublicKey struct {
	q [PointSize]byte
}

// GenerateKey returns a new private key using randomness from rand.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	k, Q, err := randomScalar(readFull(rand))
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{}
	copy(priv.d[:], k.Bytes(n()))
	copy(priv.pub.q[:], Q.Bytes())
	return priv, nil
}

// NewPrivateKey returns the private key with the 32-byte big-endian scalar d,
// computing its public key.
func NewPrivateKey(d []byte) (*PrivateKey, error) {
	if len(d) != ScalarSize {
		return nil, errInvalidKey
	}
	k, err := bigmod.NewNat().SetBytes(d, n())
	if err != nil || k.IsZero() == 1 {
		return nil, errInvalidKey
	}
	Q, err := nistec.NewP256Point().ScalarBaseMult(d)
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{}
	copy(priv.d[:], d)
	copy(priv.pub.q[:], Q.Bytes())
	return priv, nil
}

// NewPublicKey parses and validates an uncompressed SEC 1 point.
func NewPublicKey(q []byte) (*PublicKey, error) {
	if len(q) != PointSize || q[0] != 4 {
		return nil, errInvalidKey
	}
	if _, err := nistec.NewP256Point().SetBytes(q); err != nil {
		return nil, errInvalidKey
	}
	pub := &PublicKey{}
	copy(pub.q[:], q)
	return pub, nil
}

// Bytes returns the 32-byte big-endian private scalar.
func (k *PrivateKey) Bytes() []byte { b := k.d; return b[:] }

// PublicKey returns the public key of k.
func (k *PrivateKey) PublicKey() *PublicKey { return &k.pub }

// Bytes returns the 65-byte uncompressed encoding of the public key.
func (k *PublicKey) Bytes() []byte { b := k.q; return b[:] }

// Equal reports whether k and x are the same public key.
func (k *PublicKey) Equal(x *PublicKey) bool { return k.q == x.q }

// ECDH returns the X coordinate of k*peer, the Matter (and SEC 1) shared
// secret.
func (k *PrivateKey) ECDH(peer *PublicKey) ([]byte, error) {
	p, err := nistec.NewP256Point().SetBytes(peer.q[:])
	if err != nil {
		return nil, err
	}
	if _, err := p.ScalarMult(p, k.d[:]); err != nil {
		return nil, err
	}
	x, err := p.BytesX()
	if err != nil {
		return nil, errors.New("p256: ECDH result is the point at infinity")
	}
	return x, nil
}
