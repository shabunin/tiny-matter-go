// Portions adapted from Go's crypto/internal/fips140/ecdsa.
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the crypto/internal/LICENSE-GO file.

package p256

import (
	"crypto/sha256"
	"errors"
	"io"

	"github.com/shabunin/tiny-matter-go/crypto/internal/nistec"
	"github.com/shabunin/tiny-matter-go/crypto/internal/nistec/fiat"
)

// Sign signs digest (normally a SHA-256 hash) and returns a raw r||s
// signature.
//
// The nonce is hedged as in Go's crypto/ecdsa: it is derived from the key and
// digest per RFC 6979 and mixed with 32 bytes from rand, so a weak or
// repeating random source does not leak the key.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	var Z [ScalarSize]byte
	if err := readFull(rand)(Z[:]); err != nil {
		return nil, err
	}
	drbg := newDRBG(Z[:], nil, blockAlignedPersonalizationString{k.d[:], bits2octets(digest)})
	return sign(k, drbg, digest)
}

// SignDeterministic signs digest with a deterministic RFC 6979 nonce. It is
// mostly useful for tests against known vectors.
func (k *PrivateKey) SignDeterministic(digest []byte) ([]byte, error) {
	drbg := newDRBG(k.d[:], bits2octets(digest), nil)
	return sign(k, drbg, digest)
}

// SignMessage hashes msg with SHA-256 and signs it, as Matter's
// Crypto_Sign does.
func (k *PrivateKey) SignMessage(rand io.Reader, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return k.Sign(rand, h[:])
}

// Verify reports whether sig is a valid raw r||s signature of digest.
func (k *PublicKey) Verify(digest, sig []byte) bool {
	return verify(k, digest, sig) == nil
}

// VerifyMessage hashes msg with SHA-256 and verifies sig, as Matter's
// Crypto_Verify does.
func (k *PublicKey) VerifyMessage(msg, sig []byte) bool {
	h := sha256.Sum256(msg)
	return k.Verify(h[:], sig)
}

func bits2octets(digest []byte) []byte {
	e := hashToScalar(digest).Bytes()
	return e[:]
}

// The scalar arithmetic below is fiat.P256Scalar's: fixed size and free of
// heap allocations, which bigmod makes on TinyGo for every multiplication.

func sign(k *PrivateKey, drbg *hmacDRBG, digest []byte) ([]byte, error) {
	kk, R, err := randomScalar(func(b []byte) error {
		drbg.Generate(b)
		return nil
	})
	if err != nil {
		return nil, err
	}

	kInv := new(fiat.P256Scalar).Invert(kk)

	Rx, err := R.BytesX()
	if err != nil {
		return nil, err
	}
	r := new(fiat.P256Scalar).SetReducedBytes((*[ScalarSize]byte)(Rx))
	if r.IsZero() == 1 {
		return nil, errors.New("p256: internal error: r is zero")
	}

	e := hashToScalar(digest)

	s, err := new(fiat.P256Scalar).SetBytes(k.d[:])
	if err != nil {
		return nil, err
	}
	s.Mul(s, r)
	s.Add(s, e)
	s.Mul(s, kInv)
	if s.IsZero() == 1 {
		return nil, errors.New("p256: internal error: s is zero")
	}

	rb, sb := r.Bytes(), s.Bytes()
	sig := make([]byte, 0, SignatureSize)
	sig = append(sig, rb[:]...)
	return append(sig, sb[:]...), nil
}

func verify(pub *PublicKey, digest, sig []byte) error {
	if len(sig) != SignatureSize {
		return errors.New("p256: invalid signature length")
	}
	Q, err := nistec.NewP256Point().SetBytes(pub.q[:])
	if err != nil {
		return err
	}
	r, err := new(fiat.P256Scalar).SetBytes(sig[:ScalarSize])
	if err != nil || r.IsZero() == 1 {
		return errors.New("p256: invalid signature")
	}
	s, err := new(fiat.P256Scalar).SetBytes(sig[ScalarSize:])
	if err != nil || s.IsZero() == 1 {
		return errors.New("p256: invalid signature")
	}

	e := hashToScalar(digest)

	w := new(fiat.P256Scalar).Invert(s)

	u1 := new(fiat.P256Scalar).Mul(e, w).Bytes()
	p1, err := nistec.NewP256Point().ScalarBaseMult(u1[:])
	if err != nil {
		return err
	}
	u2 := new(fiat.P256Scalar).Mul(r, w).Bytes()
	p2, err := Q.ScalarMult(Q, u2[:])
	if err != nil {
		return err
	}
	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return err
	}
	v := new(fiat.P256Scalar).SetReducedBytes((*[ScalarSize]byte)(Rx))
	if v.Equal(r) != 1 {
		return errors.New("p256: signature did not verify")
	}
	return nil
}

// hashToScalar returns the left-most bits of hash as a scalar, as specified
// in SEC 1, Section 4.1.3, Step 5 and Section 4.1.4, Step 3. For P-256 the
// order is exactly 256 bits, so no bit shifting is needed, and a 256-bit
// value is below 2n, so one reduction suffices.
func hashToScalar(hash []byte) *fiat.P256Scalar {
	if len(hash) > ScalarSize {
		hash = hash[:ScalarSize]
	}
	var b [ScalarSize]byte
	copy(b[ScalarSize-len(hash):], hash)
	return new(fiat.P256Scalar).SetReducedBytes(&b)
}
