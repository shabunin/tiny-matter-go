// Portions adapted from Go's crypto/internal/fips140/ecdsa.
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the crypto/internal/LICENSE-GO file.

package p256

import (
	"crypto/sha256"
	"errors"
	"io"

	"tinymatter/crypto/internal/bigmod"
	"tinymatter/crypto/internal/nistec"
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
	e := bigmod.NewNat()
	hashToNat(e, digest)
	return e.Bytes(n())
}

func sign(k *PrivateKey, drbg *hmacDRBG, digest []byte) ([]byte, error) {
	N := n()
	kk, R, err := randomScalar(func(b []byte) error {
		drbg.Generate(b)
		return nil
	})
	if err != nil {
		return nil, err
	}

	kInv := bigmod.NewNat().Exp(kk, nMinus2, N)

	Rx, err := R.BytesX()
	if err != nil {
		return nil, err
	}
	r, err := bigmod.NewNat().SetOverflowingBytes(Rx, N)
	if err != nil {
		return nil, err
	}
	if r.IsZero() == 1 {
		return nil, errors.New("p256: internal error: r is zero")
	}

	e := bigmod.NewNat()
	hashToNat(e, digest)

	s, err := bigmod.NewNat().SetBytes(k.d[:], N)
	if err != nil {
		return nil, err
	}
	s.Mul(r, N)
	s.Add(e, N)
	s.Mul(kInv, N)
	if s.IsZero() == 1 {
		return nil, errors.New("p256: internal error: s is zero")
	}

	sig := make([]byte, 0, SignatureSize)
	sig = append(sig, r.Bytes(N)...)
	return append(sig, s.Bytes(N)...), nil
}

func verify(pub *PublicKey, digest, sig []byte) error {
	if len(sig) != SignatureSize {
		return errors.New("p256: invalid signature length")
	}
	N := n()
	Q, err := nistec.NewP256Point().SetBytes(pub.q[:])
	if err != nil {
		return err
	}
	r, err := bigmod.NewNat().SetBytes(sig[:ScalarSize], N)
	if err != nil || r.IsZero() == 1 {
		return errors.New("p256: invalid signature")
	}
	s, err := bigmod.NewNat().SetBytes(sig[ScalarSize:], N)
	if err != nil || s.IsZero() == 1 {
		return errors.New("p256: invalid signature")
	}

	e := bigmod.NewNat()
	hashToNat(e, digest)

	w := bigmod.NewNat().Exp(s, nMinus2, N)

	p1, err := nistec.NewP256Point().ScalarBaseMult(e.Mul(w, N).Bytes(N))
	if err != nil {
		return err
	}
	p2, err := Q.ScalarMult(Q, w.Mul(r, N).Bytes(N))
	if err != nil {
		return err
	}
	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return err
	}
	v, err := bigmod.NewNat().SetOverflowingBytes(Rx, N)
	if err != nil {
		return err
	}
	if v.Equal(r) != 1 {
		return errors.New("p256: signature did not verify")
	}
	return nil
}

// hashToNat sets e to the left-most bits of hash, as specified in SEC 1,
// Section 4.1.3, Step 5 and Section 4.1.4, Step 3. For P-256 the order is
// exactly 256 bits, so no bit shifting is needed.
func hashToNat(e *bigmod.Nat, hash []byte) {
	if len(hash) > ScalarSize {
		hash = hash[:ScalarSize]
	}
	if _, err := e.SetOverflowingBytes(hash, n()); err != nil {
		panic("p256: internal error: truncated hash is too long")
	}
}
