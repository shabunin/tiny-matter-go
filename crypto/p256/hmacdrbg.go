// Adapted from Go's crypto/internal/fips140/ecdsa/hmacdrbg.go.
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the crypto/internal/LICENSE-GO file.

package p256

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// hmacDRBG is an SP 800-90A Rev. 1 HMAC_DRBG with SHA-256, used to generate
// RFC 6979 (optionally hedged) ECDSA nonces. It is not a general-purpose DRBG.
type hmacDRBG struct {
	hK hash.Hash
	V  []byte
}

type plainPersonalizationString []byte

func (plainPersonalizationString) isPersonalizationString() {}

// blockAlignedPersonalizationString is a personalization string made of
// fields, each zero-padded to the HMAC block size, as in
// draft-irtf-cfrg-det-sigs-with-noise-04, Section 4.
type blockAlignedPersonalizationString [][]byte

func (blockAlignedPersonalizationString) isPersonalizationString() {}

type personalizationString interface {
	isPersonalizationString()
}

func newDRBG(entropy, nonce []byte, s personalizationString) *hmacDRBG {
	const size = sha256.Size
	d := &hmacDRBG{V: make([]byte, size)}
	for i := range d.V {
		d.V[i] = 0x01
	}
	K := make([]byte, size)

	update := func(sep byte) {
		h := hmac.New(sha256.New, K)
		h.Write(d.V)
		h.Write([]byte{sep})
		h.Write(entropy)
		h.Write(nonce)
		switch s := s.(type) {
		case plainPersonalizationString:
			h.Write(s)
		case blockAlignedPersonalizationString:
			l := len(d.V) + 1 + len(entropy) + len(nonce)
			for _, b := range s {
				pad000(h, l)
				h.Write(b)
				l = len(b)
			}
		}
		K = h.Sum(K[:0])
		h = hmac.New(sha256.New, K)
		h.Write(d.V)
		d.V = h.Sum(d.V[:0])
		d.hK = h
	}
	update(0x00)
	update(0x01)
	return d
}

func pad000(h hash.Hash, writtenSoFar int) {
	blockSize := h.BlockSize()
	if rem := writtenSoFar % blockSize; rem != 0 {
		h.Write(make([]byte, blockSize-rem))
	}
}

// Generate produces at most maxRequestSize bytes of random data in out.
func (d *hmacDRBG) Generate(out []byte) {
	tlen := 0
	for tlen < len(out) {
		d.hK.Reset()
		d.hK.Write(d.V)
		d.V = d.hK.Sum(d.V[:0])
		tlen += copy(out[tlen:], d.V)
	}
	d.hK.Reset()
	d.hK.Write(d.V)
	d.hK.Write([]byte{0x00})
	K := d.hK.Sum(nil)
	d.hK = hmac.New(sha256.New, K)
	d.hK.Write(d.V)
	d.V = d.hK.Sum(d.V[:0])
}
