package casesession

import (
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/shabunin/tiny-matter-go/crypto/ccm"
)

var (
	ErrNoFabric   = errors.New("case: no fabric matches the destination")
	ErrSignature  = errors.New("case: peer signature invalid")
	ErrPeerCert   = errors.New("case: peer certificate invalid")
	ErrDecrypt    = errors.New("case: decryption failed")
	ErrUnexpected = errors.New("case: unexpected message")
)

// transcript accumulates the SHA-256 of the Sigma messages.
type transcript struct{ h hash.Hash }

func newTranscript() *transcript { return &transcript{h: sha256.New()} }

func (t *transcript) add(b []byte) { t.h.Write(b) }

func (t *transcript) sum() []byte { return t.h.Sum(nil) }

func seal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := ccm.New(block, len(nonce), micSize)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func open(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := ccm.New(block, len(nonce), micSize)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func cat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
