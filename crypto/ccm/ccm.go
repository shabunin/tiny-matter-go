// Package ccm implements the CCM authenticated encryption mode
// (NIST SP 800-38C, RFC 3610) as a cipher.AEAD.
//
// Matter uses AES-128-CCM with a 13-byte nonce and a 16-byte tag for message
// encryption (Crypto_AEAD_GenerateEncrypt), and the same primitive appears in
// session establishment. The standard library has no CCM.
package ccm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
	"unsafe"
)

const blockSize = 16

type ccm struct {
	b         cipher.Block
	nonceSize int
	tagSize   int

	// Scratch blocks. Passing stack arrays to the cipher.Block interface
	// makes them escape, which would cost several heap allocations per
	// message on TinyGo; mu keeps the AEAD safe for concurrent use.
	mu              sync.Mutex
	x, s0, ctrb, ks [blockSize]byte
}

// New returns a CCM AEAD over the 16-byte block cipher b. nonceSize must be
// in [7, 13] and tagSize must be even and in [4, 16].
func New(b cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if b.BlockSize() != blockSize {
		return nil, errors.New("ccm: block size must be 16 bytes")
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, errors.New("ccm: invalid nonce size")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errors.New("ccm: invalid tag size")
	}
	return &ccm{b: b, nonceSize: nonceSize, tagSize: tagSize}, nil
}

func (c *ccm) NonceSize() int { return c.nonceSize }
func (c *ccm) Overhead() int  { return c.tagSize }

// maxLen returns the largest payload length encodable in the length field.
func (c *ccm) maxLen() uint64 {
	q := 15 - c.nonceSize
	if q >= 8 {
		return ^uint64(0)
	}
	return 1<<(8*q) - 1
}

// mac computes the raw CBC-MAC tag T (before encryption with S0) over the
// formatted B0, associated data and plaintext, leaving it in c.x.
func (c *ccm) mac(nonce, plaintext, aad []byte) {
	q := 15 - c.nonceSize
	x := &c.x
	clear(x[:])

	// B0: flags || N || Q
	x[0] = byte(q - 1)
	x[0] |= byte((c.tagSize-2)/2) << 3
	if len(aad) > 0 {
		x[0] |= 0x40
	}
	copy(x[1:], nonce)
	l := uint64(len(plaintext))
	for i := blockSize - 1; i > c.nonceSize; i-- {
		x[i] = byte(l)
		l >>= 8
	}
	c.b.Encrypt(x[:], x[:])

	if len(aad) > 0 {
		// Length prefix of the associated data, then the data, zero padded.
		var hdr [10]byte
		var n int
		a := uint64(len(aad))
		switch {
		case a < 0xFF00:
			binary.BigEndian.PutUint16(hdr[:], uint16(a))
			n = 2
		case a <= 0xFFFFFFFF:
			hdr[0], hdr[1] = 0xFF, 0xFE
			binary.BigEndian.PutUint32(hdr[2:], uint32(a))
			n = 6
		default:
			hdr[0], hdr[1] = 0xFF, 0xFF
			binary.BigEndian.PutUint64(hdr[2:], a)
			n = 10
		}
		pos := 0
		pos = c.absorb(x, pos, hdr[:n])
		pos = c.absorb(x, pos, aad)
		if pos != 0 {
			c.b.Encrypt(x[:], x[:])
		}
	}
	if c.absorb(x, 0, plaintext) != 0 {
		c.b.Encrypt(x[:], x[:])
	}
}

// absorb XORs data into the CBC-MAC state starting at offset pos within the
// current block, encrypting each completed block, and returns the new offset.
func (c *ccm) absorb(x *[blockSize]byte, pos int, data []byte) int {
	for _, b := range data {
		x[pos] ^= b
		pos++
		if pos == blockSize {
			c.b.Encrypt(x[:], x[:])
			pos = 0
		}
	}
	return pos
}

// ctr XORs src with the CCM keystream starting at counter block 1 into dst,
// and leaves S0, the keystream block for counter 0 that masks the tag, in
// c.s0.
func (c *ccm) ctr(dst, src, nonce []byte) {
	ctr, ks := &c.ctrb, &c.ks
	clear(ctr[:])
	ctr[0] = byte(14 - c.nonceSize) // q - 1
	copy(ctr[1:], nonce)
	c.b.Encrypt(c.s0[:], ctr[:])
	for len(src) > 0 {
		// Increment the big-endian counter field.
		for i := blockSize - 1; i > c.nonceSize; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		c.b.Encrypt(ks[:], ctr[:])
		n := subtle.XORBytes(dst, src, ks[:])
		dst, src = dst[n:], src[n:]
	}
}

func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("ccm: incorrect nonce length")
	}
	if uint64(len(plaintext)) > c.maxLen() {
		panic("ccm: message too large")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSize)
	if inexactOverlap(out, plaintext) {
		panic("ccm: invalid buffer overlap")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mac(nonce, plaintext, additionalData) // before ctr: out may alias plaintext
	c.ctr(out[:len(plaintext)], plaintext, nonce)
	subtle.XORBytes(out[len(plaintext):], c.x[:c.tagSize], c.s0[:c.tagSize])
	return ret
}

var errOpen = errors.New("ccm: message authentication failed")

func (c *ccm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		panic("ccm: incorrect nonce length")
	}
	if len(ciphertext) < c.tagSize {
		return nil, errOpen
	}
	ptLen := len(ciphertext) - c.tagSize
	if uint64(ptLen) > c.maxLen() {
		return nil, errOpen
	}
	ret, out := sliceForAppend(dst, ptLen)
	if inexactOverlap(out, ciphertext) {
		panic("ccm: invalid buffer overlap")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctr(out, ciphertext[:ptLen], nonce)
	c.mac(nonce, out, additionalData)
	var want [blockSize]byte
	subtle.XORBytes(want[:c.tagSize], c.x[:c.tagSize], c.s0[:c.tagSize])
	if subtle.ConstantTimeCompare(want[:c.tagSize], ciphertext[ptLen:]) != 1 {
		clear(out)
		return nil, errOpen
	}
	return ret, nil
}

// sliceForAppend extends in by n bytes, returning the whole slice and the
// extension (as in crypto/cipher).
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// inexactOverlap reports whether x and y share memory at different offsets.
// In-place operation (x and y starting at the same address) is allowed.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}
