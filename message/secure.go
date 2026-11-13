package message

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"tinymatter/crypto/ccm"
)

// ErrAuth is returned when an encrypted message fails authentication.
var ErrAuth = errors.New("message: authentication failed")

// KeySize is the size of a session encryption key (AES-128).
const KeySize = 16

// Cipher encrypts or decrypts messages with one session key using
// AES-128-CCM (spec 4.8). A secure session has two: one keyed with its
// encryption key for sending and one with its decryption key for receiving.
//
// A Cipher reuses internal scratch space and is not safe for concurrent use.
type Cipher struct {
	aead  cipher.AEAD
	nonce [NonceSize]byte
}

// NewCipher returns a Cipher for a 16-byte session key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, errors.New("message: session key must be 16 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := ccm.New(b, NonceSize, MICSize)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: a}, nil
}

// Nonce builds the AES-CCM nonce for a message (spec 4.8.1.1):
// security flags || message counter (LE) || sender node ID (LE).
//
// nodeID is the sender's node ID: its operational node ID for CASE sessions,
// and 0 (unspecified) for PASE sessions.
func Nonce(h *Header, nodeID uint64) [NonceSize]byte {
	var n [NonceSize]byte
	putNonce(&n, h, nodeID)
	return n
}

func putNonce(n *[NonceSize]byte, h *Header, nodeID uint64) {
	n[0] = h.SecurityFlags()
	binary.LittleEndian.PutUint32(n[1:], h.MessageCounter)
	binary.LittleEndian.PutUint64(n[5:], nodeID)
}

// AppendUnsecured appends an unencrypted message: header || payload, where
// payload is the protocol header followed by the application payload.
func AppendUnsecured(dst []byte, h *Header, payload []byte) []byte {
	dst = h.AppendTo(dst)
	return append(dst, payload...)
}

// AppendSealed appends an encrypted message: header || ciphertext || MIC.
// payload is the protocol header followed by the application payload, and
// nodeID is as for Nonce. To encode without allocating, give dst capacity for
// h.Size()+len(payload)+MICSize; payload must not overlap dst's free space.
func (c *Cipher) AppendSealed(dst []byte, h *Header, payload []byte, nodeID uint64) ([]byte, error) {
	if h.Privacy {
		return nil, ErrUnsupported
	}
	start := len(dst)
	dst = h.AppendTo(dst)
	putNonce(&c.nonce, h, nodeID)
	return c.aead.Seal(dst, c.nonce[:], payload, dst[start:]), nil
}

// OpenInPlace authenticates and decrypts an encrypted message. h is its
// header, already decoded from the start of packet with encoded size hdrLen,
// and nodeID is the sender's node ID as for Nonce. The payload is decrypted
// in place and returned as a sub-slice of packet; on failure the packet
// contents are undefined.
func (c *Cipher) OpenInPlace(packet []byte, h *Header, hdrLen int, nodeID uint64) ([]byte, error) {
	if h.Privacy {
		return nil, ErrUnsupported
	}
	if len(packet)-hdrLen < MICSize {
		return nil, ErrTruncated
	}
	putNonce(&c.nonce, h, nodeID)
	ct := packet[hdrLen:]
	pt, err := c.aead.Open(ct[:0], c.nonce[:], ct, packet[:hdrLen])
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}
