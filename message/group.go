package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// GroupKeys are the keys derived from one group epoch key (spec 4.17.2):
// the operational group key, which encrypts group messages, the privacy
// key, which obfuscates their headers, and the session ID that names the
// operational key in the message header.
type GroupKeys struct {
	Encryption [KeySize]byte
	Privacy    [KeySize]byte
	SessionID  uint16
}

// DeriveGroupKeys derives the group keys of epochKey on the fabric with
// the given compressed fabric ID.
func DeriveGroupKeys(epochKey []byte, compressedFabricID [8]byte) (GroupKeys, error) {
	var k GroupKeys
	if len(epochKey) != KeySize {
		return k, errors.New("message: epoch key must be 16 bytes")
	}
	op, err := hkdf.Key(sha256.New, epochKey, compressedFabricID[:], "GroupKey v1.0", KeySize)
	if err != nil {
		return k, err
	}
	copy(k.Encryption[:], op)
	err = k.deriveFromEncryption()
	return k, err
}

// GroupKeysFromOperational completes GroupKeys from an operational group
// key alone (the privacy key and session ID derive from it).
func GroupKeysFromOperational(op [KeySize]byte) (GroupKeys, error) {
	k := GroupKeys{Encryption: op}
	err := k.deriveFromEncryption()
	return k, err
}

func (k *GroupKeys) deriveFromEncryption() error {
	h, err := hkdf.Key(sha256.New, k.Encryption[:], nil, "GroupKeyHash", 2)
	if err != nil {
		return err
	}
	k.SessionID = binary.BigEndian.Uint16(h)
	p, err := hkdf.Key(sha256.New, k.Encryption[:], nil, "PrivacyKey", KeySize)
	if err != nil {
		return err
	}
	copy(k.Privacy[:], p)
	return nil
}

// Privacy offsets (spec 4.9.3): the obfuscated part of a header follows
// the message flags, session ID and security flags, and covers the message
// counter and the source and destination IDs.
const (
	privacyOffset      = 4
	privacyMICOffset   = 5
	privacyNonceLength = NonceSize
)

// privacyLength returns the length of the obfuscated part of h.
func privacyLength(h *Header) int {
	n := 4
	if h.HasSource {
		n += 8
	}
	switch h.Dest {
	case DestNode:
		n += 8
	case DestGroup:
		n += 2
	}
	return n
}

// Obfuscate applies (or, being its own inverse, removes) header privacy on
// an encrypted message: AES-CTR over the message counter and node IDs with
// the privacy key, nonced by the session ID and part of the MIC. h holds the
// flags of the message, which are not obfuscated; packet is changed in
// place.
func Obfuscate(packet []byte, h *Header, privacyKey []byte) error {
	n := privacyLength(h)
	if len(packet) < privacyOffset+n+MICSize || len(packet) < h.Size()+MICSize {
		return ErrTruncated
	}
	b, err := aes.NewCipher(privacyKey)
	if err != nil {
		return err
	}
	mic := packet[len(packet)-MICSize:]
	// The CTR blocks of AES-CCM with a 13-byte nonce: flags (L-1 = 1),
	// nonce, and a 2-byte counter starting at 1.
	var iv [aes.BlockSize]byte
	iv[0] = 1
	binary.BigEndian.PutUint16(iv[1:], h.SessionID)
	copy(iv[3:1+privacyNonceLength], mic[privacyMICOffset:])
	iv[15] = 1
	region := packet[privacyOffset : privacyOffset+n]
	cipher.NewCTR(b, iv[:]).XORKeyStream(region, region)
	return nil
}
