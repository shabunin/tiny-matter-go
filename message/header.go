// Package message implements the Matter message layer (Matter Core
// Specification, chapter 4): the message header, the protocol (exchange)
// header, message encryption, and message counters with replay protection.
package message

import (
	"encoding/binary"
	"errors"
)

// Wire-format constants.
const (
	// MICSize is the size of the AES-CCM tag on encrypted messages.
	MICSize = 16
	// NonceSize is the size of the AES-CCM message nonce.
	NonceSize = 13
	// UnsecuredSessionID is the session ID of unencrypted messages.
	UnsecuredSessionID = 0
	// MaxHeaderSize is the largest message header we encode (without
	// extensions): 8 fixed bytes plus source and destination node IDs.
	MaxHeaderSize = 8 + 8 + 8
	// MaxPacketSize is the largest Matter message over UDP/IPv6
	// (1280-byte IPv6 minimum MTU less IPv6 and UDP headers).
	MaxPacketSize = 1280 - 48
)

// Message flag bits.
const (
	flagVersionMask = 0xF0
	flagSource      = 0x04
	flagDSIZMask    = 0x03
)

// Security flag bits.
const (
	secPrivacy        = 0x80
	secControl        = 0x40
	secExtensions     = 0x20
	secSessionTypeMsk = 0x03
)

// SessionType is the session type in the security flags.
type SessionType uint8

const (
	SessionUnicast SessionType = 0
	SessionGroup   SessionType = 1
)

// DestKind says which destination field, if any, a header carries (DSIZ).
type DestKind uint8

const (
	DestNone  DestKind = 0
	DestNode  DestKind = 1 // 64-bit destination node ID
	DestGroup DestKind = 2 // 16-bit destination group ID
)

// Header is the unencrypted message header (spec 4.4.1). For encrypted
// messages its encoding is the AES-CCM additional data.
type Header struct {
	SessionID      uint16
	SessionType    SessionType
	Privacy        bool // P flag: header obfuscated (group messages, see Obfuscate)
	Control        bool // C flag: message counter synchronization traffic
	MessageCounter uint32

	HasSource    bool
	SourceNodeID uint64

	Dest        DestKind
	DestNodeID  uint64
	DestGroupID uint16

	// Extensions holds the message extensions block (MX) of a decoded
	// message, aliasing the input. Encoding writes it if non-nil.
	Extensions []byte
}

var (
	ErrTruncated   = errors.New("message: truncated")
	ErrVersion     = errors.New("message: unsupported version")
	ErrInvalid     = errors.New("message: invalid header")
	ErrUnsupported = errors.New("message: unsupported feature")
)

// MessageFlags returns the encoded message flags octet.
func (h *Header) MessageFlags() byte {
	f := byte(h.Dest) & flagDSIZMask
	if h.HasSource {
		f |= flagSource
	}
	return f
}

// SecurityFlags returns the encoded security flags octet. It is also the
// first byte of the AES-CCM nonce.
func (h *Header) SecurityFlags() byte {
	f := byte(h.SessionType) & secSessionTypeMsk
	if h.Privacy {
		f |= secPrivacy
	}
	if h.Control {
		f |= secControl
	}
	if h.Extensions != nil {
		f |= secExtensions
	}
	return f
}

// IsEncrypted reports whether the message is protected by a secure session.
func (h *Header) IsEncrypted() bool {
	return !(h.SessionID == UnsecuredSessionID && h.SessionType == SessionUnicast)
}

// Size returns the encoded size of the header.
func (h *Header) Size() int {
	n := 8
	if h.HasSource {
		n += 8
	}
	switch h.Dest {
	case DestNode:
		n += 8
	case DestGroup:
		n += 2
	}
	if h.Extensions != nil {
		n += 2 + len(h.Extensions)
	}
	return n
}

// AppendTo appends the encoded header to b.
func (h *Header) AppendTo(b []byte) []byte {
	b = append(b, h.MessageFlags())
	b = binary.LittleEndian.AppendUint16(b, h.SessionID)
	b = append(b, h.SecurityFlags())
	b = binary.LittleEndian.AppendUint32(b, h.MessageCounter)
	if h.HasSource {
		b = binary.LittleEndian.AppendUint64(b, h.SourceNodeID)
	}
	switch h.Dest {
	case DestNode:
		b = binary.LittleEndian.AppendUint64(b, h.DestNodeID)
	case DestGroup:
		b = binary.LittleEndian.AppendUint16(b, h.DestGroupID)
	}
	if h.Extensions != nil {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(h.Extensions)))
		b = append(b, h.Extensions...)
	}
	return b
}

// Decode parses a header from the start of b and returns its encoded size.
func (h *Header) Decode(b []byte) (int, error) {
	*h = Header{}
	if len(b) < 8 {
		return 0, ErrTruncated
	}
	mf := b[0]
	if mf&flagVersionMask != 0 {
		return 0, ErrVersion
	}
	h.SessionID = binary.LittleEndian.Uint16(b[1:])
	sf := b[3]
	h.SessionType = SessionType(sf & secSessionTypeMsk)
	h.Privacy = sf&secPrivacy != 0
	h.Control = sf&secControl != 0
	h.MessageCounter = binary.LittleEndian.Uint32(b[4:])
	if h.SessionType > SessionGroup {
		return 0, ErrInvalid
	}
	n := 8
	if mf&flagSource != 0 {
		if len(b) < n+8 {
			return 0, ErrTruncated
		}
		h.HasSource = true
		h.SourceNodeID = binary.LittleEndian.Uint64(b[n:])
		n += 8
	}
	switch DestKind(mf & flagDSIZMask) {
	case DestNone:
	case DestNode:
		if len(b) < n+8 {
			return 0, ErrTruncated
		}
		h.Dest = DestNode
		h.DestNodeID = binary.LittleEndian.Uint64(b[n:])
		n += 8
	case DestGroup:
		if h.SessionType != SessionGroup {
			return 0, ErrInvalid
		}
		if len(b) < n+2 {
			return 0, ErrTruncated
		}
		h.Dest = DestGroup
		h.DestGroupID = binary.LittleEndian.Uint16(b[n:])
		n += 2
	default:
		return 0, ErrInvalid
	}
	if sf&secExtensions != 0 {
		if len(b) < n+2 {
			return 0, ErrTruncated
		}
		l := int(binary.LittleEndian.Uint16(b[n:]))
		n += 2
		if len(b)-n < l {
			return 0, ErrTruncated
		}
		h.Extensions = b[n : n+l : n+l]
		n += l
	}
	return n, nil
}
