package exchange

import (
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/message"
)

// Addr is a peer transport address.
type Addr = netip.AddrPort

// Session is a channel to one peer over which exchanges run: either an
// unsecured session (used only for PASE and CASE session establishment) or a
// secure unicast session established by PASE or CASE.
type Session struct {
	m      *Manager
	secure bool
	closed bool

	// Peer is the peer's current address; for secure sessions it follows the
	// source address of the latest authenticated message.
	Peer Addr
	// PeerMRP holds the peer's reliable messaging parameters.
	PeerMRP MRPConfig

	// Secure sessions.
	localSessionID uint16
	peerSessionID  uint16
	localNodeID    uint64 // nonce node ID when sending (0 for PASE)
	peerNodeID     uint64 // nonce node ID when receiving (0 for PASE)
	enc, dec       *message.Cipher
	counter        message.Counter

	// Unsecured sessions: the initiator's ephemeral node ID and our role.
	ephemeralNodeID uint64
	initiator       bool

	recv             message.ReceptionState
	lastPeerActivity time.Time
	lastUse          time.Time

	// AuthMode and FabricIndex describe the session's subject for access
	// control. FabricIndex is 0 while a PASE session has no fabric yet.
	AuthMode    AuthMode
	FabricIndex uint8
	// PeerCATs are the CASE Authenticated Tags of a CASE peer.
	PeerCATs []uint32
	// AttestationChallenge is derived with the session keys and used to
	// bind device attestation to the session.
	AttestationChallenge [16]byte

	// Attachment is free for the layer that established the session.
	Attachment any
}

// AuthMode is how a session's peer was authenticated (the access control
// auth modes of spec 9.10.5).
type AuthMode uint8

const (
	AuthNone  AuthMode = 0
	AuthPASE  AuthMode = 1
	AuthCASE  AuthMode = 2
	AuthGroup AuthMode = 3
)

// SecureSessionParams describes a secure session established by PASE or
// CASE.
type SecureSessionParams struct {
	Peer           Addr
	PeerMRP        MRPConfig
	LocalSessionID uint16 // allocated with Manager.AllocateSessionID
	PeerSessionID  uint16
	LocalNodeID    uint64 // 0 for PASE
	PeerNodeID     uint64 // 0 for PASE
	EncryptKey     []byte // I2RKey for the initiator, R2IKey for the responder
	DecryptKey     []byte
	AuthMode       AuthMode
	FabricIndex    uint8
	PeerCATs       []uint32
	// AttestationChallenge, from the session key derivation.
	AttestationChallenge [16]byte
}

// IsSecure reports whether the session is encrypted.
func (s *Session) IsSecure() bool { return s.secure }

// LocalSessionID returns the session ID peers use to address us.
func (s *Session) LocalSessionID() uint16 { return s.localSessionID }

// PeerNodeID returns the peer's operational node ID (0 for PASE sessions).
func (s *Session) PeerNodeID() uint64 { return s.peerNodeID }

// Closed reports whether the session was released.
func (s *Session) Closed() bool { return s.closed }

func (s *Session) peerActive(now time.Time) bool {
	return !s.lastPeerActivity.IsZero() && now.Sub(s.lastPeerActivity) < s.PeerMRP.ActiveThreshold
}

// retransBase returns the peer's current MRP base interval.
func (s *Session) retransBase(now time.Time) time.Duration {
	if s.peerActive(now) {
		return s.PeerMRP.ActiveInterval
	}
	return s.PeerMRP.IdleInterval
}

// nextCounter returns the message counter for an outgoing message.
func (s *Session) nextCounter() (uint32, error) {
	if s.secure {
		return s.counter.Next()
	}
	return s.m.globalCounter.NextWrapping(), nil
}

// header returns the message header for an outgoing message.
func (s *Session) header(counter uint32) message.Header {
	h := message.Header{MessageCounter: counter}
	switch {
	case s.secure:
		h.SessionID = s.peerSessionID
	case s.initiator:
		h.HasSource = true
		h.SourceNodeID = s.ephemeralNodeID
	default:
		h.Dest = message.DestNode
		h.DestNodeID = s.ephemeralNodeID
	}
	return h
}
