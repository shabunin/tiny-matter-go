package exchange

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/message"
)

// ErrGroupSession is returned for a send on a session a group message
// arrived on: group messages are never answered.
var ErrGroupSession = errors.New("exchange: group messages are not answered")

// maxGroupPeers bounds the senders whose group message counters are
// tracked; the least recently heard is forgotten first.
const maxGroupPeers = 16

// GroupKey is an operational group key of a group the node is a member of
// (spec 4.17), or one a controller sends to a group with.
type GroupKey struct {
	FabricIndex uint8
	GroupID     uint16
	// SessionID is the group session ID that names the key in message
	// headers (derived from the key).
	SessionID  uint16
	Cipher     *message.Cipher // keyed with the operational group key
	PrivacyKey [message.KeySize]byte
}

// GroupKeyFunc calls yield with each key that may have sent a message
// with the given group session ID, until yield returns false.
type GroupKeyFunc func(sessionID uint16, yield func(k *GroupKey) bool)

// SetGroupKeys sets where group message keys are looked up. Without it,
// group messages are dropped.
func (m *Manager) SetGroupKeys(f GroupKeyFunc) { m.groupKeys = f }

type groupPeer struct {
	fabric  uint8
	node    uint64
	control bool
	recv    message.ReceptionState
	used    uint32
}

// ForgetGroupPeers drops the group message counters kept for senders on
// a fabric (when the fabric is removed).
func (m *Manager) ForgetGroupPeers(fabric uint8) {
	j := 0
	for _, p := range m.groupPeers {
		if p.fabric != fabric {
			m.groupPeers[j] = p
			j++
		}
	}
	m.groupPeers = m.groupPeers[:j]
}

// groupPeer returns the counter state of a group sender, making room for
// it if needed.
func (m *Manager) groupPeer(fabric uint8, node uint64, control bool) *groupPeer {
	m.groupTick++
	for i := range m.groupPeers {
		p := &m.groupPeers[i]
		if p.fabric == fabric && p.node == node && p.control == control {
			p.used = m.groupTick
			return p
		}
	}
	if len(m.groupPeers) < maxGroupPeers {
		m.groupPeers = append(m.groupPeers, groupPeer{fabric: fabric, node: node, control: control, used: m.groupTick})
		return &m.groupPeers[len(m.groupPeers)-1]
	}
	lru := &m.groupPeers[0]
	for i := range m.groupPeers {
		if m.groupPeers[i].used < lru.used {
			lru = &m.groupPeers[i]
		}
	}
	*lru = groupPeer{fabric: fabric, node: node, control: control, used: m.groupTick}
	return lru
}

// handleGroup processes an encrypted group message (spec 4.16): it is
// tried with each key of the session ID, then its sender's counter is
// checked, and an initiating message is handed to the protocol's factory
// on a one-message group session. Group messages are never acknowledged
// or answered.
func (m *Manager) handleGroup(now time.Time, from Addr, pkt []byte, h *message.Header) error {
	if m.groupKeys == nil {
		return ErrDropped
	}
	if h.Dest != message.DestGroup || !h.HasSource {
		return message.ErrInvalid
	}
	if len(pkt) > len(m.groupBuf) {
		return ErrTooLarge
	}
	var (
		key     *GroupKey
		gh      message.Header
		payload []byte
	)
	m.groupKeys(h.SessionID, func(k *GroupKey) bool {
		buf := m.groupBuf[:len(pkt)]
		copy(buf, pkt)
		if h.Privacy && message.Obfuscate(buf, h, k.PrivacyKey[:]) != nil {
			return true
		}
		n, err := gh.Decode(buf)
		if err != nil || gh.Dest != message.DestGroup || gh.DestGroupID != k.GroupID || !gh.HasSource {
			return true
		}
		if payload, err = k.Cipher.OpenInPlace(buf, &gh, n, gh.SourceNodeID); err != nil {
			return true
		}
		key = k
		return false
	})
	if key == nil {
		return message.ErrAuth
	}
	src := gh.SourceNodeID
	if src == 0 || src > 0xFFFFFFEFFFFFFFFF { // not an operational node ID
		return message.ErrInvalid
	}
	var ph message.ProtocolHeader
	pn, err := ph.Decode(payload)
	if err != nil {
		return err
	}
	if ph.NeedsAck {
		return ErrDropped // group messages are unreliable
	}
	peer := m.groupPeer(key.FabricIndex, src, gh.Control)
	if err := peer.recv.CheckGroup(gh.MessageCounter); err != nil {
		return err
	}
	peer.recv.CommitGroup(gh.MessageCounter)
	if gh.Control || !ph.Initiator {
		return ErrDropped // message counter synchronization is not supported
	}
	f := m.factories[protocolKey(ph.VendorID, ph.ProtocolID)]
	if f == nil || m.liveExchanges() >= m.cfg.MaxExchanges {
		return ErrDropped
	}
	s := &Session{
		m: m, secure: true, group: true, Peer: from, peerNodeID: src,
		AuthMode: AuthGroup, FabricIndex: key.FabricIndex, GroupID: key.GroupID,
		lastPeerActivity: now, lastUse: now,
	}
	ex := m.addExchange(now, s, ph.ExchangeID, false)
	if d := f(ex); d != nil {
		ex.d = d
		d.OnMessage(now, ex, Message{ProtocolID: ph.ProtocolID, VendorID: ph.VendorID, Opcode: ph.Opcode, Payload: payload[pn:]})
	}
	ex.done = true
	s.closed = true
	return nil
}

// SendGroup sends one message to a group as a new, unacknowledged
// exchange (spec 4.16.2): encrypted with k, its header obfuscated, from
// sourceNodeID (the sender's operational node ID) with the given message
// counter (the sender's group data message counter). to is the group's
// multicast address.
func (m *Manager) SendGroup(to Addr, k *GroupKey, sourceNodeID uint64, counter uint32, protocolID uint16, opcode uint8, payload []byte) error {
	m.nextExchangeID++
	h := message.Header{
		SessionID: k.SessionID, SessionType: message.SessionGroup, Privacy: true,
		MessageCounter: counter, HasSource: true, SourceNodeID: sourceNodeID,
		Dest: message.DestGroup, DestGroupID: k.GroupID,
	}
	ph := message.ProtocolHeader{Initiator: true, Opcode: opcode, ExchangeID: m.nextExchangeID, ProtocolID: protocolID}
	if h.Size()+ph.Size()+len(payload)+message.MICSize > message.MaxPacketSize {
		return ErrTooLarge
	}
	plain := ph.AppendTo(m.plain[:0])
	plain = append(plain, payload...)
	pkt, err := k.Cipher.AppendSealed(m.out[:0], &h, plain, sourceNodeID)
	if err != nil {
		return err
	}
	if err := message.Obfuscate(pkt, &h, k.PrivacyKey[:]); err != nil {
		return err
	}
	return m.cfg.Transport.Send(to, pkt)
}

// GroupMulticastAddr returns the IPv6 multicast address of a group on a
// fabric (spec 2.5.6.2): a unicast-prefix-based address (RFC 3306, flags
// P and T, site-local scope) whose 64-bit prefix is 0xFD followed by the
// fabric ID's upper 56 bits, and whose group ID part is the fabric ID's
// low byte, a zero byte and the group ID.
func GroupMulticastAddr(fabricID uint64, groupID uint16) netip.Addr {
	var a [16]byte
	a[0], a[1], a[2], a[3] = 0xFF, 0x35, 0x00, 0x40
	binary.BigEndian.PutUint64(a[4:], 0xFD00000000000000|fabricID>>8)
	a[12] = byte(fabricID)
	binary.BigEndian.PutUint16(a[14:], groupID)
	return netip.AddrFrom16(a)
}
