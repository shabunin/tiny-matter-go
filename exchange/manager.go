// Package exchange implements Matter sessions, exchanges and the Message
// Reliability Protocol (Matter Core Specification 4.10-4.12).
//
// It is sans-IO: it never reads sockets, starts goroutines or reads the
// clock. The caller feeds received packets to HandlePacket, sends packets
// through a Transport, and calls Poll at the deadline Poll returns. This
// keeps it deterministic to test and suits a single-threaded MCU main loop.
// A Manager is not safe for concurrent use.
package exchange

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/message"
)

// Secure Channel opcode for MRP standalone acknowledgements.
const OpcodeStandaloneAck = 0x10

// DefaultExchangeTimeout is how long an idle open exchange may wait with no
// message, retransmission, or pending acknowledgement before timing out.
const DefaultExchangeTimeout = 90 * time.Second

var (
	ErrUnknownSession  = errors.New("exchange: unknown session")
	ErrDeliveryFailed  = errors.New("exchange: message not acknowledged")
	ErrExchangeTimeout = errors.New("exchange: response timeout")
	ErrSessionClosed   = errors.New("exchange: session closed")
	ErrExchangeClosed  = errors.New("exchange: exchange closed")
	ErrBusy            = errors.New("exchange: previous message not yet acknowledged")
	ErrTooLarge        = errors.New("exchange: message too large")
	ErrTooManySessions = errors.New("exchange: session table full")
	ErrTooMany         = errors.New("exchange: exchange table full")
	ErrDropped         = errors.New("exchange: message dropped")
)

// Transport sends encoded packets. Send errors do not fail an exchange:
// reliable messages are retransmitted as if the packet were lost.
type Transport interface {
	Send(to Addr, pkt []byte) error
}

// ReliableTransport is implemented by a Transport that delivers some peers'
// packets reliably and in order, such as BTP over BLE. Messages to those
// peers do not ask for MRP acknowledgements and are not retransmitted
// (spec 4.12.1).
type ReliableTransport interface {
	Reliable(to Addr) bool
}

func (m *Manager) reliable(to Addr) bool {
	r, ok := m.cfg.Transport.(ReliableTransport)
	return ok && r.Reliable(to)
}

// Message is an application message delivered to a Delegate. Payload is only
// valid during the callback.
type Message struct {
	ProtocolID uint16
	VendorID   uint16
	Opcode     uint8
	Payload    []byte
}

// Delegate receives the events of one exchange.
type Delegate interface {
	// OnMessage is called for each new message on the exchange.
	OnMessage(now time.Time, ex *Exchange, msg Message)
	// OnError is called when the exchange fails (ErrDeliveryFailed,
	// ErrSessionClosed). The exchange is closed afterwards.
	OnError(now time.Time, ex *Exchange, err error)
}

// Factory accepts an exchange started by a peer, returning its delegate, or
// nil to decline it.
type Factory func(ex *Exchange) Delegate

// Config configures a Manager.
type Config struct {
	Transport Transport
	Rand      io.Reader // counters, IDs and MRP jitter
	// Table limits; zero means a small default suitable for a device.
	MaxSecureSessions    int
	MaxUnsecuredSessions int
	MaxExchanges         int
	// ExchangeTimeout closes idle open exchanges after inactivity (zero uses
	// DefaultExchangeTimeout; negative disables).
	ExchangeTimeout time.Duration
	// Clock, if set, returns the current time. Sends use it to schedule
	// retransmissions, so a reply computed slowly after the message it
	// answers is not retransmitted at once. Nil uses the time passed in.
	Clock func() time.Time
}

// Manager owns the sessions and exchanges of a node.
type Manager struct {
	cfg            Config
	globalCounter  message.Counter
	sessions       []*Session
	exchanges      []*Exchange
	factories      map[uint32]Factory
	nextExchangeID uint16
	nextSessionID  uint16

	plain [message.MaxPacketSize]byte
	out   [message.MaxPacketSize]byte
}

// NewManager returns a Manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.MaxSecureSessions == 0 {
		cfg.MaxSecureSessions = 8
	}
	if cfg.MaxUnsecuredSessions == 0 {
		cfg.MaxUnsecuredSessions = 4
	}
	if cfg.MaxExchanges == 0 {
		cfg.MaxExchanges = 16
	}
	if cfg.ExchangeTimeout == 0 {
		cfg.ExchangeTimeout = DefaultExchangeTimeout
	}
	m := &Manager{cfg: cfg, factories: make(map[uint32]Factory)}
	var err error
	if m.globalCounter, err = message.NewCounter(cfg.Rand); err != nil {
		return nil, err
	}
	var b [4]byte
	if _, err := io.ReadFull(cfg.Rand, b[:]); err != nil {
		return nil, err
	}
	m.nextExchangeID = binary.LittleEndian.Uint16(b[:])
	m.nextSessionID = binary.LittleEndian.Uint16(b[2:])
	return m, nil
}

func protocolKey(vendor, protocol uint16) uint32 { return uint32(vendor)<<16 | uint32(protocol) }

// Register makes f accept exchanges that peers start with protocolID (in
// the common vendor namespace).
func (m *Manager) Register(protocolID uint16, f Factory) {
	m.factories[protocolKey(0, protocolID)] = f
}

// AllocateSessionID returns an unused non-zero local session ID.
func (m *Manager) AllocateSessionID() (uint16, error) {
	for range 1 << 16 {
		m.nextSessionID++
		id := m.nextSessionID
		if id != 0 && m.secureByLocalID(id) == nil {
			return id, nil
		}
	}
	return 0, ErrTooManySessions
}

// NewSecureSession installs a secure session established by PASE or CASE.
func (m *Manager) NewSecureSession(now time.Time, p SecureSessionParams) (*Session, error) {
	if m.count(true) >= m.cfg.MaxSecureSessions {
		if !m.evict(now, true) {
			return nil, ErrTooManySessions
		}
	}
	if p.LocalSessionID == 0 || m.secureByLocalID(p.LocalSessionID) != nil {
		return nil, errors.New("exchange: invalid local session ID")
	}
	enc, err := message.NewCipher(p.EncryptKey)
	if err != nil {
		return nil, err
	}
	dec, err := message.NewCipher(p.DecryptKey)
	if err != nil {
		return nil, err
	}
	ctr, err := message.NewCounter(m.cfg.Rand)
	if err != nil {
		return nil, err
	}
	s := &Session{
		m: m, secure: true, Peer: p.Peer, PeerMRP: p.PeerMRP,
		localSessionID: p.LocalSessionID, peerSessionID: p.PeerSessionID,
		localNodeID: p.LocalNodeID, peerNodeID: p.PeerNodeID,
		enc: enc, dec: dec, counter: ctr, lastUse: now,
		AuthMode: p.AuthMode, FabricIndex: p.FabricIndex, PeerCATs: p.PeerCATs,
		AttestationChallenge: p.AttestationChallenge,
	}
	if s.PeerMRP == (MRPConfig{}) {
		s.PeerMRP = DefaultMRPConfig
	}
	s.recv.SetCounter(0)
	m.sessions = append(m.sessions, s)
	return s, nil
}

// NewUnsecuredSession starts an unsecured session to peer as initiator, as
// a commissioner does for PASE or CASE.
func (m *Manager) NewUnsecuredSession(now time.Time, peer Addr, peerMRP MRPConfig) (*Session, error) {
	var b [8]byte
	if _, err := io.ReadFull(m.cfg.Rand, b[:]); err != nil {
		return nil, err
	}
	return m.addUnsecured(now, peer, binary.LittleEndian.Uint64(b[:]), true, peerMRP)
}

func (m *Manager) addUnsecured(now time.Time, peer Addr, eph uint64, initiator bool, peerMRP MRPConfig) (*Session, error) {
	if m.count(false) >= m.cfg.MaxUnsecuredSessions && !m.evict(now, false) {
		return nil, ErrTooManySessions
	}
	if peerMRP == (MRPConfig{}) {
		peerMRP = DefaultMRPConfig
	}
	s := &Session{m: m, Peer: peer, PeerMRP: peerMRP, ephemeralNodeID: eph, initiator: initiator, lastUse: now}
	m.sessions = append(m.sessions, s)
	return s, nil
}

// CloseSession releases s, failing its open exchanges with
// ErrSessionClosed.
func (m *Manager) CloseSession(now time.Time, s *Session) {
	if s.closed {
		return
	}
	s.closed = true
	for _, ex := range m.exchanges {
		if ex.s == s && !ex.done {
			ex.fail(now, ErrSessionClosed)
		}
	}
	m.compact()
}

func (m *Manager) count(secure bool) int {
	n := 0
	for _, s := range m.sessions {
		if s.secure == secure {
			n++
		}
	}
	return n
}

func (m *Manager) hasLiveExchange(s *Session) bool {
	for _, ex := range m.exchanges {
		if ex.s == s && !ex.done {
			return true
		}
	}
	return false
}

// evict closes the least recently used session of the given kind, preferring
// idle sessions that have no live exchanges.
func (m *Manager) evict(now time.Time, secure bool) bool {
	var idleLRU, anyLRU *Session
	for _, s := range m.sessions {
		if s.secure != secure || s.closed {
			continue
		}
		if anyLRU == nil || s.lastUse.Before(anyLRU.lastUse) {
			anyLRU = s
		}
		if !m.hasLiveExchange(s) && (idleLRU == nil || s.lastUse.Before(idleLRU.lastUse)) {
			idleLRU = s
		}
	}
	lru := idleLRU
	if lru == nil {
		lru = anyLRU
	}
	if lru == nil {
		return false
	}
	m.CloseSession(now, lru)
	return true
}

func (m *Manager) secureByLocalID(id uint16) *Session {
	for _, s := range m.sessions {
		if s.secure && s.localSessionID == id {
			return s
		}
	}
	return nil
}

func (m *Manager) unsecured(eph uint64, initiator bool, peer Addr) *Session {
	for _, s := range m.sessions {
		if !s.secure && s.ephemeralNodeID == eph && s.initiator == initiator &&
			(initiator || s.Peer == peer) {
			return s
		}
	}
	return nil
}

// HandlePacket processes a received packet. pkt is decrypted in place. The
// returned error describes why a packet was dropped and is informational.
func (m *Manager) HandlePacket(now time.Time, from Addr, pkt []byte) error {
	defer m.compact()
	var h message.Header
	n, err := h.Decode(pkt)
	if err != nil {
		return err
	}
	var s *Session
	var payload []byte
	var ph message.ProtocolHeader
	var pn int
	dup := false
	createdSession := false
	if h.IsEncrypted() {
		if h.SessionType != message.SessionUnicast {
			return message.ErrUnsupported // group messaging
		}
		if s = m.secureByLocalID(h.SessionID); s == nil {
			return ErrUnknownSession
		}
		err := s.recv.CheckEncryptedUnicast(h.MessageCounter)
		if err != nil && err != message.ErrDuplicate {
			return err
		}
		dup = err != nil
		if payload, err = s.dec.OpenInPlace(pkt, &h, n, s.peerNodeID); err != nil {
			return err
		}
		if !dup {
			s.recv.CommitEncryptedUnicast(h.MessageCounter)
			s.Peer = from
			s.lastPeerActivity, s.lastUse = now, now
		}
		if pn, err = ph.Decode(payload); err != nil {
			return err
		}
	} else {
		payload = pkt[n:]
		if pn, err = ph.Decode(payload); err != nil {
			return err
		}
		switch {
		case h.HasSource && h.Dest == message.DestNone: // from an initiator
			s = m.unsecured(h.SourceNodeID, false, from)
		case !h.HasSource && h.Dest == message.DestNode: // reply to our initiator
			if s = m.unsecured(h.DestNodeID, true, from); s == nil {
				return ErrUnknownSession
			}
		default:
			return message.ErrInvalid
		}
		if s == nil {
			isAck := ph.VendorID == 0 && ph.ProtocolID == message.ProtocolSecureChannel && ph.Opcode == OpcodeStandaloneAck
			if isAck {
				return nil
			}
			var f Factory
			if ph.Initiator && m.liveExchanges() < m.cfg.MaxExchanges {
				f = m.factories[protocolKey(ph.VendorID, ph.ProtocolID)]
			}
			if f == nil {
				if ph.NeedsAck {
					tmp := Session{m: m, Peer: from, ephemeralNodeID: h.SourceNodeID}
					m.sendStandaloneAck(now, &tmp, ph.ExchangeID, !ph.Initiator, h.MessageCounter)
				}
				return ErrDropped
			}
			if s, err = m.addUnsecured(now, from, h.SourceNodeID, false, MRPConfig{}); err != nil {
				return err
			}
			createdSession = true
		}
		if err := s.recv.CheckUnencrypted(h.MessageCounter); err != nil {
			dup = true
		} else {
			s.recv.CommitUnencrypted(h.MessageCounter)
			s.lastPeerActivity, s.lastUse = now, now
		}
	}

	app := payload[pn:]
	if ph.HasAck {
		m.handleAck(now, s, ph.AckCounter)
	}
	isAck := ph.VendorID == 0 && ph.ProtocolID == message.ProtocolSecureChannel && ph.Opcode == OpcodeStandaloneAck

	ex := m.findExchange(s, ph.ExchangeID, !ph.Initiator)
	if dup {
		if ph.NeedsAck {
			m.sendStandaloneAck(now, s, ph.ExchangeID, !ph.Initiator, h.MessageCounter)
		}
		return message.ErrDuplicate
	}
	if ex == nil && isAck {
		return nil // consumed by handleAck (which may have closed the exchange)
	}
	if ex == nil {
		var d Delegate
		if !isAck && ph.Initiator {
			if f := m.factories[protocolKey(ph.VendorID, ph.ProtocolID)]; f != nil && m.liveExchanges() < m.cfg.MaxExchanges {
				ex = m.addExchange(now, s, ph.ExchangeID, false)
				if d = f(ex); d == nil {
					ex.done = true
				}
				ex.d = d
			}
		}
		if d == nil {
			if ph.NeedsAck {
				m.sendStandaloneAck(now, s, ph.ExchangeID, !ph.Initiator, h.MessageCounter)
			}
			if createdSession {
				s.closed = true
			}
			return ErrDropped
		}
	}
	if ph.NeedsAck {
		if ex.ackPending { // only one pending ack per exchange: flush the older one
			m.sendStandaloneAck(now, s, ex.id, ex.initiator, ex.ackCounter)
		}
		ex.ackPending, ex.ackCounter, ex.ackDeadline = true, h.MessageCounter, now.Add(StandaloneAckTimeout)
	}
	if isAck || ex.closing {
		return nil
	}
	ex.lastActive = now
	ex.d.OnMessage(now, ex, Message{ProtocolID: ph.ProtocolID, VendorID: ph.VendorID, Opcode: ph.Opcode, Payload: app})
	return nil
}

func (m *Manager) handleAck(now time.Time, s *Session, counter uint32) {
	for _, ex := range m.exchanges {
		if ex.s == s && ex.rtActive && ex.rtCounter == counter {
			ex.rtActive = false
			ex.lastActive = now
			if ex.closing {
				ex.done = true
			}
			return
		}
	}
}

func (m *Manager) findExchange(s *Session, id uint16, initiator bool) *Exchange {
	for _, ex := range m.exchanges {
		if !ex.done && ex.s == s && ex.id == id && ex.initiator == initiator {
			return ex
		}
	}
	return nil
}

func (m *Manager) liveExchanges() int {
	n := 0
	for _, ex := range m.exchanges {
		if !ex.done {
			n++
		}
	}
	return n
}

func (m *Manager) addExchange(now time.Time, s *Session, id uint16, initiator bool) *Exchange {
	ex := &Exchange{m: m, s: s, id: id, initiator: initiator, lastActive: now}
	m.exchanges = append(m.exchanges, ex)
	return ex
}

// NewExchange starts an exchange on s as initiator.
func (m *Manager) NewExchange(s *Session, d Delegate) (*Exchange, error) {
	if s.closed {
		return nil, ErrSessionClosed
	}
	if m.liveExchanges() >= m.cfg.MaxExchanges {
		return nil, ErrTooMany
	}
	m.nextExchangeID++
	ex := m.addExchange(time.Time{}, s, m.nextExchangeID, true)
	ex.d = d
	return ex, nil
}

// send encodes, encrypts and transmits a message on s, returning the packet
// (valid until the next send) and its message counter.
func (m *Manager) send(s *Session, ph *message.ProtocolHeader, payload []byte) ([]byte, uint32, error) {
	if s.closed {
		return nil, 0, ErrSessionClosed
	}
	counter, err := s.nextCounter()
	if err != nil {
		return nil, 0, err
	}
	h := s.header(counter)
	size := h.Size() + ph.Size() + len(payload)
	if s.secure {
		size += message.MICSize
	}
	if size > message.MaxPacketSize {
		return nil, 0, ErrTooLarge
	}
	plain := ph.AppendTo(m.plain[:0])
	plain = append(plain, payload...)
	var pkt []byte
	if s.secure {
		if pkt, err = s.enc.AppendSealed(m.out[:0], &h, plain, s.localNodeID); err != nil {
			return nil, 0, err
		}
	} else {
		pkt = message.AppendUnsecured(m.out[:0], &h, plain)
	}
	m.cfg.Transport.Send(s.Peer, pkt)
	return pkt, counter, nil
}

func (m *Manager) sendStandaloneAck(now time.Time, s *Session, exchangeID uint16, initiator bool, counter uint32) {
	ph := message.ProtocolHeader{
		Initiator: initiator, HasAck: true, AckCounter: counter,
		Opcode: OpcodeStandaloneAck, ExchangeID: exchangeID, ProtocolID: message.ProtocolSecureChannel,
	}
	m.send(s, &ph, nil)
	s.lastUse = now
}

// Poll runs due retransmissions and standalone acknowledgements, and
// returns when it next needs to run (the zero Time if nothing is pending).
func (m *Manager) Poll(now time.Time) time.Time {
	var next time.Time
	soonest := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	for i := 0; i < len(m.exchanges); i++ { // callbacks may append
		ex := m.exchanges[i]
		if ex.done {
			continue
		}
		if ex.ackPending && !now.Before(ex.ackDeadline) {
			ex.ackPending = false
			m.sendStandaloneAck(now, ex.s, ex.id, ex.initiator, ex.ackCounter)
		}
		if ex.rtActive && !now.Before(ex.rtNext) {
			if ex.rtSendCount >= MaxTransmissions-1 {
				ex.rtActive = false
				if ex.closing {
					ex.done = true
				} else {
					ex.fail(now, ErrDeliveryFailed)
				}
				continue
			}
			ex.rtSendCount++
			m.cfg.Transport.Send(ex.s.Peer, ex.rtPkt)
			ex.rtNext = now.Add(Backoff(ex.s.retransBase(now), ex.rtSendCount, randByte(m.cfg.Rand)))
		}
		if ex.ackPending {
			soonest(ex.ackDeadline)
		}
		if ex.rtActive {
			soonest(ex.rtNext)
		} else if !ex.ackPending && !ex.closing && m.cfg.ExchangeTimeout > 0 {
			if ex.lastActive.IsZero() {
				ex.lastActive = now
			}
			dead := ex.lastActive.Add(m.cfg.ExchangeTimeout)
			if !now.Before(dead) {
				ex.fail(now, ErrExchangeTimeout)
				continue
			}
			soonest(dead)
		}
	}
	m.compact()
	return next
}

// compact drops finished exchanges and closed sessions.
func (m *Manager) compact() {
	j := 0
	for _, ex := range m.exchanges {
		if !ex.done {
			m.exchanges[j] = ex
			j++
		}
	}
	clear(m.exchanges[j:])
	m.exchanges = m.exchanges[:j]
	j = 0
	for _, s := range m.sessions {
		if !s.closed {
			m.sessions[j] = s
			j++
		}
	}
	clear(m.sessions[j:])
	m.sessions = m.sessions[:j]
}

// Sessions returns a snapshot of the live sessions; closing sessions while
// iterating over it is safe.
func (m *Manager) Sessions() []*Session { return append([]*Session(nil), m.sessions...) }
