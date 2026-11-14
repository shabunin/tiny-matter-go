// Package btp implements the Bluetooth Transport Protocol (Matter spec
// 4.19), which carries Matter messages over a GATT service during BLE
// commissioning: the peripheral (server) side, which a device runs, and the
// central (client) side, which a commissioner runs.
//
// A Conn is sans-IO. On a peripheral (NewConn), the caller feeds it the
// writes the central makes to characteristic C1 and the C2 subscription,
// and sends whatever Poll returns as C2 indications. On a central
// (NewCentral), the caller writes HandshakeRequest to C1, subscribes to C2,
// feeds the C2 indications to HandleIndication, and writes whatever Poll
// returns to C1. One Conn serves one BLE connection.
package btp

import (
	"encoding/binary"
	"errors"
	"time"
)

// GATT service and characteristics (spec 4.19.3).
const (
	ServiceUUID16 = 0xFFF6
	// C1: the central writes to it.
	C1UUID = "18EE2EF5-263D-4559-959F-4F9C429F9D11"
	// C2: the peripheral notifies or indicates on it.
	C2UUID = "18EE2EF5-263D-4559-959F-4F9C429F9D12"
	// C3: optional additional commissioning data (read).
	C3UUID = "64630238-8772-45F2-B87D-748A83218F04"
)

const (
	// Version is the BTP protocol version this package speaks.
	Version = 4

	// MaxWindow is the largest receive window offered to the central.
	MaxWindow = 6

	// MaxMessage is the largest message reassembled or sent.
	MaxMessage = 1280

	defaultFragment = 20  // 23-byte minimum ATT_MTU minus the 3-byte ATT header
	maxFragment     = 244 // largest BTP segment
	minFragment     = 6   // largest header plus one byte

	// SendAckDelay is how long an acknowledgement is held for piggybacking.
	SendAckDelay = 2500 * time.Millisecond
	// AckTimeout is how long the central may take to acknowledge a segment.
	AckTimeout = 15 * time.Second

	immediateAckWindow = 1 // ack at once when our receive window shrinks to this
	noAckSendWindow    = 1 // keep the last slot of the peer's window for an ack
)

// Segment header flags.
const (
	flagStart     = 0x01 // B: first segment; carries the message length
	flagContinue  = 0x02 // C: not the first segment
	flagEnd       = 0x04 // E: last segment
	flagAck       = 0x08 // A: carries an acknowledgement number
	flagMgmt      = 0x20 // M: management message (handshake)
	flagHandshake = 0x40 // H: handshake
)

const (
	handshakeFlags  = flagHandshake | flagMgmt | flagEnd | flagStart // 0x65
	handshakeOpcode = 0x6C
	handshakeReqLen = 9
)

var (
	ErrHandshake = errors.New("btp: bad handshake")
	ErrVersion   = errors.New("btp: no common protocol version")
	ErrState     = errors.New("btp: unexpected write in this state")
	ErrSequence  = errors.New("btp: bad sequence number")
	ErrAck       = errors.New("btp: invalid acknowledgement")
	ErrSegment   = errors.New("btp: malformed segment")
	ErrTooLong   = errors.New("btp: message too long")
	ErrTimeout   = errors.New("btp: acknowledgement timeout")
	ErrQueueFull = errors.New("btp: send queue full")
	ErrClosed    = errors.New("btp: connection not open")
)

type state uint8

const (
	stateIdle      state = iota // waiting for the handshake request
	stateHandshake              // request received; waiting for the C2 subscription
	stateOpen                   // response sent (or queued); on a central, received
	stateRejected               // send the response, then close
	stateClosed
	stateRequested // central: request written, waiting for the response
)

const queueLen = 4

// Conn is the BTP state of one BLE connection.
type Conn struct {
	st       state
	attMTU   int // current ATT MTU of the connection, 0 if unknown
	maxMTU   int // largest ATT MTU the local stack supports
	frag     int // negotiated segment size, header included
	window   uint8
	version  uint8
	respSent bool

	// Transmit side.
	txSeq        uint8 // next sequence number to send
	txOldest     uint8 // oldest unacknowledged
	txNewest     uint8 // newest unacknowledged
	expectingAck bool
	remoteWindow uint8
	ackDeadline  time.Time // ack-received timer, when expectingAck

	queue  [queueLen][]byte
	qHead  int
	qLen   int
	txOff  int  // bytes of queue[qHead] already sent
	txBusy bool // a message is partly sent

	// Receive side.
	rxNext      uint8 // next expected sequence number
	rxNewest    uint8 // newest received, not yet acknowledged
	rxUnacked   bool
	localWindow uint8
	sendAckAt   time.Time // send-ack timer, when rxUnacked
	rxBuf       []byte
	rxLen       int
	rxBusy      bool

	pkt [maxFragment]byte
}

// NewConn returns a Conn for a new BLE connection. maxMTU is the largest
// ATT MTU the local stack supports (0 for no limit).
func NewConn(maxMTU int) *Conn {
	c := &Conn{}
	c.Reset(maxMTU)
	return c
}

// Reset prepares the Conn for a new BLE connection.
func (c *Conn) Reset(maxMTU int) {
	buf := c.rxBuf[:0]
	q := c.queue
	*c = Conn{maxMTU: maxMTU, rxBuf: buf}
	for i := range q {
		c.queue[i] = q[i][:0]
	}
}

// NewCentral returns a Conn for the central side of a new BLE connection.
// attMTU is the connection's ATT MTU, or 0 if unknown (the peripheral then
// chooses the segment size from what it knows).
func NewCentral(attMTU int) *Conn {
	return &Conn{st: stateRequested, attMTU: min(max(attMTU, 0), 0xFFFF)}
}

// HandshakeRequest returns the handshake request a central writes to C1,
// after which it subscribes to C2.
func (c *Conn) HandshakeRequest() []byte {
	b := make([]byte, handshakeReqLen)
	b[0], b[1] = handshakeFlags, handshakeOpcode
	b[2] = Version // the supported versions, low nibble first, 0-terminated
	binary.LittleEndian.PutUint16(b[6:], uint16(c.attMTU))
	b[8] = MaxWindow
	return b
}

// HandleIndication processes a value the peripheral indicated on C2: the
// handshake response, then segments. When it completes a message, the
// message is returned; it is valid until the next call. An error means the
// BTP session is broken and the BLE connection should be dropped.
func (c *Conn) HandleIndication(now time.Time, b []byte) ([]byte, error) {
	switch c.st {
	case stateRequested:
		return nil, c.handshakeResponse(now, b)
	case stateOpen:
		return c.segment(now, b)
	}
	return nil, ErrState
}

func (c *Conn) handshakeResponse(now time.Time, b []byte) error {
	if len(b) < 6 || b[0] != handshakeFlags || b[1] != handshakeOpcode {
		return ErrHandshake
	}
	if b[2]&0x0F != Version {
		return ErrVersion
	}
	frag := int(binary.LittleEndian.Uint16(b[3:]))
	if frag < minFragment || b[5] == 0 {
		return ErrHandshake
	}
	c.version, c.frag = Version, min(frag, maxFragment)
	c.window = min(b[5], MaxWindow)
	c.remoteWindow = c.window
	// The response is the peripheral's segment 0, which we acknowledge.
	c.localWindow = c.window - 1
	c.rxNext, c.rxNewest, c.rxUnacked = 1, 0, true
	c.sendAckAt = now.Add(SendAckDelay)
	c.st, c.respSent = stateOpen, true
	return nil
}

// SetMTU records the connection's ATT MTU, used when the central's handshake
// does not state one.
func (c *Conn) SetMTU(mtu int) { c.attMTU = mtu }

// Open reports whether the handshake has completed and messages may flow.
func (c *Conn) Open() bool { return c.st == stateOpen && c.respSent }

// Closed reports whether the connection should be dropped: the versions
// were incompatible and the rejection has been sent.
func (c *Conn) Closed() bool { return c.st == stateClosed }

// FragmentSize returns the negotiated segment size (0 before the handshake).
func (c *Conn) FragmentSize() int { return c.frag }

// Window returns the negotiated receive window (0 before the handshake).
func (c *Conn) Window() int { return int(c.window) }

// Subscribed records that the central enabled notifications or indications
// on C2. The handshake response goes out on the next Poll.
func (c *Conn) Subscribed(now time.Time) {
	if c.st == stateHandshake {
		c.st = stateOpen
	}
}

// HandleWrite processes a write to C1. When it completes a message, the
// message is returned; it is valid until the next call. An error means the
// BTP session is broken and the BLE connection should be dropped.
func (c *Conn) HandleWrite(now time.Time, b []byte) ([]byte, error) {
	switch c.st {
	case stateIdle:
		return nil, c.handshake(b)
	case stateOpen:
		if c.respSent {
			return c.segment(now, b)
		}
	}
	return nil, ErrState
}

func (c *Conn) handshake(b []byte) error {
	if len(b) < handshakeReqLen || b[0] != handshakeFlags || b[1] != handshakeOpcode {
		return ErrHandshake
	}
	// Up to eight 4-bit versions, low nibble first, ended by 0.
	for i := 0; i < 8; i++ {
		v := b[2+i/2] >> (4 * (i & 1)) & 0x0F
		if v == 0 {
			break
		}
		if v == Version {
			c.version = v
		}
	}
	mtu := int(binary.LittleEndian.Uint16(b[6:]))
	if mtu == 0 {
		mtu = c.attMTU
	}
	if c.maxMTU > 0 && mtu > c.maxMTU {
		mtu = c.maxMTU
	}
	c.frag = defaultFragment
	if mtu > 0 {
		c.frag = min(max(mtu-3, minFragment), maxFragment)
	}
	w := b[8]
	if w == 0 {
		return ErrHandshake
	}
	c.window = min(w, MaxWindow)
	c.remoteWindow, c.localWindow = c.window, c.window
	c.st = stateHandshake
	return nil
}

func (c *Conn) segment(now time.Time, b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, ErrSegment
	}
	flags, p := b[0], 1
	if flags&(flagHandshake|flagMgmt) != 0 {
		return nil, ErrSegment
	}
	if flags&flagAck != 0 {
		if err := c.ack(now, b[p]); err != nil {
			return nil, err
		}
		p++
	}
	if p >= len(b) {
		return nil, ErrSegment
	}
	seq := b[p]
	p++
	if seq != c.rxNext {
		return nil, ErrSequence
	}
	c.rxNext++
	c.rxNewest = seq
	if !c.rxUnacked {
		c.rxUnacked = true
		c.sendAckAt = now.Add(SendAckDelay)
	}
	c.localWindow--

	if flags&(flagStart|flagContinue|flagEnd) == 0 {
		return nil, nil // standalone acknowledgement
	}
	if p > c.frag {
		return nil, ErrSegment
	}
	if len(b) > c.frag {
		b = b[:c.frag]
	}
	if !c.rxBusy {
		if flags&flagStart == 0 || p+2 > len(b) {
			return nil, ErrSegment
		}
		c.rxLen = int(binary.LittleEndian.Uint16(b[p:]))
		p += 2
		if c.rxLen > MaxMessage {
			return nil, ErrTooLong
		}
		c.rxBuf, c.rxBusy = c.rxBuf[:0], true
	} else if flags&flagStart != 0 || flags&(flagContinue|flagEnd) == 0 {
		return nil, ErrSegment
	}
	if len(c.rxBuf)+len(b)-p > c.rxLen {
		return nil, ErrSegment
	}
	c.rxBuf = append(c.rxBuf, b[p:]...)
	if flags&flagEnd == 0 {
		return nil, nil
	}
	c.rxBusy = false
	if len(c.rxBuf) != c.rxLen {
		return nil, ErrSegment
	}
	return c.rxBuf, nil
}

// ack handles an acknowledgement number from the central.
func (c *Conn) ack(now time.Time, n uint8) error {
	if !c.expectingAck || uint8(n-c.txOldest) > uint8(c.txNewest-c.txOldest) {
		return ErrAck
	}
	if n == c.txNewest {
		c.expectingAck = false
	} else {
		c.txOldest = n + 1
		c.ackDeadline = now.Add(AckTimeout)
	}
	c.remoteWindow = c.window - (c.txNewest - n)
	return nil
}

// Send queues a message for the central. The message is copied.
func (c *Conn) Send(msg []byte) error {
	if c.st != stateOpen {
		return ErrClosed
	}
	if len(msg) > MaxMessage {
		return ErrTooLong
	}
	if c.qLen == queueLen {
		return ErrQueueFull
	}
	i := (c.qHead + c.qLen) % queueLen
	c.queue[i] = append(c.queue[i][:0], msg...)
	c.qLen++
	return nil
}

// Pending reports whether queued data or an acknowledgement remains to send.
func (c *Conn) Pending() bool { return c.qLen > 0 || c.rxUnacked }

// Flushed reports whether every queued message has been sent and
// acknowledged by the central.
func (c *Conn) Flushed() bool { return c.qLen == 0 && !c.expectingAck }

// Poll returns the next packet to send on C2, or nil, and the time Poll
// should next be called (zero if only on new input). The packet is valid
// until the next call; call Poll again until it returns nil. An error means
// the central stopped acknowledging and the connection should be dropped.
func (c *Conn) Poll(now time.Time) (pkt []byte, next time.Time, err error) {
	switch c.st {
	case stateOpen, stateRejected:
		if !c.respSent {
			return c.response(now), now, nil
		}
		if c.st == stateRejected {
			c.st = stateClosed
			return nil, time.Time{}, nil
		}
	default:
		return nil, time.Time{}, nil
	}
	if c.expectingAck && !now.Before(c.ackDeadline) {
		return nil, time.Time{}, ErrTimeout
	}
	if pkt = c.next(now); pkt != nil {
		return pkt, now, nil
	}
	if c.rxUnacked {
		next = c.sendAckAt
	}
	if c.expectingAck && (next.IsZero() || c.ackDeadline.Before(next)) {
		next = c.ackDeadline
	}
	return nil, next, nil
}

func (c *Conn) response(now time.Time) []byte {
	b := c.pkt[:6]
	b[0], b[1], b[2] = handshakeFlags, handshakeOpcode, c.version
	binary.LittleEndian.PutUint16(b[3:], uint16(c.frag))
	b[5] = c.window
	c.respSent = true
	if c.version == 0 {
		c.st = stateRejected
		return b
	}
	// The response counts as segment 0 and must be acknowledged.
	c.sent(now, 0)
	c.txSeq = 1
	return b
}

func (c *Conn) sent(now time.Time, seq uint8) {
	if !c.expectingAck {
		c.expectingAck, c.txOldest = true, seq
		c.ackDeadline = now.Add(AckTimeout)
	}
	c.txNewest = seq
	c.remoteWindow--
}

// next encodes the next data segment or standalone acknowledgement, if the
// central's receive window allows one.
func (c *Conn) next(now time.Time) []byte {
	if c.remoteWindow == 0 || c.remoteWindow <= noAckSendWindow && !c.rxUnacked {
		return nil
	}
	if c.qLen == 0 {
		if !c.rxUnacked || c.localWindow > immediateAckWindow && now.Before(c.sendAckAt) {
			return nil
		}
		b := c.pkt[:3]
		b[0], b[1], b[2] = flagAck, c.rxNewest, c.txSeq
		c.acked()
		c.sent(now, c.txSeq)
		c.txSeq++
		return b
	}
	msg := c.queue[c.qHead]
	b := c.pkt[:0]
	var flags uint8 = flagContinue
	if !c.txBusy {
		flags = flagStart
	}
	b = append(b, flags)
	if c.rxUnacked {
		b[0] |= flagAck
		b = append(b, c.rxNewest)
		c.acked()
	}
	b = append(b, c.txSeq)
	if !c.txBusy {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(msg)))
		c.txBusy, c.txOff = true, 0
	}
	n := min(c.frag-len(b), len(msg)-c.txOff)
	b = append(b, msg[c.txOff:c.txOff+n]...)
	c.txOff += n
	if c.txOff == len(msg) {
		b[0] |= flagEnd
		c.txBusy = false
		c.qHead, c.qLen = (c.qHead+1)%queueLen, c.qLen-1
	}
	c.sent(now, c.txSeq)
	c.txSeq++
	return b
}

func (c *Conn) acked() {
	c.rxUnacked = false
	c.localWindow = c.window
}

// ServiceData returns the 8-byte Matter BLE advertisement payload, to be
// placed in a Service Data AD structure for UUID 0xFFF6 (spec 5.4.2.5.6).
func ServiceData(discriminator, vendorID, productID uint16, extendedAnnouncement bool) [8]byte {
	var d [8]byte
	d[0] = 0 // opcode: commissionable
	// Discriminator in the low 12 bits; advertisement version 0 above it.
	binary.LittleEndian.PutUint16(d[1:], discriminator&0xFFF)
	binary.LittleEndian.PutUint16(d[3:], vendorID)
	binary.LittleEndian.PutUint16(d[5:], productID)
	if extendedAnnouncement {
		d[7] |= 0x02
	}
	return d
}

// AdvertisingData returns the full legacy advertising payload: the flags AD
// (LE General Discoverable, BR/EDR not supported) and the Matter service
// data. It is 15 bytes, well under the 31-byte limit.
func AdvertisingData(discriminator, vendorID, productID uint16) []byte {
	sd := ServiceData(discriminator, vendorID, productID, false)
	b := []byte{0x02, 0x01, 0x06, 0x0B, 0x16, ServiceUUID16 & 0xFF, ServiceUUID16 >> 8}
	return append(b, sd[:]...)
}

// Advertisement is what a commissionable device's Matter BLE service data
// says (spec 5.4.2.5.6).
type Advertisement struct {
	Discriminator        uint16 // 12 bits
	Version              uint8  // advertisement version (0)
	VendorID, ProductID  uint16
	AdditionalData       bool // C3 holds additional commissioning data
	ExtendedAnnouncement bool
}

// ParseServiceData decodes the service data of UUID 0xFFF6. ok is false if
// it is not a commissionable-device advertisement.
func ParseServiceData(b []byte) (a Advertisement, ok bool) {
	if len(b) < 7 || b[0] != 0 {
		return a, false
	}
	v := binary.LittleEndian.Uint16(b[1:])
	a.Discriminator, a.Version = v&0xFFF, uint8(v>>12)
	a.VendorID = binary.LittleEndian.Uint16(b[3:])
	a.ProductID = binary.LittleEndian.Uint16(b[5:])
	if len(b) > 7 {
		a.AdditionalData = b[7]&0x01 != 0
		a.ExtendedAnnouncement = b[7]&0x02 != 0
	}
	return a, true
}
