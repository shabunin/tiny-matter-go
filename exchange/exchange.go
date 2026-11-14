package exchange

import (
	"time"

	"github.com/shabunin/tiny-matter-go/message"
)

// Exchange is a request/response conversation with a peer (spec 4.10). Every
// message it sends is reliable (MRP), and at most one may be awaiting
// acknowledgement at a time.
type Exchange struct {
	m         *Manager
	s         *Session
	d         Delegate
	id        uint16
	initiator bool
	closing   bool // closed by the application; awaiting the last ack
	done      bool

	// Acknowledgement we owe the peer.
	ackPending  bool
	ackCounter  uint32
	ackDeadline time.Time

	// Our message awaiting acknowledgement.
	rtActive    bool
	rtPkt       []byte // retained encoded packet, reused across messages
	rtCounter   uint32
	rtSendCount int // retransmissions so far
	rtNext      time.Time
}

// ID returns the exchange ID.
func (ex *Exchange) ID() uint16 { return ex.id }

// Session returns the session the exchange runs on.
func (ex *Exchange) Session() *Session { return ex.s }

// IsInitiator reports whether this node started the exchange.
func (ex *Exchange) IsInitiator() bool { return ex.initiator }

// AwaitingAck reports whether the last message sent is unacknowledged.
func (ex *Exchange) AwaitingAck() bool { return ex.rtActive }

// Send sends a reliable message, piggybacking any pending acknowledgement.
func (ex *Exchange) Send(now time.Time, protocolID uint16, opcode uint8, payload []byte) error {
	if ex.done || ex.closing {
		return ErrExchangeClosed
	}
	if ex.rtActive {
		return ErrBusy
	}
	if ex.m.cfg.Clock != nil {
		// Time the retransmission from the real send time: the caller's
		// now may predate slow work such as a PASE or CASE computation.
		now = ex.m.cfg.Clock()
	}
	ph := message.ProtocolHeader{
		Initiator: ex.initiator, NeedsAck: true,
		Opcode: opcode, ExchangeID: ex.id, ProtocolID: protocolID,
	}
	if ex.ackPending {
		ph.HasAck, ph.AckCounter = true, ex.ackCounter
	}
	pkt, counter, err := ex.m.send(ex.s, &ph, payload)
	if err != nil {
		return err
	}
	ex.ackPending = false
	ex.rtPkt = append(ex.rtPkt[:0], pkt...)
	ex.rtActive, ex.rtCounter, ex.rtSendCount = true, counter, 0
	ex.rtNext = now.Add(Backoff(ex.s.retransBase(now), 0, randByte(ex.m.cfg.Rand)))
	ex.s.lastUse = now
	return nil
}

// Close ends the exchange. A pending acknowledgement is sent immediately; an
// unacknowledged message keeps being retransmitted until it is acknowledged
// or fails, without further callbacks.
func (ex *Exchange) Close(now time.Time) {
	if ex.done || ex.closing {
		return
	}
	if ex.ackPending {
		ex.ackPending = false
		ex.m.sendStandaloneAck(now, ex.s, ex.id, ex.initiator, ex.ackCounter)
	}
	ex.closing = true
	if !ex.rtActive {
		ex.done = true
	}
}

func (ex *Exchange) fail(now time.Time, err error) {
	ex.done = true
	ex.rtActive = false
	ex.ackPending = false
	if ex.d != nil && !ex.closing {
		ex.d.OnError(now, ex, err)
	}
}

// MaxPayload returns the largest application payload Send accepts on this
// exchange.
func (ex *Exchange) MaxPayload() int {
	h := ex.s.header(0)
	ph := message.ProtocolHeader{HasAck: true, NeedsAck: true}
	n := message.MaxPacketSize - h.Size() - ph.Size()
	if ex.s.secure {
		n -= message.MICSize
	}
	return n
}
