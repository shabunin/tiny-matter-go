package securechannel

import (
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
)

// Dispatcher accepts Secure Channel exchanges started by peers and routes
// each to a handler chosen by the opcode of its first message (for example
// PBKDFParamRequest to PASE and Sigma1 to CASE).
//
// A CloseSession status report from the peer of a secure session, unless
// a handler takes status reports, closes the session.
type Dispatcher struct {
	m        *exchange.Manager
	handlers map[uint8]exchange.Factory
}

// NewDispatcher returns a Dispatcher and registers it with m for the Secure
// Channel protocol.
func NewDispatcher(m *exchange.Manager) *Dispatcher {
	d := &Dispatcher{m: m, handlers: make(map[uint8]exchange.Factory)}
	m.Register(message.ProtocolSecureChannel, d.factory)
	return d
}

// CloseSession tells the peer that a secure session ends, with a
// CloseSession status report that asks for no acknowledgement (spec
// 4.10.1.4), and closes it.
func CloseSession(now time.Time, m *exchange.Manager, s *exchange.Session) error {
	if s.Closed() {
		return nil
	}
	defer m.CloseSession(now, s)
	if !s.IsSecure() {
		return nil
	}
	ex, err := m.NewExchange(s, nil)
	if err != nil {
		return err
	}
	sr := SecureChannelStatus(GeneralSuccess, CodeCloseSession)
	err = ex.SendUnacked(now, message.ProtocolSecureChannel, OpStatusReport, sr.AppendTo(nil))
	ex.Close(now)
	return err
}

// Handle routes exchanges whose first message has opcode op to f.
func (d *Dispatcher) Handle(op uint8, f exchange.Factory) { d.handlers[op] = f }

func (d *Dispatcher) factory(ex *exchange.Exchange) exchange.Delegate {
	return &router{d: d}
}

// router picks the real delegate on the first message.
type router struct {
	d     *Dispatcher
	inner exchange.Delegate
}

func (r *router) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if r.inner == nil {
		if f := r.d.handlers[msg.Opcode]; f != nil {
			r.inner = f(ex)
		}
		if r.inner == nil {
			// Unsolicited status reports and unsupported opcodes end here;
			// the exchange layer acknowledges them.
			ex.Close(now)
			if msg.Opcode == OpStatusReport && ex.Session().IsSecure() {
				if sr, err := ParseStatusReport(msg.Payload); err == nil &&
					sr.ProtocolID == uint32(message.ProtocolSecureChannel) && sr.ProtocolCode == CodeCloseSession {
					r.d.m.CloseSession(now, ex.Session())
				}
			}
			return
		}
	}
	r.inner.OnMessage(now, ex, msg)
}

func (r *router) OnError(now time.Time, ex *exchange.Exchange, err error) {
	if r.inner != nil {
		r.inner.OnError(now, ex, err)
	}
}
