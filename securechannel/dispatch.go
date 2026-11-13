package securechannel

import (
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
)

// Dispatcher accepts Secure Channel exchanges started by peers and routes
// each to a handler chosen by the opcode of its first message (for example
// PBKDFParamRequest to PASE and Sigma1 to CASE).
type Dispatcher struct {
	handlers map[uint8]exchange.Factory
}

// NewDispatcher returns a Dispatcher and registers it with m for the Secure
// Channel protocol.
func NewDispatcher(m *exchange.Manager) *Dispatcher {
	d := &Dispatcher{handlers: make(map[uint8]exchange.Factory)}
	m.Register(message.ProtocolSecureChannel, d.factory)
	return d
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
			// Unsolicited status reports (e.g. CloseSession) and unsupported
			// opcodes end here; the exchange layer acknowledges them.
			ex.Close(now)
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
