package im

import (
	"bytes"
	"errors"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// ErrNoResponse means a command got no response in time.
var ErrNoResponse = errors.New("im: no response")

// Invocation is a command a node sends as a client, without blocking (as a
// device calls an OTA provider's commands). Start it, then call Poll until
// Done has been called.
type Invocation struct {
	// Done is called once with the command's result: err is the transport
	// error, a malformed response, ErrNoResponse, or the Status the peer
	// failed the whole interaction with. A command-level failure is in
	// res.Status.
	Done func(now time.Time, res InvokeResult, err error)
	// Timeout is how long to wait for the response once the request is
	// sent (default 30 s).
	Timeout time.Duration

	ex       *exchange.Exchange
	deadline time.Time
	ended    bool
}

// Start sends the InvokeRequest for p on s.
func (inv *Invocation) Start(now time.Time, m *exchange.Manager, s *exchange.Session, p CommandPath, fields func(w *tlv.Writer)) error {
	ex, err := m.NewExchange(s, inv)
	if err != nil {
		return err
	}
	if inv.Timeout == 0 {
		inv.Timeout = 30 * time.Second
	}
	inv.ex, inv.deadline = ex, now.Add(inv.Timeout)
	if err := ex.Send(now, message.ProtocolInteractionModel, OpInvokeRequest, EncodeInvokeRequest(p, false, fields)); err != nil {
		ex.Close(now)
		inv.ended = true
		return err
	}
	return nil
}

// Pending reports whether the invocation has not finished.
func (inv *Invocation) Pending() bool { return inv.ex != nil && !inv.ended }

// Poll ends the invocation with ErrNoResponse once it times out, and
// returns when it next needs to run.
func (inv *Invocation) Poll(now time.Time) time.Time {
	if !inv.Pending() {
		return time.Time{}
	}
	if !now.Before(inv.deadline) {
		inv.ex.Close(now)
		inv.finish(now, InvokeResult{}, ErrNoResponse)
		return time.Time{}
	}
	return inv.deadline
}

func (inv *Invocation) finish(now time.Time, res InvokeResult, err error) {
	if inv.ended {
		return
	}
	inv.ended = true
	if inv.Done != nil {
		inv.Done(now, res, err)
	}
}

// OnMessage implements exchange.Delegate.
func (inv *Invocation) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if inv.ended {
		return
	}
	ex.Close(now)
	switch {
	case msg.ProtocolID != message.ProtocolInteractionModel:
		inv.finish(now, InvokeResult{}, errors.New("im: unexpected protocol"))
	case msg.Opcode == OpStatusResponse:
		st, err := DecodeStatusResponse(msg.Payload)
		if err == nil {
			err = st
		}
		inv.finish(now, InvokeResult{}, err)
	case msg.Opcode != OpInvokeResponse:
		inv.finish(now, InvokeResult{}, errors.New("im: unexpected response"))
	default:
		results, err := DecodeInvokeResponse(bytes.Clone(msg.Payload))
		if err == nil && len(results) != 1 {
			err = errors.New("im: expected one invoke result")
		}
		if err != nil {
			inv.finish(now, InvokeResult{}, err)
			return
		}
		inv.finish(now, results[0], nil)
	}
}

// OnError implements exchange.Delegate.
func (inv *Invocation) OnError(now time.Time, ex *exchange.Exchange, err error) {
	inv.finish(now, InvokeResult{}, err)
}
