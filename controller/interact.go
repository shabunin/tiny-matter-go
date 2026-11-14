package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// responseTimeout bounds the wait for a response to a request the peer
// has acknowledged.
const responseTimeout = 30 * time.Second

var (
	errUnexpected      = errors.New("controller: unexpected response")
	errResponseTimeout = errors.New("controller: no response")
)

// request runs one Interaction Model transaction on its own exchange: an
// optional TimedRequest, the request, and its responses.
type request struct {
	c       *Controller
	ex      *exchange.Exchange
	op      uint8
	payload []byte
	timeout uint16 // timed interaction window in ms (0: untimed)
	timedOK bool
	// handle processes a response (its payload owned by the handler) and
	// reports whether the transaction is over.
	handle func(now time.Time, op uint8, b []byte) (done bool, err error)
	finish func(err error)
	over   bool
}

// start sends the request on s (loop goroutine).
func (r *request) start(now time.Time, s *exchange.Session) error {
	ex, err := r.c.m.NewExchange(s, r)
	if err != nil {
		return err
	}
	r.ex = ex
	if r.timeout > 0 {
		return ex.Send(now, message.ProtocolInteractionModel, im.OpTimedRequest, im.EncodeTimedRequest(r.timeout))
	}
	return ex.Send(now, message.ProtocolInteractionModel, r.op, r.payload)
}

func (r *request) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if r.over {
		return
	}
	if msg.ProtocolID != message.ProtocolInteractionModel {
		r.end(now, errUnexpected)
		return
	}
	b := bytes.Clone(msg.Payload)
	if r.timeout > 0 && !r.timedOK {
		st, err := im.DecodeStatusResponse(b)
		switch {
		case msg.Opcode != im.OpStatusResponse || err != nil:
			r.end(now, errUnexpected)
		case st != im.Success:
			r.end(now, st)
		default:
			r.timedOK = true
			if err := ex.Send(now, message.ProtocolInteractionModel, r.op, r.payload); err != nil {
				r.end(now, err)
			}
		}
		return
	}
	if msg.Opcode == im.OpStatusResponse {
		st, err := im.DecodeStatusResponse(b)
		if err == nil && st == im.Success {
			err = errUnexpected
		} else if err == nil {
			err = st
		}
		r.end(now, err)
		return
	}
	done, err := r.handle(now, msg.Opcode, b)
	if done || err != nil {
		r.end(now, err)
	}
}

func (r *request) OnError(now time.Time, ex *exchange.Exchange, err error) { r.end(now, err) }

func (r *request) end(now time.Time, err error) {
	if r.over {
		return
	}
	r.over = true
	if r.ex != nil {
		r.ex.Close(now)
	}
	r.finish(err)
}

// sendStatus acknowledges a report chunk with a StatusResponse.
func sendStatus(now time.Time, ex *exchange.Exchange, st im.Status) error {
	return ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(st))
}

// run starts r on s and waits for it to finish.
func (c *Controller) run(ctx context.Context, s *exchange.Session, r *request) error {
	res := make(chan error, 1)
	r.c = c
	r.finish = func(err error) { res <- err }
	err := c.do(func(now time.Time) {
		if err := r.start(now, s); err != nil {
			r.over = true
			res <- err
		}
	})
	if err != nil {
		return err
	}
	timer := time.NewTimer(responseTimeout)
	defer timer.Stop()
	select {
	case err := <-res:
		return err
	case <-ctx.Done():
	case <-timer.C:
	}
	// Give up: close the exchange; a late response is dropped.
	c.do(func(now time.Time) { r.end(now, errResponseTimeout) })
	if err := <-res; err != errResponseTimeout {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errResponseTimeout
}

// Report is the merged result of a read: attribute reports and events.
type Report struct {
	Attributes []im.AttributeReport
	Events     []im.EventReport
}

func (rep *Report) add(rd *im.ReportData) {
	rep.Attributes = append(rep.Attributes, rd.Reports...)
	rep.Events = append(rep.Events, rd.Events...)
}

// readOn reads on a session, merging the chunks of the report.
func (c *Controller) readOn(ctx context.Context, s *exchange.Session, q im.Request) (*Report, error) {
	rep := &Report{}
	r := &request{op: im.OpReadRequest, payload: im.EncodeRead(q)}
	r.handle = func(now time.Time, op uint8, b []byte) (bool, error) {
		if op != im.OpReportData {
			return true, errUnexpected
		}
		rd, err := im.DecodeReportData(b)
		if err != nil {
			return true, err
		}
		rep.add(rd)
		if rd.MoreChunks {
			return false, sendStatus(now, r.ex, im.Success)
		}
		if !rd.SuppressResponse {
			sendStatus(now, r.ex, im.Success)
		}
		return true, nil
	}
	return rep, c.run(ctx, s, r)
}

// invokeOn invokes one command on a session and returns its result.
func (c *Controller) invokeOn(ctx context.Context, s *exchange.Session, p im.CommandPath, timed uint16, fields func(w *tlv.Writer)) (im.InvokeResult, error) {
	var res im.InvokeResult
	r := &request{op: im.OpInvokeRequest, payload: im.EncodeInvokeRequest(p, timed > 0, fields), timeout: timed}
	r.handle = func(now time.Time, op uint8, b []byte) (bool, error) {
		if op != im.OpInvokeResponse {
			return true, errUnexpected
		}
		results, err := im.DecodeInvokeResponse(b)
		if err != nil {
			return true, err
		}
		if len(results) != 1 {
			return true, fmt.Errorf("controller: %d invoke results", len(results))
		}
		res = results[0]
		return true, nil
	}
	if err := c.run(ctx, s, r); err != nil {
		return res, err
	}
	if res.Status != im.Success {
		return res, &CommandError{Status: res.Status, ClusterStatus: res.ClusterStatus, HasClusterStatus: res.HasClusterStatus}
	}
	return res, nil
}

// CommandError is a command that failed with a status.
type CommandError struct {
	Status           im.Status
	ClusterStatus    uint8
	HasClusterStatus bool
}

func (e *CommandError) Error() string {
	if e.HasClusterStatus {
		return fmt.Sprintf("command failed: status %#x, cluster status %d", uint8(e.Status), e.ClusterStatus)
	}
	return fmt.Sprintf("command failed: status %#x", uint8(e.Status))
}

// writeOn writes one attribute on a session.
func (c *Controller) writeOn(ctx context.Context, s *exchange.Session, p im.AttributePath, timed uint16, value func(w *tlv.Writer, tag tlv.Tag)) error {
	var st im.Status
	r := &request{op: im.OpWriteRequest, payload: im.EncodeWriteRequest(p, timed > 0, value), timeout: timed}
	r.handle = func(now time.Time, op uint8, b []byte) (bool, error) {
		if op != im.OpWriteResponse {
			return true, errUnexpected
		}
		reps, err := im.DecodeWriteResponse(b)
		if err != nil {
			return true, err
		}
		for _, rep := range reps {
			if rep.Status != im.Success {
				st = rep.Status
			}
		}
		return true, nil
	}
	if err := c.run(ctx, s, r); err != nil {
		return err
	}
	if st != im.Success {
		return st
	}
	return nil
}

// Read reads attributes and events from a node.
func (c *Controller) Read(ctx context.Context, node uint64, q im.Request) (*Report, error) {
	var rep *Report
	err := c.withSession(ctx, node, func(s *exchange.Session) (err error) {
		rep, err = c.readOn(ctx, s, q)
		return err
	})
	return rep, err
}

// Invoke invokes a command on a node. A nonzero timed (ms) makes it a
// timed invoke, which some commands require.
func (c *Controller) Invoke(ctx context.Context, node uint64, p im.CommandPath, timed uint16, fields func(w *tlv.Writer)) (im.InvokeResult, error) {
	var res im.InvokeResult
	err := c.withSession(ctx, node, func(s *exchange.Session) (err error) {
		res, err = c.invokeOn(ctx, s, p, timed, fields)
		return err
	})
	return res, err
}

// Write writes one attribute of a node; value writes it with the tag it
// is given. A nonzero timed (ms) makes it a timed write.
func (c *Controller) Write(ctx context.Context, node uint64, p im.AttributePath, timed uint16, value func(w *tlv.Writer, tag tlv.Tag)) error {
	return c.withSession(ctx, node, func(s *exchange.Session) error {
		return c.writeOn(ctx, s, p, timed, value)
	})
}

// SubscribeOptions configure a subscription.
type SubscribeOptions struct {
	// MinInterval and MaxInterval bound the reporting interval in
	// seconds; the device may raise the maximum.
	MinInterval, MaxInterval uint16
	// OnReport receives each report, the priming one first. It runs on its
	// own goroutine, one report at a time.
	OnReport func(rd *im.ReportData)
	// OnStatus, if set, hears when the subscription is lost (err) and
	// established again (nil).
	OnStatus func(err error)
}

// Subscription is a subscription to a node that re-subscribes when it is
// lost.
type Subscription struct {
	c      *Controller
	node   uint64
	q      im.Request
	opts   SubscribeOptions
	ctx    context.Context
	cancel context.CancelFunc
	queue  chan func()
	done   chan struct{}
}

// subState is an established subscription (loop goroutine).
type subState struct {
	sub         *Subscription
	id          uint32
	session     *exchange.Session
	maxInterval time.Duration
	last        time.Time
	lost        chan error
}

// Subscribe subscribes to attributes and events of a node. It returns
// once the first subscription is established; afterwards, a lost
// subscription is established again until Close.
func (c *Controller) Subscribe(ctx context.Context, node uint64, q im.Request, opts SubscribeOptions) (*Subscription, error) {
	if opts.MaxInterval == 0 {
		opts.MaxInterval = 60
	}
	sub := &Subscription{c: c, node: node, q: q, opts: opts,
		queue: make(chan func(), 256), done: make(chan struct{})}
	sub.ctx, sub.cancel = context.WithCancel(context.Background())
	go sub.deliver()
	st, err := sub.establish(ctx)
	if err != nil {
		sub.cancel()
		close(sub.queue)
		return nil, err
	}
	go sub.keep(st)
	return sub, nil
}

// Close ends the subscription.
func (s *Subscription) Close() {
	s.cancel()
	<-s.done
}

// deliver runs the callbacks in order.
func (s *Subscription) deliver() {
	for f := range s.queue {
		f()
	}
}

func (s *Subscription) post(f func()) {
	select {
	case s.queue <- f:
	case <-s.ctx.Done():
	}
}

// establish subscribes once.
func (s *Subscription) establish(ctx context.Context) (*subState, error) {
	st := &subState{sub: s, lost: make(chan error, 1)}
	err := s.c.withSession(ctx, s.node, func(sess *exchange.Session) error {
		st.session = sess
		r := &request{op: im.OpSubscribeRequest,
			payload: im.EncodeSubscribe(s.q, s.opts.MinInterval, s.opts.MaxInterval, false)}
		r.handle = func(now time.Time, op uint8, b []byte) (bool, error) {
			switch op {
			case im.OpReportData:
				rd, err := im.DecodeReportData(b)
				if err != nil {
					return true, err
				}
				if s.opts.OnReport != nil {
					s.post(func() { s.opts.OnReport(rd) })
				}
				return false, sendStatus(now, r.ex, im.Success)
			case im.OpSubscribeResp:
				id, maxInterval, err := im.DecodeSubscribeResponse(b)
				if err != nil {
					return true, err
				}
				st.id, st.maxInterval, st.last = id, time.Duration(maxInterval)*time.Second, now
				s.c.subs[id] = st
				return true, nil
			}
			return true, errUnexpected
		}
		return s.c.run(ctx, sess, r)
	})
	if err != nil {
		return nil, err
	}
	return st, nil
}

// keep waits for the subscription to be lost and establishes it again,
// backing off while that fails.
func (s *Subscription) keep(st *subState) {
	defer func() {
		close(s.queue)
		close(s.done)
	}()
	for {
		select {
		case err := <-st.lost:
			if s.opts.OnStatus != nil {
				s.post(func() { s.opts.OnStatus(err) })
			}
		case <-s.ctx.Done():
			s.c.do(func(time.Time) { delete(s.c.subs, st.id) })
			return
		}
		for backoff := time.Second; ; backoff = min(2*backoff, 30*time.Second) {
			var err error
			if st, err = s.establish(s.ctx); err == nil {
				if s.opts.OnStatus != nil {
					s.post(func() { s.opts.OnStatus(nil) })
				}
				break
			}
			select {
			case <-time.After(backoff):
			case <-s.ctx.Done():
				return
			}
		}
	}
}

// pollSubs declares subscriptions lost when no report arrived within
// their max interval and some slack (loop goroutine). It returns the next
// deadline.
func (c *Controller) pollSubs(now time.Time) time.Time {
	var next time.Time
	for id, st := range c.subs {
		deadline := st.last.Add(st.maxInterval + st.maxInterval/2 + 10*time.Second)
		if st.session.Closed() || !now.Before(deadline) {
			delete(c.subs, id)
			st.lost <- fmt.Errorf("subscription %#x lost", id)
			continue
		}
		if next.IsZero() || deadline.Before(next) {
			next = deadline
		}
	}
	return next
}

// imFactory accepts exchanges a device starts: subscription reports.
func (c *Controller) imFactory(ex *exchange.Exchange) exchange.Delegate { return &reportHandler{c: c} }

type reportHandler struct{ c *Controller }

func (h *reportHandler) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if msg.ProtocolID != message.ProtocolInteractionModel || msg.Opcode != im.OpReportData {
		sendStatus(now, ex, im.InvalidAction)
		ex.Close(now)
		return
	}
	rd, err := im.DecodeReportData(bytes.Clone(msg.Payload))
	var st *subState
	if err == nil {
		st = h.c.subs[rd.SubscriptionID]
	}
	if st == nil || st.session != ex.Session() {
		sendStatus(now, ex, im.InvalidSubscription)
		ex.Close(now)
		return
	}
	st.last = now
	if len(rd.Reports) > 0 || len(rd.Events) > 0 {
		if f := st.sub.opts.OnReport; f != nil {
			st.sub.post(func() { f(rd) })
		}
	}
	if rd.SuppressResponse && !rd.MoreChunks {
		ex.Close(now)
		return
	}
	sendStatus(now, ex, im.Success)
	if !rd.MoreChunks {
		ex.Close(now)
	}
}

func (h *reportHandler) OnError(time.Time, *exchange.Exchange, error) {}
