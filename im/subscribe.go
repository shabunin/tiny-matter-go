package im

import (
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const (
	// MaxSubscriptions bounds the subscriptions held at once (the spec asks
	// for at least 3 per fabric).
	MaxSubscriptions = 6
	// maxDirty bounds the changed paths remembered per subscription; more
	// changes report all of its paths.
	maxDirty = 8
	// maxIntervalLimit is SUBSCRIPTION_MAX_INTERVAL_PUBLISHER_LIMIT.
	maxIntervalLimit = time.Hour
)

type subState uint8

const (
	subPriming   subState = iota // initial report in progress
	subIdle                      // established, no report in flight
	subReporting                 // a report exchange is in flight
	subLost                      // kept for resumption, without a session
)

// subscription is an established or priming subscription.
type subscription struct {
	id       uint32
	session  *exchange.Session
	fabric   uint8
	peer     uint64
	paths    []AttributePath
	filtered bool // fabric-filtered
	min, max time.Duration
	state    subState
	last     time.Time      // when the last report started
	addr     netip.AddrPort // where the subscriber was last reached
	tries    uint8          // resumptions failed since it was last reported to

	dirty    []ConcretePath
	dirtyAll bool

	events    []EventPath
	eventNext uint64 // number of the first event not yet considered
	urgent    bool   // an event matching an urgent path is waiting
}

func (s *Server) removeSub(sub *subscription) {
	for i, x := range s.subs {
		if x == sub {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			if sub.state != subPriming {
				s.subsChanged()
			}
			return
		}
	}
}

// keeps reports whether lost subscriptions are kept for resumption.
func (s *Server) keeps() bool { return s.OnSubscriptionsChanged != nil }

func (s *Server) subsChanged() {
	if s.OnSubscriptionsChanged != nil {
		s.OnSubscriptionsChanged()
	}
}

// lose handles a report the subscriber did not answer. If the server
// keeps lost subscriptions, the session is taken for dead, as the SDK
// does: it is closed, so a resumption opens a new one, and the
// established subscriptions on it are kept for resumption. Otherwise the
// subscription ends.
func (s *Server) lose(now time.Time, sub *subscription) {
	if sub.state == subLost {
		return // with its session, closed below
	}
	if !s.keeps() || sub.state == subPriming {
		s.removeSub(sub)
		return
	}
	sess := sub.session
	for _, x := range s.subs {
		if x.session == sess && x.state != subPriming {
			x.session, x.state = nil, subLost
			if x.tries < 255 {
				x.tries++
			}
		}
	}
	s.subsChanged()
	s.m.CloseSession(now, sess) // fails the other exchanges on it
}

// Subscriptions returns the number of subscriptions held, lost ones
// included.
func (s *Server) Subscriptions() int { return len(s.subs) }

func matches(p *AttributePath, c ConcretePath) bool {
	return (p.AnyEndpoint || p.Endpoint == c.Endpoint) &&
		(p.AnyCluster || p.Cluster == c.Cluster) &&
		(p.AnyAttribute || p.Attribute == c.Attribute)
}

func matchesAny(paths []AttributePath, c ConcretePath) bool {
	for i := range paths {
		if matches(&paths[i], c) {
			return true
		}
	}
	return false
}

// logged marks the subscriptions with an urgent path covering an event
// for a report at their min interval; other events wait for the next
// report.
func (s *Server) logged(p ConcreteEventPath) {
	for _, sub := range s.subs {
		for i := range sub.events {
			if sub.events[i].IsUrgent && sub.events[i].Matches(p) {
				sub.urgent = true
				break
			}
		}
	}
}

// changed records an attribute change for the subscriptions covering it.
func (s *Server) changed(p ConcretePath) {
	for _, sub := range s.subs {
		if sub.dirtyAll || !matchesAny(sub.paths, p) {
			continue
		}
		seen := false
		for _, d := range sub.dirty {
			if d == p {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		if len(sub.dirty) >= maxDirty {
			sub.dirtyAll, sub.dirty = true, nil
			continue
		}
		sub.dirty = append(sub.dirty, p)
	}
}

func (h *handler) onSubscribe(now time.Time, ex *exchange.Exchange, b []byte) Status {
	var (
		keep              bool
		minFloor, maxCeil uint16
		haveMin, haveMax  bool
		rs                = &readState{}
	)
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			keep, err = r.Bool()
		case 1:
			minFloor, err = r.Uint16()
			haveMin = true
		case 2:
			maxCeil, err = r.Uint16()
			haveMax = true
		case 3:
			return arrayItems(r, func() error {
				p, err := DecodeAttributePath(r)
				if err != nil {
					return err
				}
				if len(rs.paths) >= maxReadPaths {
					return PathsExhausted
				}
				rs.paths = append(rs.paths, p)
				return nil
			})
		case 4:
			return rs.decodeEventPaths(r)
		case 5:
			return rs.decodeEventFilters(r)
		case 7:
			rs.fabricFiltered, err = r.Bool()
		case 8:
			return arrayItems(r, func() error {
				f, ok, err := decodeVersionFilter(r)
				if ok && len(rs.filters) < maxVersionFilters {
					rs.filters = append(rs.filters, f)
				}
				return err
			})
		}
		return err
	})
	if err != nil {
		if st, ok := err.(Status); ok {
			return st
		}
		return InvalidAction
	}
	if !haveMin || !haveMax || minFloor > maxCeil || (len(rs.paths) == 0 && len(rs.events) == 0) {
		return InvalidAction
	}
	sess := ex.Session()
	if sess.AuthMode != exchange.AuthCASE {
		return UnsupportedAccess
	}
	if !h.anyExistingPath(rs) {
		return InvalidAction // as the SDK does: nothing could ever be reported
	}
	if !keep {
		n := len(h.s.subs)
		for i := 0; i < len(h.s.subs); {
			x := h.s.subs[i]
			if x.fabric == sess.FabricIndex && x.peer == sess.PeerNodeID() {
				h.s.subs = append(h.s.subs[:i], h.s.subs[i+1:]...)
				continue
			}
			i++
		}
		if len(h.s.subs) != n {
			h.s.subsChanged()
		}
	}
	if len(h.s.subs) >= MaxSubscriptions {
		// A live subscription comes before one kept for resumption.
		for i, x := range h.s.subs {
			if x.state == subLost {
				h.s.subs = append(h.s.subs[:i], h.s.subs[i+1:]...)
				h.s.subsChanged()
				break
			}
		}
	}
	if len(h.s.subs) >= MaxSubscriptions {
		return ResourceExhausted
	}
	h.s.nextSubID++
	for h.s.sub(h.s.nextSubID) != nil || h.s.nextSubID == 0 { // restored IDs stay unique
		h.s.nextSubID++
	}
	maxInterval := time.Duration(maxCeil) * time.Second
	if maxInterval > maxIntervalLimit {
		maxInterval = maxIntervalLimit
	}
	if maxInterval < time.Duration(minFloor)*time.Second {
		maxInterval = time.Duration(minFloor) * time.Second
	}
	sub := &subscription{
		id: h.s.nextSubID, session: sess, fabric: sess.FabricIndex, peer: sess.PeerNodeID(),
		paths: rs.paths, filtered: rs.fabricFiltered, events: rs.events,
		min: time.Duration(minFloor) * time.Second, max: maxInterval,
		state: subPriming, last: now, addr: sess.Peer,
	}
	h.s.subs = append(h.s.subs, sub)
	rs.sub = sub
	h.read = rs
	h.sendReport(now, ex)
	return Success
}

// finishSubReport handles the StatusResponse to a subscription's last
// report chunk.
func (h *handler) finishSubReport(now time.Time, ex *exchange.Exchange) {
	sub := h.read.sub
	h.read = nil
	if sub.state == subPriming {
		w := tlv.NewWriter(h.s.buf[:0])
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(0), uint64(sub.id))
		w.PutUint(tlv.ContextTag(2), uint64(sub.max/time.Second))
		w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
		w.EndContainer()
		ex.Send(now, message.ProtocolInteractionModel, OpSubscribeResp, w.Bytes())
	}
	ex.Close(now)
	priming := sub.state == subPriming
	sub.state = subIdle
	if priming || sub.tries != 0 { // established, or resumed
		sub.tries = 0
		sub.addr = sub.session.Peer
		h.s.subsChanged()
	}
}

// due returns when sub next needs a report.
func (sub *subscription) due() time.Time {
	if sub.dirtyAll || len(sub.dirty) > 0 || sub.urgent {
		return sub.last.Add(sub.min)
	}
	return sub.last.Add(sub.max)
}

// Poll sends due subscription reports and returns when it next needs to run
// (zero if idle).
func (s *Server) Poll(now time.Time) time.Time {
	var next time.Time
	for i := 0; i < len(s.subs); {
		sub := s.subs[i]
		if sub.state == subLost {
			i++
			continue
		}
		if sub.session.Closed() {
			// The subscriber closed it (or its fabric went): as in the
			// SDK, that ends the subscription; only one the subscriber
			// stopped answering is kept.
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			if sub.state != subPriming {
				s.subsChanged()
			}
			continue
		}
		i++
		if sub.state != subIdle {
			continue
		}
		if t := sub.due(); now.Before(t) {
			if next.IsZero() || t.Before(next) {
				next = t
			}
			continue
		}
		s.report(now, sub)
		if sub.state == subIdle { // could not start; retry after min
			if t := now.Add(time.Second); next.IsZero() || t.Before(next) {
				next = t
			}
		}
	}
	return next
}

// report starts a report exchange for sub.
func (s *Server) report(now time.Time, sub *subscription) {
	h := &handler{s: s}
	ex, err := s.m.NewExchange(sub.session, h)
	if err != nil {
		return
	}
	rs := &readState{paths: sub.paths, fabricFiltered: sub.filtered, sub: sub,
		events: sub.events, eventNext: sub.eventNext, eventStatus: true}
	if !sub.dirtyAll {
		rs.dirty = append([]ConcretePath{}, sub.dirty...) // non-nil: changes only
	}
	sub.dirty, sub.dirtyAll, sub.urgent = sub.dirty[:0], false, false
	sub.state, sub.last = subReporting, now
	h.read = rs
	h.sendReport(now, ex)
}

// sub returns the subscription with the given ID, or nil.
func (s *Server) sub(id uint32) *subscription {
	for _, x := range s.subs {
		if x.id == id {
			return x
		}
	}
	return nil
}

// LostSubscription describes a subscription kept for resumption.
type LostSubscription struct {
	ID     uint32
	Fabric uint8
	Peer   uint64         // the subscriber's node ID
	Addr   netip.AddrPort // where it was last reached
	Min    time.Duration  // the subscription's min interval
	Tries  uint8          // resumptions failed so far
}

// Lost calls f for each subscription kept for resumption.
func (s *Server) Lost(f func(LostSubscription)) {
	for _, x := range s.subs {
		if x.state == subLost {
			f(LostSubscription{ID: x.id, Fabric: x.fabric, Peer: x.peer, Addr: x.addr, Min: x.min, Tries: x.tries})
		}
	}
}

// Resume continues a lost subscription on sess, a CASE session to its
// subscriber, with a report of all its paths, as the subscription it
// was (spec 8.5.1: the subscriber matches it by its ID). It reports
// whether the subscription was resumed.
func (s *Server) Resume(now time.Time, sess *exchange.Session, id uint32) bool {
	sub := s.sub(id)
	if sub == nil || sub.state != subLost || sess.Closed() || sess.AuthMode != exchange.AuthCASE ||
		sess.FabricIndex != sub.fabric || sess.PeerNodeID() != sub.peer {
		return false
	}
	sub.session, sub.state = sess, subIdle
	sub.dirty, sub.dirtyAll = sub.dirty[:0], true
	sub.last = now.Add(-sub.min) // due now
	return true
}

// ResumeFailed records a failed attempt to resume a lost subscription.
func (s *Server) ResumeFailed(id uint32) {
	if sub := s.sub(id); sub != nil && sub.state == subLost && sub.tries < 255 {
		sub.tries++
		s.subsChanged()
	}
}

// Drop ends a subscription.
func (s *Server) Drop(id uint32) {
	if sub := s.sub(id); sub != nil {
		s.removeSub(sub)
	}
}

// RemoveFabric ends the subscriptions of a removed fabric.
func (s *Server) RemoveFabric(index uint8) {
	n := len(s.subs)
	for i := 0; i < len(s.subs); {
		if s.subs[i].fabric == index {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			continue
		}
		i++
	}
	if len(s.subs) != n {
		s.subsChanged()
	}
}

// EncodeSubscriptions writes the established subscriptions, and those
// lost and kept for resumption, of the fabrics keep accepts, as an array
// under tag: what a restarted node needs to resume them.
func (s *Server) EncodeSubscriptions(w *tlv.Writer, tag tlv.Tag, keep func(fabricIndex uint8) bool) {
	w.StartArray(tag)
	for _, x := range s.subs {
		if x.state == subPriming || !keep(x.fabric) {
			continue
		}
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), uint64(x.id))
		w.PutUint(tlv.ContextTag(2), uint64(x.fabric))
		w.PutUint(tlv.ContextTag(3), x.peer)
		w.PutUint(tlv.ContextTag(4), uint64(x.min/time.Second))
		w.PutUint(tlv.ContextTag(5), uint64(x.max/time.Second))
		if x.filtered {
			w.PutBool(tlv.ContextTag(6), true)
		}
		if len(x.paths) > 0 {
			w.StartArray(tlv.ContextTag(7))
			for _, p := range x.paths {
				EncodeAttributePath(w, tlv.Anonymous, p)
			}
			w.EndContainer()
		}
		if len(x.events) > 0 {
			w.StartArray(tlv.ContextTag(8))
			for _, p := range x.events {
				EncodeEventPath(w, tlv.Anonymous, p)
			}
			w.EndContainer()
		}
		if x.addr.IsValid() {
			var b [18]byte
			a := x.addr.Addr().As16()
			copy(b[:], a[:])
			b[16], b[17] = byte(x.addr.Port()>>8), byte(x.addr.Port())
			w.PutBytes(tlv.ContextTag(9), b[:])
		}
		if x.tries != 0 {
			w.PutUint(tlv.ContextTag(10), uint64(x.tries))
		}
		w.EndContainer()
	}
	w.EndContainer()
}

// DecodeSubscriptions restores subscriptions EncodeSubscriptions wrote,
// as lost ones to resume. Those beyond MaxSubscriptions are ignored.
func (s *Server) DecodeSubscriptions(r *tlv.Reader) error {
	return arrayItems(r, func() error {
		sub := &subscription{state: subLost}
		var min, max uint16
		err := structFields(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 1:
				sub.id, err = r.Uint32()
			case 2:
				sub.fabric, err = r.Uint8()
			case 3:
				sub.peer, err = r.Uint()
			case 4:
				min, err = r.Uint16()
			case 5:
				max, err = r.Uint16()
			case 6:
				sub.filtered, err = r.Bool()
			case 7:
				return arrayItems(r, func() error {
					p, err := DecodeAttributePath(r)
					sub.paths = append(sub.paths, p)
					return err
				})
			case 8:
				return arrayItems(r, func() error {
					p, err := DecodeEventPath(r)
					sub.events = append(sub.events, p)
					return err
				})
			case 9:
				var b []byte
				if b, err = r.Bytes(); err == nil && len(b) == 18 {
					sub.addr = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[:16])).Unmap(), uint16(b[16])<<8|uint16(b[17]))
				}
			case 10:
				sub.tries, err = r.Uint8()
			}
			return err
		})
		if err != nil {
			return err
		}
		sub.min, sub.max = time.Duration(min)*time.Second, time.Duration(max)*time.Second
		if sub.id != 0 && sub.peer != 0 && len(s.subs) < MaxSubscriptions && s.sub(sub.id) == nil &&
			(len(sub.paths) > 0 || len(sub.events) > 0) {
			s.subs = append(s.subs, sub)
		}
		return nil
	})
}
