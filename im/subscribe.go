package im

import (
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
	last     time.Time // when the last report started

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
			return
		}
	}
}

// Subscriptions returns the number of subscriptions held.
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
	if !keep {
		for i := 0; i < len(h.s.subs); {
			x := h.s.subs[i]
			if x.fabric == sess.FabricIndex && x.peer == sess.PeerNodeID() {
				h.s.subs = append(h.s.subs[:i], h.s.subs[i+1:]...)
				continue
			}
			i++
		}
	}
	if len(h.s.subs) >= MaxSubscriptions {
		return ResourceExhausted
	}
	h.s.nextSubID++
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
		state: subPriming, last: now,
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
	sub.state = subIdle
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
		if sub.session.Closed() {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
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
