package im

import (
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Spec limits this server advertises.
const (
	// MaxPathsPerInvoke matches the session parameter we advertise.
	MaxPathsPerInvoke = 1
	// maxReadPaths bounds the attribute paths, and separately the event
	// paths, accepted in one read or subscription.
	maxReadPaths = 32
	// maxVersionFilters bounds the data version filters kept from a read.
	maxVersionFilters = 32
	// reportReserve is the room kept for closing a ReportData message.
	reportReserve = 12
)

// Server serves the Interaction Model for a node.
type Server struct {
	node *Node
	m    *exchange.Manager
	buf  []byte // shared encode buffer; messages are sent synchronously
	// Access, if set, enforces access control; nil allows everything.
	Access AccessChecker
	// GroupEndpoints, if set, returns the endpoints that are members of a
	// group on a fabric, which commands and writes sent to the group reach.
	// Without it, group messages are ignored.
	GroupEndpoints func(fabricIndex uint8, groupID uint16) []uint16
	// OnWritten, if set, is called after a client writes an attribute
	// (after the node's OnChange for it), so configuration a client sets
	// can be saved at once.
	OnWritten func(p ConcretePath)
	// OnInvoked, if set, is called after a command a client sent ran
	// successfully (a status of Success, or a response command).
	OnInvoked func(ctx *Context, p CommandPath)
	// OnSubscriptionsChanged, if set, makes the server keep a subscription
	// whose subscriber stopped answering for resumption (Lost, Resume)
	// instead of ending it, and is called when the subscriptions
	// EncodeSubscriptions writes change, to save them.
	OnSubscriptionsChanged func()

	subs      []*subscription
	nextSubID uint32
}

// written reports a successful write of p.
func (s *Server) written(p ConcretePath) {
	s.node.Changed(p.Endpoint, p.Cluster, p.Attribute)
	if s.OnWritten != nil {
		s.OnWritten(p)
	}
}

// NewServer returns a Server for n and registers it with m. It chains
// itself into n.OnChange and n.OnEvent to drive subscriptions; call Poll
// to send their reports.
func NewServer(m *exchange.Manager, n *Node) *Server {
	s := &Server{node: n, m: m, buf: make([]byte, 0, message.MaxPacketSize), nextSubID: n.version * 0x9E3779B1}
	m.Register(message.ProtocolInteractionModel, s.factory)
	prev := n.OnChange
	n.OnChange = func(p ConcretePath) {
		s.changed(p)
		if prev != nil {
			prev(p)
		}
	}
	prevEvent := n.OnEvent
	n.OnEvent = func(p ConcreteEventPath) {
		s.logged(p)
		if prevEvent != nil {
			prevEvent(p)
		}
	}
	return s
}

// Accept takes an exchange a client starts (exchange.Factory), for a node
// that routes Interaction Model exchanges itself instead of letting
// NewServer register the server.
func (s *Server) Accept(ex *exchange.Exchange) exchange.Delegate { return s.factory(ex) }

func (s *Server) factory(ex *exchange.Exchange) exchange.Delegate {
	if !ex.Session().IsSecure() {
		return nil // the Interaction Model needs a secure session
	}
	return &handler{s: s}
}

type versionFilter struct {
	endpoint uint16
	cluster  uint32
	version  uint32
}

type readState struct {
	paths          []AttributePath
	filters        []versionFilter
	fabricFiltered bool
	next           int // index of the first candidate path not yet reported
	// When a list too large for one message is split across chunks,
	// inList is set and item is the index of the next item to report.
	inList bool
	item   int

	events      []EventPath
	eventNext   uint64 // number of the first event not yet considered
	eventStatus bool   // statuses of the concrete event paths were sent

	// Subscriptions only.
	sub   *subscription
	dirty []ConcretePath // changed paths to report; nil reports all paths
	done  bool           // last chunk sent, awaiting its StatusResponse
}

type writeState struct {
	timed bool
	auth  []ConcretePath // list-replace paths authorized in earlier chunks
}

// handler serves one exchange.
type handler struct {
	s     *Server
	read  *readState  // read in progress, awaiting a StatusResponse
	write *writeState // chunked write in progress
	timed time.Time   // deadline of a preceding TimedRequest
}

func (h *handler) ctx(now time.Time, ex *exchange.Exchange) *Context {
	return &Context{Now: now, Node: h.s.node, Session: ex.Session()}
}

func (h *handler) OnError(now time.Time, ex *exchange.Exchange, err error) { h.abort(now, true) }

// abort ends the read, report, timed state, or chunked write in progress.
// A subscription report the subscriber did not answer (lost) loses the
// subscription; one it refused ends it.
func (h *handler) abort(now time.Time, lost bool) {
	if h.read != nil && h.read.sub != nil {
		if lost {
			h.s.lose(now, h.read.sub)
		} else {
			h.s.removeSub(h.read.sub)
		}
	}
	h.read = nil
	h.write = nil
	h.timed = time.Time{}
}

func (h *handler) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if ex.Session().IsGroup() {
		h.onGroup(now, ex, msg)
		return
	}
	if msg.ProtocolID != message.ProtocolInteractionModel {
		ex.Close(now)
		return
	}
	var st Status
	switch msg.Opcode {
	case OpReadRequest:
		if h.read != nil || h.write != nil {
			st = InvalidAction
			break
		}
		st = h.onRead(now, ex, msg.Payload)
	case OpSubscribeRequest:
		if h.read != nil || h.write != nil {
			st = InvalidAction
			break
		}
		st = h.onSubscribe(now, ex, msg.Payload)
	case OpStatusResponse:
		if h.read == nil {
			ex.Close(now)
			return
		}
		if s, err := decodeStatusResponse(msg.Payload); err != nil || s != Success {
			h.abort(now, false)
			ex.Close(now)
			return
		}
		if h.read.done {
			h.finishSubReport(now, ex)
			return
		}
		h.sendReport(now, ex)
		return
	case OpTimedRequest:
		if h.read != nil || h.write != nil {
			st = InvalidAction
			break
		}
		st = h.onTimed(now, ex, msg.Payload)
		if st == Success {
			h.sendStatus(now, ex, Success, false)
			return
		}
	case OpInvokeRequest:
		if h.read != nil || h.write != nil {
			st = InvalidAction
			break
		}
		st = h.onInvoke(now, ex, msg.Payload)
	case OpWriteRequest:
		if h.read != nil {
			st = InvalidAction
			break
		}
		st = h.onWrite(now, ex, msg.Payload)
	default:
		st = InvalidAction
	}
	if st != Success {
		h.abort(now, false)
		h.sendStatus(now, ex, st, true)
	}
}

// sendStatus sends a StatusResponse, closing the exchange if close is set.
func (h *handler) sendStatus(now time.Time, ex *exchange.Exchange, st Status, close bool) {
	w := tlv.NewWriter(h.s.buf[:0])
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(0), uint64(st))
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	ex.Send(now, message.ProtocolInteractionModel, OpStatusResponse, w.Bytes())
	if close {
		ex.Close(now)
	}
}

func decodeStatusResponse(b []byte) (Status, error) {
	st := Failure
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) error {
		if tag == 0 {
			v, err := r.Uint8()
			st = Status(v)
			return err
		}
		return nil
	})
	return st, err
}

func (h *handler) onTimed(now time.Time, ex *exchange.Exchange, b []byte) Status {
	var ms uint16
	seen := false
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		if tag == 0 {
			ms, err = r.Uint16()
			seen = true
		}
		return err
	})
	if err != nil || !seen {
		return InvalidAction
	}
	h.timed = now.Add(time.Duration(ms) * time.Millisecond)
	return Success
}

// checkTimed validates the TimedRequest flag of a write or invoke against
// the exchange's timed state.
func (h *handler) checkTimed(now time.Time, flag bool) Status {
	deadline := h.timed
	h.timed = time.Time{}
	if flag != !deadline.IsZero() {
		return TimedRequestMismatch
	}
	if flag && now.After(deadline) {
		return Timeout
	}
	return Success
}

// ---- Read ----

func (h *handler) onRead(now time.Time, ex *exchange.Exchange, b []byte) Status {
	rs := &readState{}
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
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
		case 1:
			return rs.decodeEventPaths(r)
		case 2:
			return rs.decodeEventFilters(r)
		case 3:
			rs.fabricFiltered, err = r.Bool()
		case 4:
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
	h.read = rs
	h.sendReport(now, ex)
	return Success
}

func (rs *readState) decodeEventPaths(r *tlv.Reader) error {
	return arrayItems(r, func() error {
		p, err := DecodeEventPath(r)
		if err != nil {
			return err
		}
		if len(rs.events) >= maxReadPaths {
			return PathsExhausted
		}
		rs.events = append(rs.events, p)
		return nil
	})
}

// decodeEventFilters keeps the highest EventMin of the filters.
func (rs *readState) decodeEventFilters(r *tlv.Reader) error {
	return arrayItems(r, func() error {
		min, err := decodeEventFilter(r)
		if min > rs.eventNext {
			rs.eventNext = min
		}
		return err
	})
}

func decodeVersionFilter(r *tlv.Reader) (f versionFilter, ok bool, err error) {
	var have uint8
	err = structFields(r, func(r *tlv.Reader, tag uint8) error {
		switch tag {
		case 0:
			if r.Type() != tlv.TypeList {
				return errMalformed
			}
			return arrayItems(r, func() (err error) {
				switch {
				case r.Tag().IsContext(1):
					f.endpoint, err = r.Uint16()
					have |= 1
				case r.Tag().IsContext(2):
					f.cluster, err = r.Uint32()
					have |= 2
				}
				return err
			})
		case 1:
			v, err := r.Uint32()
			f.version = v
			have |= 4
			return err
		}
		return nil
	})
	return f, have == 7, err
}

// candidate is one attribute a read may report: a concrete path, or an
// expansion of a wildcard path (whose errors are silently skipped).
type candidate struct {
	path     ConcretePath
	wildcard bool
	status   Status // non-success: report this status for a concrete path
	cluster  Cluster
	version  uint32
}

// candidates calls f for each candidate of the read in order until f
// returns false.
func (h *handler) candidates(rs *readState, f func(c *candidate) bool) {
	node := h.s.node
	var c candidate
	if rs.dirty != nil {
		// A subscription report: the changed attributes it covers.
		for _, d := range rs.dirty {
			if !matchesAny(rs.paths, d) {
				continue
			}
			e := node.Endpoint(d.Endpoint)
			if e == nil {
				continue
			}
			ce := e.entry(d.Cluster)
			if ce == nil {
				continue
			}
			c = candidate{path: d, wildcard: true, cluster: ce.c, version: ce.version}
			if !f(&c) {
				return
			}
		}
		return
	}
	for i := range rs.paths {
		p := &rs.paths[i]
		if !p.IsWildcard() {
			c = candidate{path: ConcretePath{p.Endpoint, p.Cluster, p.Attribute}}
			if e := node.Endpoint(p.Endpoint); e == nil {
				c.status = UnsupportedEndpoint
			} else if ce := e.entry(p.Cluster); ce == nil {
				c.status = UnsupportedCluster
			} else if !hasAttribute(ce.c, p.Attribute) {
				c.status = UnsupportedAttribute
			} else {
				c.cluster, c.version = ce.c, ce.version
				if filtered(rs, p.Endpoint, p.Cluster, ce.version) {
					continue
				}
			}
			if !f(&c) {
				return
			}
			continue
		}
		for _, e := range node.endpoints {
			if !p.AnyEndpoint && e.ID != p.Endpoint {
				continue
			}
			for ci := range e.clusters {
				ce := &e.clusters[ci]
				cid := ce.c.ID()
				if !p.AnyCluster && cid != p.Cluster {
					continue
				}
				if filtered(rs, e.ID, cid, ce.version) {
					continue
				}
				c = candidate{path: ConcretePath{Endpoint: e.ID, Cluster: cid}, wildcard: true, cluster: ce.c, version: ce.version}
				for _, a := range ce.c.Attributes() {
					if !p.AnyAttribute && a != p.Attribute {
						continue
					}
					c.path.Attribute = a
					if !f(&c) {
						return
					}
				}
				for _, a := range globalAttributes {
					if !p.AnyAttribute && a != p.Attribute {
						continue
					}
					c.path.Attribute = a
					if !f(&c) {
						return
					}
				}
			}
		}
	}
}

func filtered(rs *readState, endpoint uint16, cluster, version uint32) bool {
	for _, f := range rs.filters {
		if f.endpoint == endpoint && f.cluster == cluster && f.version == version {
			return true
		}
	}
	return false
}

// sendReport sends the next ReportData chunk of the read in progress:
// attribute reports first, then events.
func (h *handler) sendReport(now time.Time, ex *exchange.Exchange) {
	rs := h.read
	ctx := h.ctx(now, ex)
	ctx.FabricFiltered = rs.fabricFiltered
	limit := ex.MaxPayload() - reportReserve

	w := tlv.NewWriter(h.s.buf[:0])
	w.StartStruct(tlv.Anonymous)
	if rs.sub != nil {
		w.PutUint(tlv.ContextTag(0), uint64(rs.sub.id))
	}
	inChunk, more := h.encodeAttributes(ctx, rs, w, limit)
	if !more && len(rs.events) > 0 {
		more = h.encodeEvents(ctx, rs, w, limit, inChunk > 0)
		if rs.sub != nil {
			rs.sub.eventNext = rs.eventNext
		}
	}
	if more {
		w.PutBool(tlv.ContextTag(3), true)
	} else if rs.sub == nil {
		w.PutBool(tlv.ContextTag(4), true) // SuppressResponse
	}
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	ex.Send(now, message.ProtocolInteractionModel, OpReportData, w.Bytes())
	if !more {
		if rs.sub == nil {
			h.read = nil
			ex.Close(now)
		} else {
			rs.done = true // subscriptions want a StatusResponse
		}
	}
}

// encodeAttributes writes the AttributeReports of the next chunk,
// returning how many it wrote and whether more remain for later chunks.
func (h *handler) encodeAttributes(ctx *Context, rs *readState, w *tlv.Writer, limit int) (inChunk int, more bool) {
	arrayStart := w.Checkpoint()
	w.StartArray(tlv.ContextTag(1))
	index := 0
	h.candidates(rs, func(c *candidate) bool {
		i := index
		index++
		if i < rs.next {
			return true
		}
		cp := w.Checkpoint()
		if c.status == Success && !h.s.allowed(ctx, c.path.Endpoint, c.path.Cluster, readPrivilege(c.cluster, c.path.Attribute)) {
			if c.wildcard {
				rs.next = i + 1
				return true
			}
			c.status = UnsupportedAccess
		}
		var wrote bool
		if !rs.inList {
			wrote = encodeReport(ctx, w, c)
		}
		if rs.inList || w.Len() > limit {
			if !rs.inList {
				w.Rollback(cp)
				if inChunk > 0 {
					more = true // the attribute starts the next chunk
					return false
				}
			}
			n, next, done := encodeListChunk(ctx, w, c, rs.inList, rs.item, limit)
			inChunk += n
			if !done {
				rs.inList, rs.item = true, next
				more = true
				return false
			}
			rs.inList, rs.item = false, 0
		}
		rs.next = i + 1
		if wrote {
			inChunk++
		}
		return true
	})
	if inChunk == 0 {
		w.Rollback(arrayStart) // nothing to report (a keep-alive)
	} else {
		w.EndContainer()
	}
	return inChunk, more
}

// encodeEvents writes the EventReports of the next chunk: once, the
// statuses of invalid concrete paths, then the readable events from
// rs.eventNext on. used tells whether the chunk already holds reports; it
// returns whether more remain for later chunks.
func (h *handler) encodeEvents(ctx *Context, rs *readState, w *tlv.Writer, limit int, used bool) (more bool) {
	log := h.s.node.Events
	start := w.Checkpoint()
	w.StartArray(tlv.ContextTag(2))
	n := 0
	if !rs.eventStatus {
		for i := range rs.events {
			p := &rs.events[i]
			if p.IsWildcard() {
				continue
			}
			c := ConcreteEventPath{p.Endpoint, p.Cluster, p.Event}
			if st := h.eventPathStatus(ctx, c); st != Success {
				encodeEventStatus(w, c, st)
				n++
			}
		}
		if w.Len() > limit && used {
			w.Rollback(start) // the statuses start the next chunk
			return true
		}
		rs.eventStatus = true
	}
	log.each(rs.eventNext, func(e *eventRecord) bool {
		if matchesAnyEvent(rs.events, e.path) && h.eventReadable(ctx, e) {
			cp := w.Checkpoint()
			encodeEventData(w, e)
			if w.Len() > limit {
				w.Rollback(cp)
				if n > 0 || used {
					more = true
					return false
				}
				// A single event too large for a message is skipped.
			} else {
				n++
			}
		}
		rs.eventNext = e.number + 1
		return true
	})
	if !more {
		rs.eventNext = log.Next()
	}
	if n == 0 {
		w.Rollback(start)
	} else {
		w.EndContainer()
	}
	return more
}

// eventPathStatus checks a concrete event path of a request.
// anyExistingPath reports whether a path of rs names an existing attribute,
// or an event of an existing cluster (a wildcard event path always may).
func (h *handler) anyExistingPath(rs *readState) bool {
	for _, p := range rs.events {
		if p.IsWildcard() {
			return true
		}
		if e := h.s.node.Endpoint(p.Endpoint); e != nil && e.Cluster(p.Cluster) != nil {
			return true
		}
	}
	found := false
	h.candidates(rs, func(c *candidate) bool {
		found = c.status == Success
		return !found
	})
	return found
}

func (h *handler) eventPathStatus(ctx *Context, p ConcreteEventPath) Status {
	e := h.s.node.Endpoint(p.Endpoint)
	if e == nil {
		return UnsupportedEndpoint
	}
	c := e.Cluster(p.Cluster)
	if c == nil {
		return UnsupportedCluster
	}
	// An event the cluster does not generate is not an error: like the SDK
	// (and its TestEventsById), the path just matches nothing.
	if !h.s.allowed(ctx, p.Endpoint, p.Cluster, eventPrivilege(c, p.Event)) {
		return UnsupportedAccess
	}
	return Success
}

// eventReadable reports whether the subject of ctx may read e: a
// fabric-sensitive event only by its fabric, and every event only with
// its read privilege.
func (h *handler) eventReadable(ctx *Context, e *eventRecord) bool {
	if e.sensitive {
		if ctx.Session == nil || ctx.Session.FabricIndex == 0 || ctx.Session.FabricIndex != e.fabric {
			return false
		}
	}
	ep := h.s.node.Endpoint(e.path.Endpoint)
	if ep == nil {
		return false
	}
	c := ep.Cluster(e.path.Cluster)
	if c == nil {
		return false
	}
	return h.s.allowed(ctx, e.path.Endpoint, e.path.Cluster, eventPrivilege(c, e.path.Event))
}

// encodeReport writes the AttributeReportIB of c, reporting whether it wrote
// anything (wildcard expansions with errors are skipped).
func encodeReport(ctx *Context, w *tlv.Writer, c *candidate) bool {
	if c.status != Success {
		encodeStatusReport(w, c.path, c.status, nil)
		return true
	}
	ctx.Endpoint = c.path.Endpoint
	ctx.clusterStatus = nil
	cp := w.Checkpoint()
	w.StartStruct(tlv.Anonymous)
	w.StartStruct(tlv.ContextTag(1)) // AttributeDataIB
	w.PutUint(tlv.ContextTag(0), uint64(c.version))
	encodeAttributePath(w, tlv.ContextTag(1), c.path, false)
	st := readAttribute(ctx, c.cluster, c.path.Attribute, w, tlv.ContextTag(2))
	w.EndContainer()
	w.EndContainer()
	if st == Success {
		return true
	}
	w.Rollback(cp)
	if c.wildcard {
		return false
	}
	encodeStatusReport(w, c.path, st, ctx.clusterStatus)
	return true
}

// encodeListChunk writes as much of a list attribute too large for one
// message as fits within limit: at first (started unset) the attribute with
// the items that fit, then from item from on one AttributeReportIB each, as
// list appends. It returns how many reports it wrote, the next item, and
// whether the attribute is complete. An attribute that is not a list, or an
// item too large for any message, is reported as ResourceExhausted.
func encodeListChunk(ctx *Context, w *tlv.Writer, c *candidate, started bool, from, limit int) (n, next int, done bool) {
	whole := tlv.NewWriter(nil)
	ctx.clusterStatus = nil
	st := readAttribute(ctx, c.cluster, c.path.Attribute, whole, tlv.Anonymous)
	r := tlv.NewReader(whole.Bytes())
	if st != Success || r.Next() != nil || r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		if started {
			return 0, 0, true // gone since the first chunk: the client keeps what it has
		}
		if st == Success {
			st = ResourceExhausted
		}
		encodeStatusReport(w, c.path, st, ctx.clusterStatus)
		return 1, 0, true
	}
	var items [][]byte
	for r.Next() == nil {
		raw, err := r.RawElement()
		if err != nil {
			break
		}
		items = append(items, raw)
	}
	const closing = 3 // the containers still open around an item
	start := func(appendItem bool) {
		w.StartStruct(tlv.Anonymous)     // AttributeReportIB
		w.StartStruct(tlv.ContextTag(1)) // AttributeDataIB
		w.PutUint(tlv.ContextTag(0), uint64(c.version))
		encodeAttributePath(w, tlv.ContextTag(1), c.path, appendItem)
	}
	i := from
	if !started {
		start(false)
		w.StartArray(tlv.ContextTag(2))
		for ; i < len(items); i++ {
			cp := w.Checkpoint()
			w.PutRaw(items[i])
			if w.Len()+closing > limit {
				w.Rollback(cp)
				break
			}
		}
		w.EndContainer()
		w.EndContainer()
		w.EndContainer()
		n = 1
	}
	for ; i < len(items); i++ {
		cp := w.Checkpoint()
		start(true)
		item := items[i]
		w.PutRaw(append([]byte{item[0] | 0x20, 2}, item[1:]...)) // retagged as context tag 2
		w.EndContainer()
		w.EndContainer()
		if w.Len() > limit {
			w.Rollback(cp)
			if n == 0 {
				encodeStatusReport(w, c.path, ResourceExhausted, nil)
				return 1, 0, true
			}
			return n, i, false
		}
		n++
	}
	return n, i, true
}

func encodeStatusReport(w *tlv.Writer, p ConcretePath, st Status, clusterStatus *uint8) {
	w.StartStruct(tlv.Anonymous)
	w.StartStruct(tlv.ContextTag(0)) // AttributeStatusIB
	encodeAttributePath(w, tlv.ContextTag(0), p, false)
	encodeStatusIB(w, tlv.ContextTag(1), st, clusterStatus)
	w.EndContainer()
	w.EndContainer()
}

// ---- Invoke ----

// Response lets a command handler write its response command.
type Response struct {
	w       *tlv.Writer
	path    CommandPath
	started bool
	cluster *uint8 // cluster-specific status
}

// NewResponse returns a Response that writes to w, to call a cluster's
// Invoke outside a server (in tests): a response command it starts is an
// InvokeResponseIB left open in w (w.Depth() > 0), its fields in
// CommandDataIB field 1.
func NewResponse(w *tlv.Writer, p CommandPath) *Response { return &Response{w: w, path: p} }

// ClusterStatus fails the command with a cluster-specific status code. The
// handler returns its result.
func (r *Response) ClusterStatus(code uint8) Status {
	r.cluster = &code
	return Failure
}

// Fields starts response command cmd and returns the writer for its fields,
// which the handler writes with context tags. Call it at most once and
// return Success afterwards.
func (r *Response) Fields(cmd uint32) *tlv.Writer {
	r.started = true
	w := r.w
	w.StartStruct(tlv.Anonymous)     // InvokeResponseIB
	w.StartStruct(tlv.ContextTag(0)) // CommandDataIB
	EncodeCommandPath(w, tlv.ContextTag(0), CommandPath{r.path.Endpoint, r.path.Cluster, cmd})
	w.StartStruct(tlv.ContextTag(1))
	return w
}

type invokeRequest struct {
	path   CommandPath
	fields []byte
	ref    uint16
	hasRef bool
}

var emptyStruct = []byte{0x15, 0x18}

func (h *handler) onInvoke(now time.Time, ex *exchange.Exchange, b []byte) Status {
	var (
		timedFlag, suppress bool
		reqs                [MaxPathsPerInvoke]invokeRequest
		n                   int
	)
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			suppress, err = r.Bool()
		case 1:
			timedFlag, err = r.Bool()
		case 2:
			return arrayItems(r, func() error {
				if n == len(reqs) {
					return InvalidAction
				}
				q := &reqs[n]
				n++
				q.fields = emptyStruct
				return structFields(r, func(r *tlv.Reader, tag uint8) (err error) {
					switch tag {
					case 0:
						q.path, err = DecodeCommandPath(r)
					case 1:
						if r.Type() != tlv.TypeStruct {
							return InvalidCommand
						}
						q.fields, err = r.RawElement()
					case 2:
						q.ref, err = r.Uint16()
						q.hasRef = true
					}
					return err
				})
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
	if n == 0 {
		return InvalidAction
	}
	if st := h.checkTimed(now, timedFlag); st != Success {
		return st
	}

	ctx := h.ctx(now, ex)
	ctx.Timed = timedFlag
	w := tlv.NewWriter(h.s.buf[:0])
	w.StartStruct(tlv.Anonymous)
	w.PutBool(tlv.ContextTag(0), false)
	w.StartArray(tlv.ContextTag(1))
	for i := 0; i < n; i++ {
		h.invokeOne(ctx, w, &reqs[i])
	}
	w.EndContainer()
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	if !suppress {
		if w.Len() > ex.MaxPayload() {
			return ResourceExhausted
		}
		ex.Send(now, message.ProtocolInteractionModel, OpInvokeResponse, w.Bytes())
	}
	ex.Close(now)
	return Success
}

func (h *handler) invokeOne(ctx *Context, w *tlv.Writer, q *invokeRequest) {
	st := Success
	var c Cluster
	if e := h.s.node.Endpoint(q.path.Endpoint); e == nil {
		st = UnsupportedEndpoint
	} else if c = e.Cluster(q.path.Cluster); c == nil {
		st = UnsupportedCluster
	} else if !hasID(c.AcceptedCommands(), q.path.Command) {
		st = UnsupportedCommand
	} else if !h.s.allowed(ctx, q.path.Endpoint, q.path.Cluster, invokePrivilege(c, q.path.Command)) {
		st = UnsupportedAccess
	}
	cp := w.Checkpoint()
	resp := Response{w: w, path: q.path}
	if st == Success {
		ctx.Endpoint = q.path.Endpoint
		r := tlv.NewReader(q.fields)
		if r.Next() != nil {
			st = InvalidCommand
		} else {
			st = c.Invoke(ctx, q.path.Command, r, &resp)
			if st == Success && h.s.OnInvoked != nil {
				h.s.OnInvoked(ctx, q.path)
			}
		}
	}
	if resp.started && st == Success {
		w.EndContainer() // fields
		if q.hasRef {
			w.PutUint(tlv.ContextTag(2), uint64(q.ref))
		}
		w.EndContainer() // CommandDataIB
		w.EndContainer() // InvokeResponseIB
		return
	}
	w.Rollback(cp)
	w.StartStruct(tlv.Anonymous)     // InvokeResponseIB
	w.StartStruct(tlv.ContextTag(1)) // CommandStatusIB
	EncodeCommandPath(w, tlv.ContextTag(0), q.path)
	var cs *uint8
	if st == Failure {
		cs = resp.cluster
	}
	encodeStatusIB(w, tlv.ContextTag(1), st, cs)
	if q.hasRef {
		w.PutUint(tlv.ContextTag(2), uint64(q.ref))
	}
	w.EndContainer()
	w.EndContainer()
}

// ---- Write ----

type writeItem struct {
	path    AttributePath
	cpath   ConcretePath
	version uint32
	hasVer  bool
	data    []byte
	st      Status
	ce      *clusterEntry
}

func hasConcretePath(paths []ConcretePath, p ConcretePath) bool {
	for _, x := range paths {
		if x == p {
			return true
		}
	}
	return false
}

func decodeWriteItem(r *tlv.Reader) (writeItem, error) {
	it, err := decodeWriteItemPath(r)
	if err != nil {
		return writeItem{}, err
	}
	if it.path.IsWildcard() {
		return writeItem{}, InvalidAction
	}
	it.cpath = ConcretePath{it.path.Endpoint, it.path.Cluster, it.path.Attribute}
	return it, nil
}

// decodeWriteItemPath decodes an AttributeDataIB of a write, whose path
// may have wildcards (as a group write's does).
func decodeWriteItemPath(r *tlv.Reader) (writeItem, error) {
	var (
		it      writeItem
		hasPath bool
	)
	err := structFields(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			it.version, err = r.Uint32()
			it.hasVer = true
		case 1:
			it.path, err = DecodeAttributePath(r)
			hasPath = true
		case 2:
			it.data, err = r.RawElement()
		}
		return err
	})
	if err != nil {
		return writeItem{}, err
	}
	if !hasPath || it.data == nil {
		return writeItem{}, InvalidAction
	}
	return it, nil
}

func (h *handler) onWrite(now time.Time, ex *exchange.Exchange, b []byte) Status {
	var timedFlag, more bool
	// First pass: the flags, which may follow the write requests.
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			timedFlag, err = r.Bool()
		case 3:
			more, err = r.Bool()
		}
		return err
	})
	if err != nil {
		return InvalidAction
	}
	if h.write == nil {
		if st := h.checkTimed(now, timedFlag); st != Success {
			return st
		}
	} else if !h.timed.IsZero() || timedFlag != h.write.timed {
		h.timed = time.Time{}
		return TimedRequestMismatch
	}

	var buf [8]writeItem
	items := buf[:0]
	err = structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) error {
		if tag != 2 {
			return nil
		}
		return arrayItems(r, func() error {
			it, err := decodeWriteItem(r)
			if err != nil {
				return err
			}
			items = append(items, it)
			return nil
		})
	})
	if err != nil {
		return InvalidAction
	}

	ctx := h.ctx(now, ex)
	// Evaluate all path validations and ACL checks before applying any writes
	// so a multi-item list replacement (e.g. ACL = [] followed by ListAppend)
	// does not revoke its own access mid-batch.
	var chunkAuth []ConcretePath
	for i := range items {
		it := &items[i]
		var ce *clusterEntry
		if e := h.s.node.Endpoint(it.path.Endpoint); e == nil {
			it.st = UnsupportedEndpoint
			continue
		} else if ce = e.entry(it.path.Cluster); ce == nil {
			it.st = UnsupportedCluster
			continue
		} else if !hasAttribute(ce.c, it.path.Attribute) {
			it.st = UnsupportedAttribute
			continue
		} else if isGlobalAttribute(it.path.Attribute) {
			it.st = UnsupportedWrite
			continue
		}
		allowed := h.s.allowed(ctx, it.path.Endpoint, it.path.Cluster, writePrivilege(ce.c, it.path.Attribute)) ||
			(it.path.ListAppend && h.write != nil && hasConcretePath(h.write.auth, it.cpath))
		if !allowed {
			it.st = UnsupportedAccess
			continue
		}
		if it.path.hasListIdx && !it.path.ListAppend {
			it.st = UnsupportedWrite
			continue
		}
		if it.hasVer && it.version != ce.version {
			it.st = DataVersionMismatch
			continue
		}
		if more && !it.path.hasListIdx && !hasConcretePath(chunkAuth, it.cpath) {
			chunkAuth = append(chunkAuth, it.cpath)
		}
		it.ce = ce
	}

	ctx.Timed = timedFlag
	w := tlv.NewWriter(h.s.buf[:0])
	w.StartStruct(tlv.Anonymous)
	w.StartArray(tlv.ContextTag(0))
	for i := range items {
		it := &items[i]
		ctx.clusterStatus = nil
		if it.st == Success {
			ctx.Endpoint = it.path.Endpoint
			dr := tlv.NewReader(it.data)
			if dr.Next() != nil {
				it.st = InvalidDataType
			} else if it.st = it.ce.c.WriteAttribute(ctx, it.path.Attribute, it.path.ListAppend, dr); it.st == Success {
				h.s.written(ConcretePath{Endpoint: it.path.Endpoint, Cluster: it.path.Cluster, Attribute: it.path.Attribute})
			}
		}
		w.StartStruct(tlv.Anonymous) // AttributeStatusIB
		encodeAttributePath(w, tlv.ContextTag(0), it.cpath, it.path.ListAppend)
		encodeStatusIB(w, tlv.ContextTag(1), it.st, ctx.clusterStatus)
		w.EndContainer()
	}
	w.EndContainer()
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	if w.Len() > ex.MaxPayload() {
		return ResourceExhausted
	}
	ex.Send(now, message.ProtocolInteractionModel, OpWriteResponse, w.Bytes())
	if more {
		if h.write == nil {
			h.write = &writeState{timed: timedFlag}
		}
		h.write.auth = append(h.write.auth, chunkAuth...)
	} else {
		h.write = nil
		ex.Close(now)
	}
	return Success
}
