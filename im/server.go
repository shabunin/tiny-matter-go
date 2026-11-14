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
	// maxReadPaths bounds the attribute paths accepted in one read.
	maxReadPaths = 9
	// maxVersionFilters bounds the data version filters kept from a read.
	maxVersionFilters = 9
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

	subs      []*subscription
	nextSubID uint32
}

// NewServer returns a Server for n and registers it with m. It chains
// itself into n.OnChange to drive subscriptions; call Poll to send their
// reports.
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
	return s
}

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

	// Subscriptions only.
	sub   *subscription
	dirty []ConcretePath // changed paths to report; nil reports all paths
	done  bool           // last chunk sent, awaiting its StatusResponse
}

// handler serves one exchange.
type handler struct {
	s     *Server
	read  *readState // read in progress, awaiting a StatusResponse
	timed time.Time  // deadline of a preceding TimedRequest
}

func (h *handler) ctx(now time.Time, ex *exchange.Exchange) *Context {
	return &Context{Now: now, Node: h.s.node, Session: ex.Session()}
}

func (h *handler) OnError(now time.Time, ex *exchange.Exchange, err error) { h.abort() }

// abort ends the read or report in progress; a failed subscription report
// ends the subscription.
func (h *handler) abort() {
	if h.read != nil && h.read.sub != nil {
		h.s.removeSub(h.read.sub)
	}
	h.read = nil
}

func (h *handler) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if msg.ProtocolID != message.ProtocolInteractionModel {
		ex.Close(now)
		return
	}
	var st Status
	switch msg.Opcode {
	case OpReadRequest:
		if h.read != nil {
			st = InvalidAction
			break
		}
		st = h.onRead(now, ex, msg.Payload)
	case OpSubscribeRequest:
		if h.read != nil {
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
			h.abort()
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
		st = h.onTimed(now, ex, msg.Payload)
		if st == Success {
			h.sendStatus(now, ex, Success, false)
			return
		}
	case OpInvokeRequest:
		st = h.onInvoke(now, ex, msg.Payload)
	case OpWriteRequest:
		st = h.onWrite(now, ex, msg.Payload)
	default:
		st = InvalidAction
	}
	if st != Success {
		h.abort()
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

// sendReport sends the next ReportData chunk of the read in progress.
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
	arrayStart := w.Checkpoint()
	w.StartArray(tlv.ContextTag(1))
	index, inChunk, more := 0, 0, false
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
		wrote := encodeReport(ctx, w, c)
		if w.Len() > limit {
			w.Rollback(cp)
			if inChunk > 0 {
				more = true
				return false
			}
			// A single attribute too large for a message.
			// TODO: split list attributes across chunks.
			encodeStatusReport(w, c.path, ResourceExhausted)
			wrote = true
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

// encodeReport writes the AttributeReportIB of c, reporting whether it wrote
// anything (wildcard expansions with errors are skipped).
func encodeReport(ctx *Context, w *tlv.Writer, c *candidate) bool {
	if c.status != Success {
		encodeStatusReport(w, c.path, c.status)
		return true
	}
	ctx.Endpoint = c.path.Endpoint
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
	encodeStatusReport(w, c.path, st)
	return true
}

func encodeStatusReport(w *tlv.Writer, p ConcretePath, st Status) {
	w.StartStruct(tlv.Anonymous)
	w.StartStruct(tlv.ContextTag(0)) // AttributeStatusIB
	encodeAttributePath(w, tlv.ContextTag(0), p, false)
	encodeStatusIB(w, tlv.ContextTag(1), st, nil)
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
	if st := h.checkTimed(now, timedFlag); st != Success {
		return st
	}
	if more {
		// A chunked write stays timed across its chunks.
		h.timed = now.Add(time.Hour)
		if !timedFlag {
			h.timed = time.Time{}
		}
	}

	ctx := h.ctx(now, ex)
	ctx.Timed = timedFlag
	w := tlv.NewWriter(h.s.buf[:0])
	w.StartStruct(tlv.Anonymous)
	w.StartArray(tlv.ContextTag(0))
	err = structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) error {
		if tag != 2 {
			return nil
		}
		return arrayItems(r, func() error { return h.writeOne(ctx, w, r) })
	})
	if err != nil {
		return InvalidAction
	}
	w.EndContainer()
	w.PutUint(tlv.ContextTag(tagIMRevision), Revision)
	w.EndContainer()
	if w.Len() > ex.MaxPayload() {
		return ResourceExhausted
	}
	ex.Send(now, message.ProtocolInteractionModel, OpWriteResponse, w.Bytes())
	if !more {
		ex.Close(now)
	}
	return Success
}

func (h *handler) writeOne(ctx *Context, w *tlv.Writer, r *tlv.Reader) error {
	var (
		path            AttributePath
		version         uint32
		hasPath, hasVer bool
		data            []byte
	)
	err := structFields(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			version, err = r.Uint32()
			hasVer = true
		case 1:
			path, err = DecodeAttributePath(r)
			hasPath = true
		case 2:
			data, err = r.RawElement()
		}
		return err
	})
	if err != nil {
		return err
	}
	if !hasPath || data == nil || path.IsWildcard() {
		return InvalidAction
	}
	cpath := ConcretePath{path.Endpoint, path.Cluster, path.Attribute}
	st := Success
	var ce *clusterEntry
	if e := h.s.node.Endpoint(path.Endpoint); e == nil {
		st = UnsupportedEndpoint
	} else if ce = e.entry(path.Cluster); ce == nil {
		st = UnsupportedCluster
	} else if !hasAttribute(ce.c, path.Attribute) {
		st = UnsupportedAttribute
	} else if isGlobalAttribute(path.Attribute) {
		st = UnsupportedWrite
	} else if !h.s.allowed(ctx, path.Endpoint, path.Cluster, writePrivilege(ce.c, path.Attribute)) {
		st = UnsupportedAccess
	} else if hasVer && version != ce.version {
		st = DataVersionMismatch
	}
	if st == Success {
		ctx.Endpoint = path.Endpoint
		dr := tlv.NewReader(data)
		if dr.Next() != nil {
			st = InvalidDataType
		} else if st = ce.c.WriteAttribute(ctx, path.Attribute, path.ListAppend, dr); st == Success {
			h.s.node.Changed(path.Endpoint, path.Cluster, path.Attribute)
		}
	}
	w.StartStruct(tlv.Anonymous) // AttributeStatusIB
	encodeAttributePath(w, tlv.ContextTag(0), cpath, path.ListAppend)
	encodeStatusIB(w, tlv.ContextTag(1), st, nil)
	w.EndContainer()
	return nil
}
