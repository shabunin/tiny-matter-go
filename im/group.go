package im

import (
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// onGroup serves a message sent to a group (spec 8.2.2): only invokes
// and writes are accepted, their paths name no endpoint and expand to
// the endpoints that are members of the group, and nothing is answered.
// Timed and chunked interactions are impossible with groups.
func (h *handler) onGroup(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	defer ex.Close(now)
	if msg.ProtocolID != message.ProtocolInteractionModel || h.s.GroupEndpoints == nil {
		return
	}
	s := ex.Session()
	endpoints := h.s.GroupEndpoints(s.FabricIndex, s.GroupID)
	if len(endpoints) == 0 {
		return
	}
	ctx := h.ctx(now, ex)
	switch msg.Opcode {
	case OpInvokeRequest:
		h.groupInvoke(ctx, endpoints, msg.Payload)
	case OpWriteRequest:
		h.groupWrite(ctx, endpoints, msg.Payload)
	}
}

func (h *handler) groupInvoke(ctx *Context, endpoints []uint16, b []byte) {
	type request struct {
		cluster, command uint32
		fields           []byte
	}
	var (
		reqs  [MaxPathsPerInvoke]request
		n     int
		timed bool
	)
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			timed, err = r.Bool()
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
						var hasEndpoint bool
						q.cluster, q.command, hasEndpoint, err = decodeGroupCommandPath(r)
						if err == nil && hasEndpoint {
							err = InvalidAction
						}
					case 1:
						if r.Type() != tlv.TypeStruct {
							return InvalidCommand
						}
						q.fields, err = r.RawElement()
					}
					return err
				})
			})
		}
		return err
	})
	if err != nil || timed {
		return
	}
	for i := 0; i < n; i++ {
		q := &reqs[i]
		for _, ep := range endpoints {
			e := h.s.node.Endpoint(ep)
			if e == nil {
				continue
			}
			c := e.Cluster(q.cluster)
			if c == nil || !hasID(c.AcceptedCommands(), q.command) ||
				!h.s.allowed(ctx, ep, q.cluster, invokePrivilege(c, q.command)) {
				continue
			}
			r := tlv.NewReader(q.fields)
			if r.Next() != nil {
				continue
			}
			ctx.Endpoint = ep
			// A response command is written and dropped.
			w := tlv.NewWriter(h.s.buf[:0])
			p := CommandPath{ep, q.cluster, q.command}
			if c.Invoke(ctx, q.command, r, &Response{w: w, path: p}) == Success && h.s.OnInvoked != nil {
				h.s.OnInvoked(ctx, p)
			}
		}
	}
}

func (h *handler) groupWrite(ctx *Context, endpoints []uint16, b []byte) {
	var timed, more bool
	type item struct {
		cluster, attr uint32
		listAppend    bool
		data          []byte
	}
	var (
		buf   [8]item
		items = buf[:0]
	)
	err := structFields(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			timed, err = r.Bool()
		case 3:
			more, err = r.Bool()
		case 2:
			return arrayItems(r, func() error {
				it, err := decodeWriteItemPath(r)
				if err != nil {
					return err
				}
				// A group write names a cluster and attribute but no
				// endpoint, and no data version.
				p := it.path
				if !p.AnyEndpoint || p.AnyCluster || p.AnyAttribute || it.hasVer ||
					(p.hasListIdx && !p.ListAppend) || len(items) == cap(items) {
					return InvalidAction
				}
				items = append(items, item{p.Cluster, p.Attribute, p.ListAppend, it.data})
				return nil
			})
		}
		return err
	})
	if err != nil || timed || more {
		return
	}
	for _, it := range items {
		for _, ep := range endpoints {
			e := h.s.node.Endpoint(ep)
			if e == nil {
				continue
			}
			ce := e.entry(it.cluster)
			if ce == nil || !hasAttribute(ce.c, it.attr) || isGlobalAttribute(it.attr) ||
				!h.s.allowed(ctx, ep, it.cluster, writePrivilege(ce.c, it.attr)) {
				continue
			}
			r := tlv.NewReader(it.data)
			if r.Next() != nil {
				continue
			}
			ctx.Endpoint = ep
			if ce.c.WriteAttribute(ctx, it.attr, it.listAppend, r) == Success {
				h.s.written(ConcretePath{Endpoint: ep, Cluster: it.cluster, Attribute: it.attr})
			}
		}
	}
}
