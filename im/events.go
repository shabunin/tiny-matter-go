package im

import (
	"encoding/binary"
	"time"

	"github.com/shabunin/tiny-matter-go/tlv"
)

// Priority is the priority level of an event (spec 7.14.2.1).
type Priority uint8

const (
	PriorityDebug    Priority = 0
	PriorityInfo     Priority = 1
	PriorityCritical Priority = 2
)

// EventPath is an event path from a request: any of Endpoint, Cluster and
// Event may be a wildcard.
type EventPath struct {
	Endpoint uint16
	Cluster  uint32
	Event    uint32
	// Wildcard flags.
	AnyEndpoint, AnyCluster, AnyEvent bool
	// IsUrgent asks a subscription to report matching events at the min
	// interval instead of with the next report.
	IsUrgent bool
}

// ConcreteEventPath identifies one event of one cluster instance.
type ConcreteEventPath struct {
	Endpoint uint16
	Cluster  uint32
	Event    uint32
}

// IsWildcard reports whether p contains a wildcard.
func (p *EventPath) IsWildcard() bool { return p.AnyEndpoint || p.AnyCluster || p.AnyEvent }

// Matches reports whether p covers c.
func (p *EventPath) Matches(c ConcreteEventPath) bool {
	return (p.AnyEndpoint || p.Endpoint == c.Endpoint) &&
		(p.AnyCluster || p.Cluster == c.Cluster) &&
		(p.AnyEvent || p.Event == c.Event)
}

func matchesAnyEvent(paths []EventPath, c ConcreteEventPath) bool {
	for i := range paths {
		if paths[i].Matches(c) {
			return true
		}
	}
	return false
}

// DecodeEventPath decodes the EventPathIB list the reader is positioned on.
func DecodeEventPath(r *tlv.Reader) (EventPath, error) {
	p := EventPath{AnyEndpoint: true, AnyCluster: true, AnyEvent: true}
	if r.Type() != tlv.TypeList {
		return p, errMalformed
	}
	err := arrayItems(r, func() (err error) {
		if r.Tag().Kind != tlv.TagContext {
			return nil
		}
		switch r.Tag().Number {
		case 0: // node: accepted, not checked
			_, err = r.Uint()
		case 1:
			p.Endpoint, err = r.Uint16()
			p.AnyEndpoint = false
		case 2:
			p.Cluster, err = r.Uint32()
			p.AnyCluster = false
		case 3:
			p.Event, err = r.Uint32()
			p.AnyEvent = false
		case 4:
			p.IsUrgent, err = r.Bool()
		}
		return err
	})
	if err != nil {
		return p, err
	}
	// A concrete event of a wildcard cluster names nothing.
	if p.AnyCluster && !p.AnyEvent {
		return p, InvalidAction
	}
	return p, nil
}

// EncodeEventPath writes a request EventPathIB, omitting wildcard fields.
func EncodeEventPath(w *tlv.Writer, tag tlv.Tag, p EventPath) {
	w.StartList(tag)
	if !p.AnyEndpoint {
		w.PutUint(tlv.ContextTag(1), uint64(p.Endpoint))
	}
	if !p.AnyCluster {
		w.PutUint(tlv.ContextTag(2), uint64(p.Cluster))
	}
	if !p.AnyEvent {
		w.PutUint(tlv.ContextTag(3), uint64(p.Event))
	}
	if p.IsUrgent {
		w.PutBool(tlv.ContextTag(4), true)
	}
	w.EndContainer()
}

func encodeConcreteEventPath(w *tlv.Writer, tag tlv.Tag, c ConcreteEventPath) {
	w.StartList(tag)
	w.PutUint(tlv.ContextTag(1), uint64(c.Endpoint))
	w.PutUint(tlv.ContextTag(2), uint64(c.Cluster))
	w.PutUint(tlv.ContextTag(3), uint64(c.Event))
	w.EndContainer()
}

// decodeEventFilter returns the EventMin of the EventFilterIB r is
// positioned on.
func decodeEventFilter(r *tlv.Reader) (min uint64, err error) {
	seen := false
	err = structFields(r, func(r *tlv.Reader, tag uint8) (err error) {
		if tag == 1 {
			min, err = r.Uint()
			seen = true
		}
		return err
	})
	if err == nil && !seen {
		err = errMalformed
	}
	return min, err
}

// EventInfo is implemented by clusters that generate events. It describes
// them: like the SDK, the server does not refuse a path naming another
// event ID, which just matches nothing.
type EventInfo interface {
	// Events returns the IDs of the events the instance generates, in
	// ascending order.
	Events() []uint32
}

// EventPrivilegeInfo is implemented by clusters whose events need more
// than View to read.
type EventPrivilegeInfo interface {
	EventPrivilege(event uint32) Privilege
}

func eventPrivilege(c Cluster, event uint32) Privilege {
	if pi, ok := c.(EventPrivilegeInfo); ok {
		return pi.EventPrivilege(event)
	}
	return View
}

// Event is an event to record with Node.Emit.
type Event struct {
	Path     ConcreteEventPath
	Priority Priority
	// Fabric is the fabric index of a fabric-sensitive event, which only
	// that fabric can read, or zero. Emit adds the FabricIndex field.
	Fabric uint8
	// Fields, if set, writes the event's fields with context tags.
	Fields func(w *tlv.Writer)
}

// EventNumberEpoch is how far event numbers are reserved ahead in
// persistent storage.
const EventNumberEpoch = 0x10000

// Default event buffer sizes, in bytes.
const (
	DefaultDebugBuffer    = 256
	DefaultInfoBuffer     = 768
	DefaultCriticalBuffer = 512
)

// EventLog keeps recent events in fixed-size buffers, one per priority,
// dropping the oldest events of a priority when its buffer is full (spec
// 7.14.2). Event numbers increase monotonically; with a persistent
// reservation (Start, OnReserve) they keep increasing across restarts.
type EventLog struct {
	rings [3]eventRing // indexed by priority
	next  uint64       // number of the next event
	limit uint64       // reserved numbers end here; zero: no reservation
	// Boot is the zero of event system timestamps; the first event sets
	// it if it is unset.
	Boot time.Time
	// OnReserve, if set, is called when event numbers run past the
	// reservation, with the new limit to persist.
	OnReserve func(limit uint64)
	scratch   []byte
}

// NewEventLog returns a log with buffers of the given sizes in bytes. A
// zero size disables a priority.
func NewEventLog(debug, info, critical int) *EventLog {
	l := &EventLog{scratch: make([]byte, 0, 128)}
	for i, n := range [3]int{debug, info, critical} {
		l.rings[i].buf = make([]byte, 0, n)
	}
	return l
}

// Start begins numbering at first and reserves numbers up to the limit it
// returns, which the caller persists and passes as first on the next
// start.
func (l *EventLog) Start(first uint64) (limit uint64) {
	l.next = first
	l.limit = first + EventNumberEpoch
	return l.limit
}

// Next returns the number the next event will get.
func (l *EventLog) Next() uint64 { return l.next }

// RemoveFabric makes the fabric-sensitive events of a removed fabric
// unreadable.
func (l *EventLog) RemoveFabric(index uint8) {
	for i := range l.rings {
		b := l.rings[i].buf
		for off := 0; off < len(b); off += int(binary.LittleEndian.Uint16(b[off:])) {
			if b[off+29]&flagSensitive != 0 && b[off+28] == index {
				b[off+28] = 0
			}
		}
	}
}

// Record layout in a ring: length u16, number u64, system time (ms) u64,
// endpoint u16, cluster u32, event u32, fabric u8, flags u8, then the
// event fields (TLV elements without the enclosing structure).
const (
	recHeader     = 30
	flagSensitive = 1
)

type eventRing struct{ buf []byte }

// add appends a record, dropping the oldest records to make room.
func (r *eventRing) add(rec []byte) bool {
	if len(rec) > cap(r.buf) {
		return false
	}
	for len(r.buf)+len(rec) > cap(r.buf) {
		first := int(binary.LittleEndian.Uint16(r.buf))
		n := copy(r.buf, r.buf[first:])
		r.buf = r.buf[:n]
	}
	r.buf = append(r.buf, rec...)
	return true
}

// eventRecord is a decoded event; data aliases the ring.
type eventRecord struct {
	number    uint64
	time      uint64 // ms since boot
	path      ConcreteEventPath
	fabric    uint8
	sensitive bool
	priority  Priority
	data      []byte
}

func decodeRecord(b []byte, pri Priority) (eventRecord, int) {
	n := int(binary.LittleEndian.Uint16(b))
	return eventRecord{
		number: binary.LittleEndian.Uint64(b[2:]),
		time:   binary.LittleEndian.Uint64(b[10:]),
		path: ConcreteEventPath{
			Endpoint: binary.LittleEndian.Uint16(b[18:]),
			Cluster:  binary.LittleEndian.Uint32(b[20:]),
			Event:    binary.LittleEndian.Uint32(b[24:]),
		},
		fabric:    b[28],
		sensitive: b[29]&flagSensitive != 0,
		priority:  pri,
		data:      b[recHeader:n],
	}, n
}

// emit records e and returns its number; ok is false if it was dropped
// (larger than its priority's buffer).
func (l *EventLog) emit(now time.Time, e *Event) (number uint64, ok bool) {
	if e.Priority > PriorityCritical {
		return 0, false
	}
	if l.Boot.IsZero() {
		l.Boot = now
	}
	var ms uint64
	if d := now.Sub(l.Boot); d > 0 {
		ms = uint64(d / time.Millisecond)
	}
	var header [recHeader]byte
	w := tlv.NewWriter(append(l.scratch[:0], header[:]...))
	if e.Fields != nil {
		e.Fields(w)
	}
	if e.Fabric != 0 {
		w.PutUint(tlv.ContextTag(0xFE), uint64(e.Fabric))
	}
	b := w.Bytes()
	l.scratch = b[:0]
	if len(b) > 0xFFFF || w.Err() != nil {
		return 0, false
	}
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	binary.LittleEndian.PutUint64(b[2:], l.next)
	binary.LittleEndian.PutUint64(b[10:], ms)
	binary.LittleEndian.PutUint16(b[18:], e.Path.Endpoint)
	binary.LittleEndian.PutUint32(b[20:], e.Path.Cluster)
	binary.LittleEndian.PutUint32(b[24:], e.Path.Event)
	b[28], b[29] = e.Fabric, 0
	if e.Fabric != 0 {
		b[29] = flagSensitive
	}
	if !l.rings[e.Priority].add(b) {
		return 0, false
	}
	number = l.next
	l.next++
	if l.limit != 0 && l.next >= l.limit {
		l.limit += EventNumberEpoch
		if l.OnReserve != nil {
			l.OnReserve(l.limit)
		}
	}
	return number, true
}

// each calls f for the recorded events numbered from on, in increasing
// number order, until f returns false. f must not emit events.
func (l *EventLog) each(from uint64, f func(e *eventRecord) bool) {
	var off [3]int
	for i := range l.rings {
		b := l.rings[i].buf
		for off[i] < len(b) && binary.LittleEndian.Uint64(b[off[i]+2:]) < from {
			off[i] += int(binary.LittleEndian.Uint16(b[off[i]:]))
		}
	}
	for {
		best := -1
		var bestNum uint64
		for i := range l.rings {
			if b := l.rings[i].buf; off[i] < len(b) {
				if n := binary.LittleEndian.Uint64(b[off[i]+2:]); best < 0 || n < bestNum {
					best, bestNum = i, n
				}
			}
		}
		if best < 0 {
			return
		}
		rec, n := decodeRecord(l.rings[best].buf[off[best]:], Priority(best))
		off[best] += n
		if !f(&rec) {
			return
		}
	}
}

// Emit records an event and returns its number; ok is false if the event
// did not fit its priority's buffer. It notifies OnEvent.
func (n *Node) Emit(now time.Time, e Event) (number uint64, ok bool) {
	number, ok = n.Events.emit(now, &e)
	if ok && n.OnEvent != nil {
		n.OnEvent(e.Path)
	}
	return number, ok
}

// encodeEventData writes the EventReportIB of an event.
func encodeEventData(w *tlv.Writer, e *eventRecord) {
	w.StartStruct(tlv.Anonymous)     // EventReportIB
	w.StartStruct(tlv.ContextTag(1)) // EventDataIB
	encodeConcreteEventPath(w, tlv.ContextTag(0), e.path)
	w.PutUint(tlv.ContextTag(1), e.number)
	w.PutUint(tlv.ContextTag(2), uint64(e.priority))
	w.PutUint(tlv.ContextTag(4), e.time) // SystemTimestamp
	w.StartStruct(tlv.ContextTag(7))
	w.PutRaw(e.data)
	w.EndContainer()
	w.EndContainer()
	w.EndContainer()
}

// encodeEventStatus writes the EventReportIB of a status for a path.
func encodeEventStatus(w *tlv.Writer, p ConcreteEventPath, st Status) {
	w.StartStruct(tlv.Anonymous)     // EventReportIB
	w.StartStruct(tlv.ContextTag(0)) // EventStatusIB
	encodeConcreteEventPath(w, tlv.ContextTag(0), p)
	encodeStatusIB(w, tlv.ContextTag(1), st, nil)
	w.EndContainer()
	w.EndContainer()
}
