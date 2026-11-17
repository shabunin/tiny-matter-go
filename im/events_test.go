package im_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// evCluster generates event 1 (readable with View) and event 2 (needs
// Administer).
type evCluster struct{ im.ClusterBase }

const evClusterID = 0xFFF1FC02

func (evCluster) ID() uint32           { return evClusterID }
func (evCluster) Revision() uint16     { return 1 }
func (evCluster) Attributes() []uint32 { return nil }
func (evCluster) ReadAttribute(*im.Context, uint32, *tlv.Writer, tlv.Tag) im.Status {
	return im.UnsupportedAttribute
}
func (evCluster) Events() []uint32 { return []uint32{1, 2} }
func (evCluster) EventPrivilege(ev uint32) im.Privilege {
	if ev == 2 {
		return im.Administer
	}
	return im.View
}

// withEvents adds evCluster on endpoint 3.
func (f *fixture) withEvents() *fixture {
	ep := f.node.AddEndpoint(3)
	f.node.AddCluster(ep, evCluster{})
	return f
}

func (f *fixture) emit(ev uint32, pri im.Priority, fabric uint8, payload string) uint64 {
	f.t.Helper()
	n, ok := f.node.Emit(f.w.Now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: 3, Cluster: evClusterID, Event: ev},
		Priority: pri, Fabric: fabric,
		Fields: func(w *tlv.Writer) { w.PutString(tlv.ContextTag(0), payload) },
	})
	if !ok {
		f.t.Fatal("event dropped")
	}
	return n
}

// readAll runs a read and returns its chunks.
func (f *fixture) readAll(q im.Request) []*im.ReportData {
	f.t.Helper()
	msgs := f.request(im.OpReadRequest, im.EncodeRead(q))
	var out []*im.ReportData
	for i, m := range msgs {
		if m.Opcode != im.OpReportData {
			st, _ := im.DecodeStatusResponse(m.Payload)
			f.t.Fatalf("message %d: opcode %#x status %#x", i, m.Opcode, st)
		}
		rd, err := im.DecodeReportData(m.Payload)
		if err != nil {
			f.t.Fatal(err)
		}
		if last := i == len(msgs)-1; rd.MoreChunks == last || rd.SuppressResponse != last {
			f.t.Fatalf("chunk %d/%d: more=%v suppress=%v", i, len(msgs), rd.MoreChunks, rd.SuppressResponse)
		}
		out = append(out, rd)
	}
	return out
}

func events(rds []*im.ReportData) []im.EventReport {
	var out []im.EventReport
	for _, rd := range rds {
		out = append(out, rd.Events...)
	}
	return out
}

func payload(t *testing.T, ev im.EventReport) string {
	t.Helper()
	r := tlv.NewReader(ev.Data)
	if r.Next() != nil || r.Type() != tlv.TypeStruct || r.EnterContainer() != nil || r.Next() != nil {
		t.Fatalf("event data %x", ev.Data)
	}
	s, err := r.String()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var anyEvent = im.EventPath{AnyEndpoint: true, AnyCluster: true, AnyEvent: true}

func TestEventLog(t *testing.T) {
	l := im.NewEventLog(0, 100, 200)
	var reserved []uint64
	l.OnReserve = func(limit uint64) { reserved = append(reserved, limit) }
	if limit := l.Start(im.EventNumberEpoch - 2); limit != 2*im.EventNumberEpoch-2 {
		t.Fatalf("limit %d", limit)
	}
	n := &im.Node{Events: l}
	now := time.Unix(50, 0)
	e := im.Event{Path: im.ConcreteEventPath{Endpoint: 1, Cluster: 2, Event: 3}, Priority: im.PriorityInfo,
		Fields: func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), make([]byte, 20)) }}
	if _, ok := n.Emit(now, im.Event{Priority: im.PriorityDebug}); ok {
		t.Fatal("event with a disabled priority kept")
	}
	first, _ := n.Emit(now, e)
	for i := 0; i < 5; i++ {
		n.Emit(now, e)
	}
	if first != im.EventNumberEpoch-2 || l.Next() != first+6 {
		t.Fatalf("numbers: first %d next %d", first, l.Next())
	}
	big := e
	big.Fields = func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), make([]byte, 120)) }
	if _, ok := n.Emit(now, big); ok {
		t.Fatal("an event larger than its buffer was kept")
	}
	if l.Next() != first+6 {
		t.Fatal("a dropped event used a number")
	}
	if len(reserved) != 0 {
		t.Fatalf("reserved early: %v", reserved)
	}
	// Numbers past the reservation reserve the next epoch.
	l.Start(0)
	tiny := im.Event{Priority: im.PriorityCritical}
	for i := 0; i < im.EventNumberEpoch-1; i++ {
		n.Emit(now, tiny)
	}
	if len(reserved) != 0 {
		t.Fatalf("reserved early: %v", reserved)
	}
	n.Emit(now, tiny)
	if len(reserved) != 1 || reserved[0] != 2*im.EventNumberEpoch {
		t.Fatalf("reservation %v", reserved)
	}
}

func TestReadEvents(t *testing.T) {
	f := newFixture(t).withEvents()
	n0 := f.emit(1, im.PriorityInfo, 0, "a")
	f.w.Advance(1500 * time.Millisecond)
	f.emit(1, im.PriorityCritical, 0, "b")
	f.emit(2, im.PriorityDebug, 0, "c")
	f.emit(1, im.PriorityInfo, 2, "other fabric")
	f.emit(1, im.PriorityInfo, 1, "own fabric")

	evs := events(f.readAll(im.Request{Events: []im.EventPath{anyEvent}}))
	var got []string
	for _, ev := range evs {
		got = append(got, payload(t, ev))
	}
	// Merged in number order across priorities; the other fabric's
	// sensitive event is hidden.
	if strings.Join(got, ",") != "a,b,c,own fabric" {
		t.Fatalf("events %q", got)
	}
	if evs[0].Number != n0 || evs[1].Number != n0+1 || evs[3].Number != n0+4 {
		t.Fatalf("numbers %d %d %d", evs[0].Number, evs[1].Number, evs[3].Number)
	}
	if !evs[1].System || evs[1].Timestamp-evs[0].Timestamp != 1500 || evs[1].Priority != im.PriorityCritical {
		t.Fatalf("event b: %+v", evs[1])
	}
	if p := evs[2].Path; p.Endpoint != 3 || p.Cluster != evClusterID || p.Event != 2 || p.AnyEvent {
		t.Fatalf("path %+v", p)
	}

	// EventMin, a concrete path, and paths that name nothing.
	evs = events(f.readAll(im.Request{EventMin: n0 + 1, Events: []im.EventPath{
		{Endpoint: 3, Cluster: evClusterID, Event: 1},
		{Endpoint: 9, Cluster: evClusterID, Event: 1},
		{Endpoint: 3, Cluster: 0x1234, Event: 1},
		{Endpoint: 3, Cluster: evClusterID, Event: 7},        // not generated: silent
		{AnyEndpoint: true, Cluster: 0x1234, AnyEvent: true}, // wildcard: silent
	}}))
	if len(evs) != 4 {
		t.Fatalf("%d reports", len(evs))
	}
	for i, want := range []im.Status{im.UnsupportedEndpoint, im.UnsupportedCluster} {
		if evs[i].Status != want || evs[i].Data != nil {
			t.Errorf("status %d: %+v", i, evs[i])
		}
	}
	if payload(t, evs[2]) != "b" || payload(t, evs[3]) != "own fabric" {
		t.Fatal("EventMin or the concrete path not applied")
	}

	// A concrete event of a wildcard cluster is an invalid request.
	msgs := f.request(im.OpReadRequest, im.EncodeRead(im.Request{Events: []im.EventPath{{AnyEndpoint: true, AnyCluster: true, Event: 1}}}))
	if st, _ := im.DecodeStatusResponse(msgs[0].Payload); msgs[0].Opcode != im.OpStatusResponse || st != im.InvalidAction {
		t.Fatalf("invalid path: opcode %#x status %#x", msgs[0].Opcode, st)
	}

	// A removed fabric's sensitive events are gone.
	f.node.Events.RemoveFabric(1)
	if evs := events(f.readAll(im.Request{Events: []im.EventPath{anyEvent}})); len(evs) != 3 {
		t.Fatalf("%d events after removing the fabric", len(evs))
	}

	// Attributes and events in one read.
	rds := f.readAll(im.Request{Attributes: []im.AttributePath{onOffPath}, Events: []im.EventPath{{Endpoint: 3, Cluster: evClusterID, AnyEvent: true}}})
	if len(rds) != 1 || len(rds[0].Reports) != 1 || len(rds[0].Events) != 3 {
		t.Fatalf("mixed read: %d chunks", len(rds))
	}
}

type denyAdmin struct{}

func (denyAdmin) Allowed(ctx *im.Context, ep uint16, cl uint32, p im.Privilege) bool {
	return p != im.Administer
}

func TestReadEventsAccess(t *testing.T) {
	f := newFixture(t).withEvents()
	f.server.Access = denyAdmin{}
	f.emit(1, im.PriorityInfo, 0, "view")
	f.emit(2, im.PriorityInfo, 0, "admin")
	evs := events(f.readAll(im.Request{Events: []im.EventPath{anyEvent, {Endpoint: 3, Cluster: evClusterID, Event: 2}}}))
	if len(evs) != 2 || evs[0].Status != im.UnsupportedAccess || payload(t, evs[1]) != "view" {
		t.Fatalf("events %+v", evs)
	}
}

func TestReadEventsChunked(t *testing.T) {
	f := newFixture(t).withEvents()
	f.node.Events = im.NewEventLog(0, 8000, 0)
	big := strings.Repeat("e", 300)
	for i := 0; i < 12; i++ {
		f.emit(1, im.PriorityInfo, 0, big)
	}
	rds := f.readAll(im.Request{
		Attributes: []im.AttributePath{{Endpoint: 2, Cluster: 0xFFF1FC01, AnyAttribute: true}},
		Events:     []im.EventPath{anyEvent},
	})
	if len(rds) < 4 {
		t.Fatalf("%d chunks", len(rds))
	}
	evs := events(rds)
	if len(evs) != 12 {
		t.Fatalf("%d events", len(evs))
	}
	for i := 1; i < len(evs); i++ {
		if evs[i].Number != evs[i-1].Number+1 {
			t.Fatalf("event %d numbered %d after %d", i, evs[i].Number, evs[i-1].Number)
		}
	}
}

func TestSubscribeEvents(t *testing.T) {
	f := newFixture(t).withEvents()
	f.emit(1, im.PriorityInfo, 0, "old")

	urgent := &subClient{}
	f.subscribeWith(urgent, im.EncodeSubscribe(im.Request{Events: []im.EventPath{
		{Endpoint: 3, Cluster: evClusterID, AnyEvent: true, IsUrgent: true}}}, 2, 60, true))
	if urgent.subID == 0 || len(urgent.reports) != 1 || len(urgent.reports[0].Events) != 1 {
		t.Fatalf("urgent priming: %+v", urgent.reports)
	}
	lazy := &subClient{}
	f.subscribeWith(lazy, im.EncodeSubscribe(im.Request{
		Attributes: []im.AttributePath{onOffPath},
		Events:     []im.EventPath{anyEvent},
		EventMin:   1 << 40, // skips the old event
	}, 0, 30, true))
	if lazy.subID == 0 || len(lazy.reports) != 1 || len(lazy.reports[0].Events) != 0 {
		t.Fatalf("lazy priming: %+v", lazy.reports[0])
	}

	// An urgent event is reported at the min interval, once.
	f.emit(1, im.PriorityInfo, 0, "new")
	f.w.Advance(time.Second)
	if len(urgent.reports) != 1 {
		t.Fatal("reported before the min interval")
	}
	f.w.Advance(1500 * time.Millisecond)
	if len(urgent.reports) != 2 || len(urgent.reports[1].Events) != 1 || payload(t, urgent.reports[1].Events[0]) != "new" {
		t.Fatalf("urgent report: %d reports", len(urgent.reports))
	}
	f.w.Advance(5 * time.Second)
	if len(urgent.reports) != 2 {
		t.Fatal("event reported twice")
	}

	// Non-urgent events wait for the next report: an attribute change.
	if len(lazy.reports) != 1 {
		t.Fatalf("lazy subscription reported early: %d", len(lazy.reports))
	}
	f.onoff.Set(f.node, 1, true)
	f.w.Advance(100 * time.Millisecond)
	if len(lazy.reports) != 2 {
		t.Fatalf("no change report: %d", len(lazy.reports))
	}
	rd := lazy.reports[1]
	if len(rd.Reports) != 1 || len(rd.Events) != 1 || payload(t, rd.Events[0]) != "new" {
		t.Fatalf("change report: %d attributes, %d events", len(rd.Reports), len(rd.Events))
	}
	// ... or the keep-alive at the max interval.
	f.emit(2, im.PriorityCritical, 0, "late")
	f.w.Advance(29 * time.Second)
	if n := len(lazy.reports); n != 2 {
		t.Fatalf("%d reports before the max interval", n)
	}
	f.w.Advance(2 * time.Second)
	if n := len(lazy.reports); n != 3 || len(lazy.reports[2].Events) != 1 || payload(t, lazy.reports[2].Events[0]) != "late" {
		t.Fatalf("keep-alive: %d reports", n)
	}
}

func TestEventDataRoundTrip(t *testing.T) {
	// The fields structure of an event is reported as written, with the
	// fabric index appended to fabric-sensitive events.
	f := newFixture(t).withEvents()
	f.node.Emit(f.w.Now, im.Event{
		Path: im.ConcreteEventPath{Endpoint: 3, Cluster: evClusterID, Event: 1}, Priority: im.PriorityInfo, Fabric: 1,
		Fields: func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(1), 7)
			w.PutNull(tlv.ContextTag(2))
		},
	})
	evs := events(f.readAll(im.Request{Events: []im.EventPath{anyEvent}}))
	want := []byte{0x35, 0x07, 0x24, 0x01, 0x07, 0x34, 0x02, 0x24, 0xFE, 0x01, 0x18}
	if len(evs) != 1 || !bytes.Equal(evs[0].Data, want) {
		t.Fatalf("data %x", evs[0].Data)
	}
}
