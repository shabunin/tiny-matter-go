package device_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// readQ runs a read on s and returns its chunks.
func (h *harness) readQ(s *exchange.Session, q im.Request) []*im.ReportData {
	h.t.Helper()
	var out []*im.ReportData
	ex, err := h.ctl.M.NewExchange(s, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
		if msg.Opcode != im.OpReportData {
			st, _ := im.DecodeStatusResponse(msg.Payload)
			h.t.Errorf("read: opcode %#x status %#x", msg.Opcode, st)
			ex.Close(now)
			return
		}
		rd, err := im.DecodeReportData(bytes.Clone(msg.Payload))
		if err != nil {
			h.t.Fatal(err)
		}
		out = append(out, rd)
		if rd.MoreChunks {
			ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(im.Success))
		} else {
			ex.Close(now)
		}
	}))
	if err != nil {
		h.t.Fatal(err)
	}
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpReadRequest, im.EncodeRead(q))
	h.w.Advance(time.Second)
	return out
}

func (h *harness) events(s *exchange.Session, paths ...im.EventPath) []im.EventReport {
	h.t.Helper()
	var out []im.EventReport
	for _, rd := range h.readQ(s, im.Request{Events: paths}) {
		out = append(out, rd.Events...)
	}
	return out
}

func (h *harness) attr(s *exchange.Session, ep uint16, cl, attr uint32) *tlv.Reader {
	h.t.Helper()
	rds := h.readQ(s, im.Request{Attributes: []im.AttributePath{{Endpoint: ep, Cluster: cl, Attribute: attr}}})
	if len(rds) != 1 || len(rds[0].Reports) != 1 || rds[0].Reports[0].Status != im.Success {
		h.t.Fatalf("read %d/%#x/%#x: %+v", ep, cl, attr, rds)
	}
	r := tlv.NewReader(rds[0].Reports[0].Data)
	r.Next()
	return r
}

// fields decodes an event's fields into tag -> reader positioned on it.
func fields(t *testing.T, ev im.EventReport) map[uint8]*tlv.Reader {
	t.Helper()
	m := map[uint8]*tlv.Reader{}
	err := im.ForEachField(tlv.NewReader(ev.Data), func(r *tlv.Reader, tag uint8) error {
		c := *r
		m[tag] = &c
		return nil
	})
	if err != nil {
		t.Fatalf("event data %x: %v", ev.Data, err)
	}
	return m
}

func uintField(t *testing.T, ev im.EventReport, tag uint8) uint64 {
	t.Helper()
	r, ok := fields(t, ev)[tag]
	if !ok {
		t.Fatalf("event %+v: no field %d", ev.Path, tag)
	}
	v, err := r.Uint()
	if err != nil {
		t.Fatalf("field %d: %v", tag, err)
	}
	return v
}

func TestBootEvents(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	h.dev.Diagnostics.BootReason = clusters.BootSoftwareReset
	_, caseS := h.commission()

	evs := h.events(caseS, im.EventPath{Endpoint: 0, AnyCluster: true, AnyEvent: true})
	// StartUp and BootReason, then the ACL entry AddNOC created.
	if len(evs) != 3 {
		t.Fatalf("%d events: %+v", len(evs), evs)
	}
	if p := evs[0].Path; p.Cluster != clusters.IDBasicInformation || p.Event != clusters.EventStartUp || evs[0].Priority != im.PriorityCritical {
		t.Fatalf("first event %+v", evs[0])
	}
	if p := evs[1].Path; p.Cluster != clusters.IDGeneralDiagnostics || uintField(t, evs[1], 0) != clusters.BootSoftwareReset {
		t.Fatalf("second event %+v", evs[1])
	}
	if v, _ := h.attr(caseS, 0, clusters.IDGeneralDiagnostics, 1).Uint(); v != 1 {
		t.Fatalf("reboot count %d", v)
	}
	last := evs[2].Number

	// After a restart, numbers continue upwards and the reboot is counted.
	h2 := newHarnessStore(t, store)
	h2.w.Advance(time.Second)
	if h2.dev.Diagnostics.RebootCount != 2 {
		t.Fatalf("reboot count after restart %d", h2.dev.Diagnostics.RebootCount)
	}
	if next := h2.dev.Node.Events.Next(); next <= last+2 || next < im.EventNumberEpoch {
		t.Fatalf("event numbers restarted at %d (last %d)", next, last)
	}
}

func TestACLEvents(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()
	acl := im.EventPath{Endpoint: 0, Cluster: clusters.IDAccessControl, Event: clusters.EventACLEntryChanged}

	// AddNOC's administrator entry, added over PASE.
	evs := h.events(caseS, acl)
	if len(evs) != 1 {
		t.Fatalf("%d ACL events", len(evs))
	}
	f := fields(t, evs[0])
	if !f[1].IsNull() || uintField(t, evs[0], 2) != 0 || uintField(t, evs[0], 3) != clusters.ACLAdded || uintField(t, evs[0], 0xFE) != 1 {
		t.Fatalf("AddNOC event %x", evs[0].Data)
	}

	// Replacing the list with two entries over CASE: one changed, one
	// added, by the controller's node ID.
	entry := func(w *tlv.Writer, priv uint64) {
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), priv)
		w.PutUint(tlv.ContextTag(2), uint64(exchange.AuthCASE))
		w.StartArray(tlv.ContextTag(3))
		w.PutUint(tlv.Anonymous, 0x1B669)
		w.EndContainer()
		w.PutNull(tlv.ContextTag(4))
		w.EndContainer()
	}
	write := func(n int) {
		var got []byte
		ex, _ := h.ctl.M.NewExchange(caseS, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
			got = bytes.Clone(msg.Payload)
			ex.Close(now)
		}))
		ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpWriteRequest, im.EncodeWriteRequest(
			im.AttributePath{Endpoint: 0, Cluster: clusters.IDAccessControl, Attribute: 0}, false,
			func(w *tlv.Writer, tag tlv.Tag) {
				w.StartArray(tag)
				entry(w, uint64(im.Administer))
				for i := 1; i < n; i++ {
					entry(w, uint64(im.View))
				}
				w.EndContainer()
			}))
		h.w.Advance(time.Second)
		res, err := im.DecodeWriteResponse(got)
		if err != nil || len(res) != 1 || res[0].Status != im.Success {
			t.Fatalf("ACL write: %+v %v", res, err)
		}
	}
	write(2)
	evs = h.events(caseS, acl)
	if len(evs) != 3 {
		t.Fatalf("%d ACL events after the write", len(evs))
	}
	for i, want := range []uint64{clusters.ACLChanged, clusters.ACLAdded} {
		ev := evs[1+i]
		if uintField(t, ev, 1) != 0x1B669 || !fields(t, ev)[2].IsNull() || uintField(t, ev, 3) != want {
			t.Fatalf("event %d: %x", i, ev.Data)
		}
	}
	write(1)
	evs = h.events(caseS, acl)
	if len(evs) != 5 || uintField(t, evs[4], 3) != clusters.ACLRemoved {
		t.Fatalf("%d events; last %x", len(evs), evs[len(evs)-1].Data)
	}
}

func TestLeaveAndFabricScopedEvents(t *testing.T) {
	h := newHarness(t)
	_, case1 := h.commission()
	const code2 = 12345678
	if res := h.invokeTimed(case1, ac(0), enhancedWindow(code2, []byte("multi-admin salt"), 1000, 0x123)); res.Status != im.Success {
		t.Fatalf("OpenCommissioningWindow: %+v", res)
	}
	_, case2 := h.commissionWith(code2, 2)

	// Each fabric reads only its own ACL events.
	acl := im.EventPath{Endpoint: 0, Cluster: clusters.IDAccessControl, AnyEvent: true}
	for i, s := range []*exchange.Session{case1, case2} {
		evs := h.events(s, acl)
		if len(evs) != 1 || uintField(t, evs[0], 0xFE) != uint64(i+1) {
			t.Fatalf("fabric %d: %d ACL events", i+1, len(evs))
		}
	}

	// Fabric 2 removes fabric 1: the node leaves it.
	res := h.invoke(case2, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: 0x0A},
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 1) })
	if res.Status != im.Success {
		t.Fatalf("RemoveFabric: %+v", res)
	}
	h.w.Advance(time.Second)
	evs := h.events(case2, im.EventPath{Endpoint: 0, Cluster: clusters.IDBasicInformation, Event: clusters.EventLeave})
	if len(evs) != 1 || uintField(t, evs[0], 0) != 1 {
		t.Fatalf("Leave events %+v", evs)
	}
}

func TestGeneralDiagnostics(t *testing.T) {
	h := newHarness(t)
	g := h.dev.Diagnostics
	var triggered []uint64
	g.Trigger = func(ctx *im.Context, trigger uint64) im.Status {
		triggered = append(triggered, trigger)
		return im.Success
	}
	_, caseS := h.commission()
	gd := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralDiagnostics, Command: cmd}
	}
	key := bytes.Repeat([]byte{0xAA}, 16)
	trigger := func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), key)
		w.PutUint(tlv.ContextTag(1), 0x1234)
	}
	if res := h.invoke(caseS, gd(0), trigger); res.Status != im.ConstraintError {
		t.Fatalf("trigger while disabled: %+v", res)
	}
	if on, _ := h.attr(caseS, 0, clusters.IDGeneralDiagnostics, 8).Bool(); on {
		t.Fatal("triggers enabled")
	}
	copy(g.EnableKey[:], key)
	if res := h.invoke(caseS, gd(0), trigger); res.Status != im.Success || len(triggered) != 1 || triggered[0] != 0x1234 {
		t.Fatalf("trigger: %+v %v", res, triggered)
	}

	h.w.Advance(90 * time.Second)
	if up, _ := h.attr(caseS, 0, clusters.IDGeneralDiagnostics, 2).Uint(); up < 90 || up > 1000 {
		t.Fatalf("uptime %d", up)
	}
	res := h.invoke(caseS, gd(1), nil)
	if res.Path.Command != 2 {
		t.Fatalf("TimeSnapshot: %+v", res)
	}
	if ms, _ := field(t, res.Fields, 0).Uint(); ms < 90000 {
		t.Fatalf("system time %d ms", ms)
	}
	if !field(t, res.Fields, 1).IsNull() {
		t.Fatal("posix time without a clock")
	}
}

func TestSwitchAndIdentify(t *testing.T) {
	h := newHarness(t)
	sw := &clusters.Switch{}
	var identifying []bool
	id := &clusters.Identify{Type: clusters.IdentifyVisibleIndicator, OnIdentify: func(on bool) { identifying = append(identifying, on) }}
	ep := h.dev.Node.AddEndpoint(2, clusters.DeviceTypeGenericSwitch)
	h.dev.Node.AddCluster(ep, clusters.Descriptor{}, id, sw)
	_, caseS := h.commission()

	// An urgent subscription to the switch's events.
	c := &eventSubscriber{}
	h.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c })
	ex, _ := h.ctl.M.NewExchange(caseS, c)
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpSubscribeRequest, im.EncodeSubscribe(im.Request{
		Events: []im.EventPath{{Endpoint: 2, Cluster: clusters.IDSwitch, AnyEvent: true, IsUrgent: true}},
	}, 0, 60, false))
	h.w.Advance(time.Second)
	if c.subID == 0 {
		t.Fatal("subscription failed")
	}

	press := func(hold time.Duration) {
		sw.Press(h.dev.Node, 2, h.w.Now)
		h.w.Advance(hold)
		sw.Release(h.dev.Node, 2, h.w.Now)
		h.w.Advance(100 * time.Millisecond)
	}
	press(200 * time.Millisecond)
	press(1500 * time.Millisecond) // LongPress comes from Poll while held
	var got []uint32
	for _, ev := range c.events {
		got = append(got, ev.Path.Event)
		if uintField(t, ev, 0) != 1 {
			t.Fatalf("position field of %+v", ev)
		}
	}
	want := []uint32{clusters.EventInitialPress, clusters.EventShortRelease,
		clusters.EventInitialPress, clusters.EventLongPress, clusters.EventLongRelease}
	if len(got) != len(want) {
		t.Fatalf("switch events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("switch events %v, want %v", got, want)
		}
	}

	// Identify for 3 s: started by a command, stopped by the timer.
	res := h.invoke(caseS, im.CommandPath{Endpoint: 2, Cluster: clusters.IDIdentify, Command: 0},
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 3) })
	if res.Status != im.Success || len(identifying) != 1 || !identifying[0] {
		t.Fatalf("Identify: %+v %v", res, identifying)
	}
	if v, _ := h.attr(caseS, 2, clusters.IDIdentify, 0).Uint(); v < 1 || v > 3 {
		t.Fatalf("IdentifyTime %d", v)
	}
	h.w.Advance(3 * time.Second)
	if len(identifying) != 2 || identifying[1] || id.Identifying() {
		t.Fatalf("identify did not stop: %v", identifying)
	}
}

// eventSubscriber acknowledges reports and collects their events.
type eventSubscriber struct {
	subID  uint32
	events []im.EventReport
}

func (c *eventSubscriber) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	switch msg.Opcode {
	case im.OpReportData:
		rd, err := im.DecodeReportData(bytes.Clone(msg.Payload))
		if err == nil {
			c.events = append(c.events, rd.Events...)
		}
		ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(im.Success))
	case im.OpSubscribeResp:
		c.subID, _, _ = im.DecodeSubscribeResponse(msg.Payload)
		ex.Close(now)
	}
}
func (c *eventSubscriber) OnError(time.Time, *exchange.Exchange, error) {}
