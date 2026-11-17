package device_test

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const aggregatorEP = 20

// addBridged bridges a contact sensor on ep, under the aggregator.
func addBridged(h *harness, ep uint16, label string) (*clusters.BooleanState, *clusters.BridgedDeviceBasicInformation) {
	st := &clusters.BooleanState{}
	info := &clusters.BridgedDeviceBasicInformation{ProductName: "Door", NodeLabel: label, UniqueID: "door-1"}
	e := h.dev.Node.AddEndpoint(ep, clusters.DeviceTypeContactSensor, clusters.DeviceTypeBridgedNode)
	e.Parent = aggregatorEP
	h.dev.Node.AddCluster(e, clusters.Descriptor{}, &clusters.Identify{}, st, info)
	return st, info
}

func addAggregator(h *harness) {
	h.dev.Node.AddCluster(h.dev.Node.AddEndpoint(aggregatorEP, clusters.DeviceTypeAggregator), clusters.Descriptor{})
}

func (h *harness) uintList(s *exchange.Session, ep uint16, cl, attr uint32) []uint64 {
	h.t.Helper()
	r := h.attr(s, ep, cl, attr)
	if r.EnterContainer() != nil {
		h.t.Fatalf("%d/%#x/%#x: not a list", ep, cl, attr)
	}
	var out []uint64
	for r.Next() == nil {
		if r.Type() == tlv.TypeStruct { // DeviceTypeStruct: the type
			r.EnterContainer()
			r.Next()
			v, _ := r.Uint()
			out = append(out, v)
			r.ExitContainer()
			continue
		}
		v, err := r.Uint()
		if err != nil {
			h.t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// pathRecorder is a subscriber that records the attribute paths reported.
type pathRecorder struct {
	t     *testing.T
	paths []im.ConcretePath
}

func (c *pathRecorder) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	switch msg.Opcode {
	case im.OpReportData:
		rd, err := im.DecodeReportData(bytes.Clone(msg.Payload))
		if err != nil {
			c.t.Fatal(err)
		}
		for _, r := range rd.Reports {
			c.paths = append(c.paths, im.ConcretePath{Endpoint: r.Path.Endpoint, Cluster: r.Path.Cluster, Attribute: r.Path.Attribute})
		}
		ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(im.Success))
	case im.OpSubscribeResp:
		ex.Close(now)
	}
}
func (c *pathRecorder) OnError(time.Time, *exchange.Exchange, error) {}

func (c *pathRecorder) saw(p im.ConcretePath) bool { return slices.Contains(c.paths, p) }

func TestBridge(t *testing.T) {
	h := newHarness(t)
	_, s := h.commission()
	addAggregator(h)
	h.dev.AddedEndpoint(aggregatorEP)

	// A subscription to every parts list and contact state. (It is kept
	// narrow: a wider one would overflow its few remembered changes and
	// report everything, hiding what is reported.)
	c := &pathRecorder{t: t}
	h.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c })
	ex, _ := h.ctl.M.NewExchange(s, c)
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpSubscribeRequest, im.EncodeSubscribeRequest(
		[]im.AttributePath{{AnyEndpoint: true, Cluster: clusters.IDDescriptor, Attribute: 3},
			{AnyEndpoint: true, Cluster: clusters.IDBooleanState, Attribute: 0}}, 0, 60, false, true))
	h.w.Advance(time.Second)
	c.paths = nil

	// A device is bridged: the parts lists and its attributes are reported.
	st, info := addBridged(h, 21, "Front door")
	h.dev.AddedEndpoint(21)
	h.w.Advance(time.Second)
	for _, p := range []im.ConcretePath{
		{Endpoint: 0, Cluster: clusters.IDDescriptor, Attribute: 3},
		{Endpoint: aggregatorEP, Cluster: clusters.IDDescriptor, Attribute: 3},
		{Endpoint: 21, Cluster: clusters.IDDescriptor, Attribute: 3},
		{Endpoint: 21, Cluster: clusters.IDBooleanState, Attribute: 0},
	} {
		if !c.saw(p) {
			t.Errorf("not reported: %+v (got %+v)", p, c.paths)
		}
	}
	if got := h.uintList(s, 0, clusters.IDDescriptor, 3); !slices.Contains(got, aggregatorEP) || !slices.Contains(got, 21) {
		t.Errorf("root parts %v", got)
	}
	if got := h.uintList(s, aggregatorEP, clusters.IDDescriptor, 3); !slices.Equal(got, []uint64{21}) {
		t.Errorf("aggregator parts %v", got)
	}
	if got := h.uintList(s, 21, clusters.IDDescriptor, 3); len(got) != 0 {
		t.Errorf("bridged device parts %v", got)
	}
	if got := h.uintList(s, 21, clusters.IDDescriptor, 0); !slices.Equal(got, []uint64{0x0015, 0x0013}) {
		t.Errorf("bridged device types %#x", got)
	}

	// Bridged Device Basic Information.
	if l, _ := h.attr(s, 21, clusters.IDBridgedDeviceBasicInformation, 5).String(); l != "Front door" {
		t.Errorf("NodeLabel %q", l)
	}
	if u, _ := h.attr(s, 21, clusters.IDBridgedDeviceBasicInformation, 0x12).String(); u != "door-1" {
		t.Errorf("UniqueID %q", u)
	}
	rds := h.readQ(s, im.Request{Attributes: []im.AttributePath{{Endpoint: 21, Cluster: clusters.IDBridgedDeviceBasicInformation, Attribute: 1}}})
	if len(rds) != 1 || len(rds[0].Reports) != 1 || rds[0].Reports[0].Status != im.UnsupportedAttribute {
		t.Errorf("VendorName (unset) read: %+v", rds)
	}
	info.SetReachable(h.dev.Node, 21, h.w.Now, false)
	if r, _ := h.attr(s, 21, clusters.IDBridgedDeviceBasicInformation, 0x11).Bool(); r {
		t.Error("still reachable")
	}
	evs := h.events(s, im.EventPath{Endpoint: 21, Cluster: clusters.IDBridgedDeviceBasicInformation, Event: clusters.EventReachableChanged})
	if len(evs) != 1 {
		t.Fatalf("ReachableChanged events: %+v", evs)
	}
	if v, _ := fields(t, evs[0])[0].Bool(); v {
		t.Error("ReachableChanged says reachable")
	}

	// The sensor reports through the bridge.
	c.paths = nil
	st.Set(h.dev.Node, 21, h.w.Now, true)
	h.w.Advance(time.Second)
	if !c.saw(im.ConcretePath{Endpoint: 21, Cluster: clusters.IDBooleanState, Attribute: 0}) {
		t.Errorf("StateValue not reported: %+v", c.paths)
	}
	if v, _ := h.attr(s, 21, clusters.IDBooleanState, 0).Bool(); !v {
		t.Error("StateValue false")
	}

	// The device goes away.
	c.paths = nil
	h.dev.RemoveEndpoint(21)
	h.w.Advance(time.Second)
	if !c.saw(im.ConcretePath{Endpoint: aggregatorEP, Cluster: clusters.IDDescriptor, Attribute: 3}) ||
		!c.saw(im.ConcretePath{Endpoint: 0, Cluster: clusters.IDDescriptor, Attribute: 3}) {
		t.Errorf("removal not reported: %+v", c.paths)
	}
	if got := h.uintList(s, aggregatorEP, clusters.IDDescriptor, 3); len(got) != 0 {
		t.Errorf("aggregator parts after removal %v", got)
	}
	rds = h.readQ(s, im.Request{Attributes: []im.AttributePath{{Endpoint: 21, Cluster: clusters.IDBooleanState, Attribute: 0}}})
	if len(rds) != 1 || len(rds[0].Reports) != 1 || rds[0].Reports[0].Status != im.UnsupportedEndpoint {
		t.Errorf("read of the removed endpoint: %+v", rds)
	}
}

// A bridged device's NodeLabel is saved; it comes back when the bridge
// re-adds the device after a restart.
func TestBridgedLabelSaved(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	_, s := h.commission()
	addAggregator(h)
	addBridged(h, 21, "Door")
	h.dev.AddedEndpoint(21)
	st := h.write(s, im.AttributePath{Endpoint: 21, Cluster: clusters.IDBridgedDeviceBasicInformation, Attribute: 5},
		func(w *tlv.Writer, tag tlv.Tag) { w.PutString(tag, "Back door") })
	if st != im.Success {
		t.Fatalf("write NodeLabel: %#x", st)
	}
	if st := h.write(s, im.AttributePath{Endpoint: 21, Cluster: clusters.IDBridgedDeviceBasicInformation, Attribute: 0x12},
		func(w *tlv.Writer, tag tlv.Tag) { w.PutString(tag, "x") }); st != im.UnsupportedWrite {
		t.Errorf("write UniqueID: %#x", st)
	}
	h.w.Advance(5 * time.Second)

	h2 := newHarnessStore(t, store)
	addAggregator(h2)
	_, info := addBridged(h2, 21, "Door")
	if info.NodeLabel != "Back door" {
		t.Fatalf("NodeLabel after restart %q", info.NodeLabel)
	}
}
