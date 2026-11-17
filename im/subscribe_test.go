package im_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
)

// subClient acknowledges every ReportData and records what it received.
type subClient struct {
	reports []*im.ReportData
	subID   uint32
	maxInt  uint16
	answer  im.Status // status sent for reports (Success by default)
}

func (c *subClient) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	switch msg.Opcode {
	case im.OpReportData:
		rd, err := im.DecodeReportData(bytes.Clone(msg.Payload))
		if err != nil {
			panic(err)
		}
		c.reports = append(c.reports, rd)
		ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(c.answer))
		if c.answer != im.Success || (!rd.MoreChunks && ex.IsInitiator() == false) {
			ex.Close(now)
		}
	case im.OpSubscribeResp:
		c.subID, c.maxInt, _ = im.DecodeSubscribeResponse(msg.Payload)
		ex.Close(now)
	default:
		ex.Close(now)
	}
}
func (c *subClient) OnError(time.Time, *exchange.Exchange, error) {}

func (f *fixture) subscribe(c *subClient, keep bool, minFloor, maxCeil uint16, paths ...im.AttributePath) {
	f.t.Helper()
	f.subscribeWith(c, im.EncodeSubscribeRequest(paths, minFloor, maxCeil, keep, true))
}

// subscribeWith sends a SubscribeRequest and runs until it is established.
func (f *fixture) subscribeWith(c *subClient, req []byte) {
	f.t.Helper()
	// Reports arrive on exchanges the device starts; the router hands them
	// to the client of their subscription.
	if f.router == nil {
		f.router = &subRouter{}
		f.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return f.router })
	}
	f.router.clients = append(f.router.clients, c)
	ex, err := f.ctl.M.NewExchange(f.cs, c)
	if err != nil {
		f.t.Fatal(err)
	}
	ex.Send(f.w.Now, message.ProtocolInteractionModel, im.OpSubscribeRequest, req)
	f.w.Advance(100 * time.Millisecond)
}

// subRouter passes device-initiated reports to the client of their
// subscription (the latest client if none matches).
type subRouter struct{ clients []*subClient }

func (r *subRouter) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	c := r.clients[len(r.clients)-1]
	if rd, err := im.DecodeReportData(msg.Payload); err == nil && msg.Opcode == im.OpReportData {
		for _, x := range r.clients {
			if x.subID == rd.SubscriptionID {
				c = x
			}
		}
	}
	c.OnMessage(now, ex, msg)
}
func (r *subRouter) OnError(time.Time, *exchange.Exchange, error) {}

var onOffPath = im.AttributePath{Endpoint: 1, Cluster: clusters.IDOnOff, Attribute: 0}

func TestSubscribeReportsChanges(t *testing.T) {
	f := newFixture(t)
	c := &subClient{}
	f.subscribe(c, false, 0, 10, onOffPath)
	if c.subID == 0 || c.maxInt != 10 || len(c.reports) != 1 {
		t.Fatalf("subscribe: id %d max %d reports %d", c.subID, c.maxInt, len(c.reports))
	}
	prime := c.reports[0]
	if prime.SubscriptionID != c.subID || prime.SuppressResponse || len(prime.Reports) != 1 || prime.Reports[0].Path.Attribute != 0 {
		t.Fatalf("priming report %+v", prime)
	}

	// A change is reported on a device-initiated exchange.
	f.onoff.Set(f.node, 1, true)
	f.w.Advance(100 * time.Millisecond)
	if len(c.reports) != 2 {
		t.Fatalf("no change report (%d reports)", len(c.reports))
	}
	rd := c.reports[1]
	if rd.SubscriptionID != c.subID || len(rd.Reports) != 1 || !bytes.Equal(rd.Reports[0].Data, []byte{0x29, 0x02}) /* context tag 2: true */ {
		t.Fatalf("change report %+v data %x", rd, rd.Reports[0].Data)
	}
	if f.server.Subscriptions() != 1 {
		t.Fatal("subscription lost after a report")
	}

	// No changes: an empty keep-alive report after the max interval.
	f.w.Advance(9 * time.Second)
	if len(c.reports) != 2 {
		t.Fatal("report before the max interval")
	}
	f.w.Advance(2 * time.Second)
	if len(c.reports) != 3 || len(c.reports[2].Reports) != 0 {
		t.Fatalf("keep-alive: %d reports", len(c.reports))
	}

	// Changes outside the subscribed paths are not reported.
	f.basic.NodeLabel = "x"
	f.node.Changed(0, clusters.IDBasicInformation, 5)
	f.w.Advance(time.Second)
	if len(c.reports) != 3 {
		t.Fatal("reported an unsubscribed attribute")
	}

	// The client rejecting a report ends the subscription.
	c.answer = im.InvalidSubscription
	f.onoff.Set(f.node, 1, false)
	f.w.Advance(time.Second)
	if f.server.Subscriptions() != 0 {
		t.Fatal("subscription kept after InvalidSubscription")
	}
}

func TestSubscribeMinInterval(t *testing.T) {
	f := newFixture(t)
	c := &subClient{}
	f.subscribe(c, false, 5, 60, onOffPath)
	f.onoff.Set(f.node, 1, true)
	f.w.Advance(time.Second)
	if len(c.reports) != 1 {
		t.Fatal("reported before the min interval")
	}
	f.w.Advance(5 * time.Second)
	if len(c.reports) != 2 {
		t.Fatalf("change not reported after the min interval: %d", len(c.reports))
	}
}

func TestSubscribeWildcardChunkedAndReplace(t *testing.T) {
	f := newFixture(t)
	c := &subClient{}
	f.subscribe(c, false, 0, 30, im.AttributePath{AnyEndpoint: true, AnyCluster: true, AnyAttribute: true})
	if c.subID == 0 || len(c.reports) < 2 || !c.reports[0].MoreChunks {
		t.Fatalf("wildcard priming: id %d, %d chunks", c.subID, len(c.reports))
	}
	first := c.subID
	// A second subscription without KeepSubscriptions replaces the first.
	c2 := &subClient{}
	f.subscribe(c2, false, 0, 30, onOffPath)
	if c2.subID == 0 || c2.subID == first || f.server.Subscriptions() != 1 {
		t.Fatalf("replace: id %d, %d subscriptions", c2.subID, f.server.Subscriptions())
	}
	c3 := &subClient{}
	f.subscribe(c3, true, 0, 30, onOffPath)
	if f.server.Subscriptions() != 2 {
		t.Fatal("KeepSubscriptions dropped a subscription")
	}
}

func TestSubscribeSessionClosed(t *testing.T) {
	f := newFixture(t)
	c := &subClient{}
	f.subscribe(c, false, 0, 30, onOffPath)
	f.dev.M.CloseSession(f.w.Now, f.ds)
	f.w.Advance(time.Second)
	if f.server.Subscriptions() != 0 {
		t.Fatal("subscription survived its session")
	}
}

func TestSubscribeInvalid(t *testing.T) {
	f := newFixture(t)
	msgs := f.request(im.OpSubscribeRequest, im.EncodeSubscribeRequest([]im.AttributePath{onOffPath}, 10, 5, false, true))
	if len(msgs) != 1 || msgs[0].Opcode != im.OpStatusResponse {
		t.Fatalf("min > max accepted: %v", msgs)
	}
	// Paths that name nothing: an endpoint, cluster and attribute that do
	// not exist, and a wildcard that matches nothing.
	for _, p := range []im.AttributePath{
		path(9, clusters.IDOnOff, 0),
		path(1, 0xFFF11FFF, 0),
		path(1, clusters.IDOnOff, 0xFFF1),
		{AnyEndpoint: true, Cluster: 0xFFF11FFF, AnyAttribute: true},
	} {
		msgs := f.request(im.OpSubscribeRequest, im.EncodeSubscribeRequest([]im.AttributePath{p}, 1, 5, false, true))
		if len(msgs) != 1 || msgs[0].Opcode != im.OpStatusResponse {
			t.Fatalf("%+v: %v", p, msgs)
		}
		if st, _ := im.DecodeStatusResponse(msgs[0].Payload); st != im.InvalidAction {
			t.Errorf("%+v: status %#x", p, st)
		}
	}
	if f.server.Subscriptions() != 0 {
		t.Fatal("a subscription to nothing was kept")
	}
}
