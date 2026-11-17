package device_test

import (
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/storage"
)

// resSubscriber is a controller's subscription client: it records the
// subscription ID and the reports, and answers reports with answer.
type resSubscriber struct {
	id       uint32
	reports  []uint32 // subscription ID of each report
	answer   im.Status
	sessions []*exchange.Session // session of each report
}

func (c *resSubscriber) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	switch msg.Opcode {
	case im.OpReportData:
		rd, err := im.DecodeReportData(msg.Payload)
		if err != nil {
			return
		}
		c.reports = append(c.reports, rd.SubscriptionID)
		c.sessions = append(c.sessions, ex.Session())
		ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(c.answer))
		if c.answer != im.Success {
			ex.Close(now)
		}
	case im.OpSubscribeResp:
		c.id, _, _ = im.DecodeSubscribeResponse(msg.Payload)
		ex.Close(now)
	}
}
func (c *resSubscriber) OnError(time.Time, *exchange.Exchange, error) {}

// subscribeOnOff subscribes the controller to the light's OnOff over s.
func subscribeOnOff(t *testing.T, h *harness, s *exchange.Session, c *resSubscriber) {
	t.Helper()
	h.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c })
	ex, _ := h.ctl.M.NewExchange(s, c)
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpSubscribeRequest, im.EncodeSubscribeRequest(
		[]im.AttributePath{{Endpoint: 1, Cluster: clusters.IDOnOff, Attribute: 0}}, 1, 60, false, true))
	h.w.Advance(time.Second)
	if c.id == 0 || h.dev.Server.Subscriptions() != 1 {
		t.Fatalf("not subscribed: %+v", c)
	}
	h.w.Advance(2 * time.Second) // saved
}

func toggle(h *harness) {
	l := h.dev.Node.Endpoint(1).Cluster(clusters.IDOnOff).(*clusters.OnOff)
	l.On = !l.On
	h.dev.Node.Changed(1, clusters.IDOnOff, 0)
}

// After a restart, the device opens a CASE session to the subscriber and
// reports under the subscription's ID; the subscription goes on.
func TestSubscriptionResumedAfterRestart(t *testing.T) {
	store := &storage.Memory{}
	h := bindingHarness(t, store)
	ctlF, s := h.commission()
	c := &resSubscriber{}
	subscribeOnOff(t, h, s, c)

	h2 := bindingHarness(t, store)
	ctlResponder(t, h2, ctlF)
	c2 := &resSubscriber{}
	h2.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c2 })
	if n := h2.dev.Server.Subscriptions(); n != 1 {
		t.Fatalf("%d subscriptions restored", n)
	}
	h2.w.Advance(3 * time.Second)
	if len(c2.reports) != 0 {
		t.Fatal("resumed before the boot delay")
	}
	h2.w.Advance(10 * time.Second)
	if len(c2.reports) != 1 || c2.reports[0] != c.id {
		t.Fatalf("reports after the restart %x, want one for %x", c2.reports, c.id)
	}
	toggle(h2)
	h2.w.Advance(2 * time.Second)
	if len(c2.reports) != 2 || c2.reports[1] != c.id {
		t.Fatalf("change not reported: %x", c2.reports)
	}
	// Max interval: still alive a minute later.
	h2.w.Advance(70 * time.Second)
	if len(c2.reports) < 3 {
		t.Fatalf("no report within the max interval: %x", c2.reports)
	}

	// And after another restart.
	h2.w.Advance(5 * time.Second)
	h3 := bindingHarness(t, store)
	ctlResponder(t, h3, ctlF)
	c3 := &resSubscriber{}
	h3.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c3 })
	h3.w.Advance(15 * time.Second)
	if len(c3.reports) != 1 || c3.reports[0] != c.id {
		t.Fatalf("reports after the second restart %x", c3.reports)
	}
}

// A subscriber that no longer knows the subscription ends it.
func TestSubscriptionResumeRefused(t *testing.T) {
	store := &storage.Memory{}
	h := bindingHarness(t, store)
	ctlF, s := h.commission()
	subscribeOnOff(t, h, s, &resSubscriber{})

	h2 := bindingHarness(t, store)
	ctlResponder(t, h2, ctlF)
	c2 := &resSubscriber{answer: im.InvalidSubscription}
	h2.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c2 })
	h2.w.Advance(15 * time.Second)
	if len(c2.reports) != 1 {
		t.Fatalf("%d reports", len(c2.reports))
	}
	if n := h2.dev.Server.Subscriptions(); n != 0 {
		t.Fatalf("%d subscriptions after the subscriber refused", n)
	}
	h2.w.Advance(time.Minute)
	if len(c2.reports) != 1 {
		t.Fatal("reported again")
	}
	h3 := bindingHarness(t, store)
	if n := h3.dev.Server.Subscriptions(); n != 0 {
		t.Fatalf("the ended subscription was restored (%d)", n)
	}
}

// A subscriber that cannot be reached is tried less and less often, and
// the subscription ends after a day or so.
func TestSubscriptionResumeGivesUp(t *testing.T) {
	store := &storage.Memory{}
	h := bindingHarness(t, store)
	_, s := h.commission()
	subscribeOnOff(t, h, s, &resSubscriber{})

	h2 := bindingHarness(t, store) // no CASE responder: Sigma1 goes unanswered
	sigma1 := 0
	h2.w.Drop = func(p simnet.Packet) bool {
		if p.To == h2.ctl.Addr && len(p.Data) > 0 {
			sigma1++
		}
		return p.To == h2.ctl.Addr
	}
	h2.w.Advance(time.Hour)
	if h2.dev.Server.Subscriptions() != 1 {
		t.Fatal("ended within an hour")
	}
	early := sigma1
	h2.w.Advance(2 * time.Hour)
	if sigma1-early > early {
		t.Errorf("not backing off: %d packets in the first hour, %d in the next two", early, sigma1-early)
	}
	h2.w.Advance(24 * time.Hour)
	if n := h2.dev.Server.Subscriptions(); n != 0 {
		t.Fatalf("%d subscriptions after a day unreachable", n)
	}
	h2.w.Advance(5 * time.Second)
	if n := bindingHarness(t, store).dev.Server.Subscriptions(); n != 0 {
		t.Fatalf("the ended subscription was restored (%d)", n)
	}
}

// A subscriber that stops answering loses the subscription, which is
// resumed over a new session when it answers again.
func TestSubscriptionLostAndResumed(t *testing.T) {
	store := &storage.Memory{}
	h := bindingHarness(t, store)
	ctlF, s := h.commission()
	ctlResponder(t, h, ctlF)
	c := &resSubscriber{}
	subscribeOnOff(t, h, s, c)
	h.w.Drop = func(p simnet.Packet) bool { return p.To == h.ctl.Addr }
	toggle(h)
	h.w.Advance(time.Minute) // the report's retransmissions run out
	if s2 := h.dev.Server.Subscriptions(); s2 != 1 {
		t.Fatalf("%d subscriptions", s2)
	}
	lost := 0
	h.dev.Server.Lost(func(im.LostSubscription) { lost++ })
	if lost != 1 {
		t.Fatal("subscription not lost")
	}
	h.w.Drop = nil
	before := len(c.reports)
	h.w.Advance(time.Minute)
	if len(c.reports) != before+1 || c.reports[before] != c.id {
		t.Fatalf("not resumed: reports %x", c.reports)
	}
	if c.sessions[before] == s {
		t.Fatal("resumed over the dead session")
	}
	toggle(h)
	h.w.Advance(2 * time.Second)
	if len(c.reports) != before+2 {
		t.Fatalf("change after resumption not reported: %x", c.reports)
	}
}
