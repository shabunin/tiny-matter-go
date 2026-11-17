package device_test

import (
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const sensorEndpoint = 2

// bindingHarness is a device with a sensor endpoint whose On/Off client
// sends through a Binding cluster. Resolve finds the controller.
func bindingHarness(t *testing.T, store storage.Store) *harness {
	var h *harness
	h = newHarnessConfig(t, store, false, func(cfg *device.Config) {
		cfg.Log = func(m string) { t.Log(m) }
		cfg.Resolve = func(now time.Time, cfid [8]byte, node uint64) (exchange.Addr, bool) {
			return h.ctl.Addr, node == providerNode
		}
	})
	ep := h.dev.Node.AddEndpoint(sensorEndpoint, clusters.DeviceTypeOccupancySensor)
	ep.Clients = []uint32{clusters.IDOnOff}
	h.dev.Node.AddCluster(ep, clusters.Descriptor{}, h.dev.NewBinding())
	return h
}

// targetLight makes the controller's node a light on endpoint 1.
func targetLight(h *harness) *clusters.OnOff {
	light := &clusters.OnOff{}
	n := im.NewNode(1)
	n.AddCluster(n.AddEndpoint(1), light)
	im.NewServer(h.ctl.M, n)
	return light
}

func bindingList(targets ...func(w *tlv.Writer)) func(w *tlv.Writer, tag tlv.Tag) {
	return func(w *tlv.Writer, tag tlv.Tag) {
		w.StartArray(tag)
		for _, f := range targets {
			w.StartStruct(tlv.Anonymous)
			f(w)
			w.EndContainer()
		}
		w.EndContainer()
	}
}

func TestBinding(t *testing.T) {
	store := &storage.Memory{}
	h := bindingHarness(t, store)
	ctlF, s := h.commission()
	light := targetLight(h)
	path := im.AttributePath{Endpoint: sensorEndpoint, Cluster: clusters.IDBinding, Attribute: 0}

	// A node target needs its endpoint; a group target has neither.
	for _, bad := range []func(w *tlv.Writer){
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(1), providerNode) },
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(2), 7); w.PutUint(tlv.ContextTag(3), 1) },
		func(w *tlv.Writer) {},
	} {
		if st := h.write(s, path, bindingList(bad)); st != im.ConstraintError {
			t.Fatalf("bad target written: %#x", st)
		}
	}
	if st := h.write(s, path, bindingList(func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(1), providerNode)
		w.PutUint(tlv.ContextTag(3), 1)
		w.PutUint(tlv.ContextTag(4), clusters.IDOnOff)
	})); st != im.Success {
		t.Fatalf("write binding: %#x", st)
	}
	if n := h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDLevelControl, 0, nil); n != 0 {
		t.Fatalf("a Level Control command went to %d targets of an On/Off binding", n)
	}

	// Over the commissioning session.
	if n := h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOn, nil); n != 1 {
		t.Fatalf("On queued for %d targets", n)
	}
	h.w.Advance(2 * time.Second)
	if !light.On {
		t.Fatal("light not switched on")
	}
	// A newer command replaces one still waiting: Off is never sent, and
	// Toggle turns the light off (sent after Off, it would turn it on).
	h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOff, nil)
	h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdToggle, nil)
	h.w.Advance(2 * time.Second)
	if light.On {
		t.Fatal("light on: the waiting Off was not replaced")
	}
	h.w.Advance(5 * time.Second) // saved

	// After a restart the binding is kept, and the device opens a CASE
	// session to the light itself.
	h2 := bindingHarness(t, store)
	light2 := targetLight(h2)
	ctlResponder(t, h2, ctlF)
	b := h2.dev.Node.Endpoint(sensorEndpoint).Cluster(clusters.IDBinding).(*clusters.Binding)
	if len(b.Targets) != 1 || b.Targets[0].Node != providerNode || b.Targets[0].Endpoint != 1 || b.Targets[0].Cluster != clusters.IDOnOff {
		t.Fatalf("restored bindings %+v", b.Targets)
	}
	h2.dev.SendBound(h2.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOn, nil)
	h2.w.Advance(5 * time.Second)
	if !light2.On {
		t.Fatal("light not switched on over a new CASE session")
	}
}
