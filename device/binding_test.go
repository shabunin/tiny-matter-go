package device_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
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

// groupLight makes the controller's node a light on endpoint 1 that is a
// member of testGroup, with its key (as fabric index 1).
func groupLight(t *testing.T, h *harness, ctlF *fabric.Fabric) *clusters.OnOff {
	keys, err := message.DeriveGroupKeys(testEpochKey, ctlF.CompressedFabricID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := message.NewCipher(keys.Encryption[:])
	if err != nil {
		t.Fatal(err)
	}
	k := &exchange.GroupKey{FabricIndex: 1, GroupID: testGroup, SessionID: keys.SessionID, Cipher: c, PrivacyKey: keys.Privacy}
	h.ctl.M.SetGroupKeys(func(sid uint16, yield func(*exchange.GroupKey) bool) {
		if sid == k.SessionID {
			yield(k)
		}
	})
	light := &clusters.OnOff{}
	n := im.NewNode(1)
	n.AddCluster(n.AddEndpoint(1), light)
	srv := im.NewServer(h.ctl.M, n)
	srv.GroupEndpoints = func(fabricIndex uint8, group uint16) []uint16 {
		if group == testGroup {
			return []uint16{1}
		}
		return nil
	}
	return light
}

func TestGroupBinding(t *testing.T) {
	store := &storage.Memory{}
	h := bindingHarness(t, store)
	ctlF, s := h.commission()
	light := groupLight(t, h, ctlF)
	path := im.AttributePath{Endpoint: sensorEndpoint, Cluster: clusters.IDBinding, Attribute: 0}
	if st := h.write(s, path, bindingList(func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(2), testGroup)
		w.PutUint(tlv.ContextTag(4), clusters.IDOnOff)
	})); st != im.Success {
		t.Fatalf("write binding: %#x", st)
	}

	// Without the group's key the command is not sent.
	if n := h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOn, nil); n != 0 {
		t.Fatalf("On sent to %d targets without a group key", n)
	}
	// The sender needs the key set and its mapping, not membership.
	if st := h.keySetWrite(s, testKeySet, testEpochKey); st != im.Success {
		t.Fatalf("KeySetWrite: %#x", st)
	}
	if st := h.mapGroup(s, testGroup, testKeySet); st != im.Success {
		t.Fatalf("group key map: %#x", st)
	}

	var sent []simnet.Packet
	h.w.Drop = func(p simnet.Packet) bool {
		if p.From == h.devN.Addr {
			sent = append(sent, p)
		}
		return false
	}
	if n := h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOn, nil); n != 1 {
		t.Fatalf("On sent to %d targets", n)
	}
	h.w.Advance(time.Second)
	if !light.On {
		t.Fatal("group On not applied")
	}
	want := netip.AddrPortFrom(exchange.GroupMulticastAddr(0xFAB, testGroup), 5540)
	if len(sent) != 1 || sent[0].To != want {
		t.Fatalf("sent %d packets, to %v; want one to %v", len(sent), sent[0].To, want)
	}
	h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOff, nil)
	h.w.Advance(time.Second)
	if light.On {
		t.Fatal("group Off not applied")
	}
	if len(sent) != 2 {
		t.Fatalf("%d packets sent for two group commands (nothing answers them)", len(sent))
	}

	// After a restart the group counter goes on from where it was saved:
	// the receiver, which trusts the first counter it saw, takes the new
	// device's message.
	h2 := bindingHarness(t, store)
	var after []simnet.Packet
	h2.w.Drop = func(p simnet.Packet) bool {
		after = append(after, p)
		return true
	}
	h2.dev.SendBound(h2.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOn, nil)
	h2.w.Advance(time.Second)
	if len(after) != 1 {
		t.Fatalf("restarted device sent %d packets", len(after))
	}
	h.ctl.M.HandlePacket(h.w.Now, after[0].From, after[0].Data)
	h.w.Advance(time.Second)
	if !light.On {
		t.Fatal("group On from the restarted device dropped: its counter went back")
	}
	// A replay is not.
	light.On = false
	h.ctl.M.HandlePacket(h.w.Now, after[0].From, after[0].Data)
	h.w.Advance(time.Second)
	if light.On {
		t.Fatal("replayed group message applied")
	}
}
