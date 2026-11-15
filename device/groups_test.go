package device_test

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const (
	testGroup  = 0x0101
	testKeySet = 0x0042
)

var testEpochKey = []byte("group epoch key!")

// write writes one attribute on s and returns the status.
func (h *harness) write(s *exchange.Session, p im.AttributePath, value func(w *tlv.Writer, tag tlv.Tag)) im.Status {
	h.t.Helper()
	var got []byte
	ex, err := h.ctl.M.NewExchange(s, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
		got = bytes.Clone(msg.Payload)
		ex.Close(now)
	}))
	if err != nil {
		h.t.Fatal(err)
	}
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpWriteRequest, im.EncodeWriteRequest(p, false, value))
	h.w.Advance(time.Second)
	res, err := im.DecodeWriteResponse(got)
	if err != nil || len(res) != 1 {
		h.t.Fatalf("write %+v: %+v %v", p, res, err)
	}
	return res[0].Status
}

// groupStatus returns the status field of a Groups command response.
func groupStatus(t *testing.T, res im.InvokeResult) im.Status {
	t.Helper()
	if res.Status != im.Success {
		return res.Status
	}
	st, _ := field(t, res.Fields, 0).Uint()
	return im.Status(st)
}

func (h *harness) addGroup(s *exchange.Session, ep uint16, group uint16, name string) im.Status {
	h.t.Helper()
	return groupStatus(h.t, h.invoke(s, im.CommandPath{Endpoint: ep, Cluster: clusters.IDGroups, Command: 0}, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), uint64(group))
		w.PutString(tlv.ContextTag(1), name)
	}))
}

func (h *harness) keySetWrite(s *exchange.Session, id uint16, key []byte) im.Status {
	h.t.Helper()
	return h.invoke(s, im.CommandPath{Endpoint: 0, Cluster: clusters.IDGroupKeyManagement, Command: 0}, func(w *tlv.Writer) {
		w.StartStruct(tlv.ContextTag(0))
		w.PutUint(tlv.ContextTag(0), uint64(id))
		w.PutUint(tlv.ContextTag(1), clusters.GroupKeyTrustFirst)
		w.PutBytes(tlv.ContextTag(2), key)
		w.PutUint(tlv.ContextTag(3), 1)
		w.PutNull(tlv.ContextTag(4))
		w.PutNull(tlv.ContextTag(5))
		w.PutNull(tlv.ContextTag(6))
		w.PutNull(tlv.ContextTag(7))
		w.EndContainer()
	}).Status
}

func (h *harness) mapGroup(s *exchange.Session, group, keySet uint16) im.Status {
	h.t.Helper()
	return h.write(s, im.AttributePath{Endpoint: 0, Cluster: clusters.IDGroupKeyManagement, Attribute: 0, ListAppend: true},
		func(w *tlv.Writer, tag tlv.Tag) {
			w.StartStruct(tag)
			w.PutUint(tlv.ContextTag(1), uint64(group))
			w.PutUint(tlv.ContextTag(2), uint64(keySet))
			w.EndContainer()
		})
}

// allowGroup appends an ACL entry granting priv to a group.
func (h *harness) allowGroup(s *exchange.Session, group uint16, priv im.Privilege) im.Status {
	h.t.Helper()
	return h.write(s, im.AttributePath{Endpoint: 0, Cluster: clusters.IDAccessControl, Attribute: 0, ListAppend: true},
		func(w *tlv.Writer, tag tlv.Tag) {
			w.StartStruct(tag)
			w.PutUint(tlv.ContextTag(1), uint64(priv))
			w.PutUint(tlv.ContextTag(2), uint64(exchange.AuthGroup))
			w.StartArray(tlv.ContextTag(3))
			w.PutUint(tlv.Anonymous, uint64(group))
			w.EndContainer()
			w.PutNull(tlv.ContextTag(4))
			w.EndContainer()
		})
}

// groupSender sends group commands as the controller would.
type groupSender struct {
	h       *harness
	key     exchange.GroupKey
	counter uint32
}

func (h *harness) groupSender(ctlF *fabric.Fabric, group uint16, epochKey []byte) *groupSender {
	keys, err := message.DeriveGroupKeys(epochKey, ctlF.CompressedFabricID)
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := message.NewCipher(keys.Encryption[:])
	if err != nil {
		h.t.Fatal(err)
	}
	return &groupSender{h: h, counter: 1000, key: exchange.GroupKey{
		GroupID: group, SessionID: keys.SessionID, Cipher: c, PrivacyKey: keys.Privacy,
	}}
}

func (g *groupSender) invoke(cluster, command uint32, fields func(w *tlv.Writer)) {
	g.h.t.Helper()
	g.counter++
	to := g.h.devN.Addr // the simulated network has no multicast
	err := g.h.ctl.M.SendGroup(to, &g.key, 0x1B669, g.counter, message.ProtocolInteractionModel,
		im.OpInvokeRequest, im.EncodeGroupInvokeRequest(cluster, command, fields))
	if err != nil {
		g.h.t.Fatal(err)
	}
	g.h.w.Advance(time.Second)
}

func TestGroupCommand(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	h.dev.Node.AddCluster(h.dev.Node.Endpoint(1), h.dev.NewGroups(nil))
	var joined []string
	h.dev.OnMulticast = func(addrs []netip.Addr) {
		joined = joined[:0]
		for _, a := range addrs {
			joined = append(joined, a.String())
		}
	}
	ctlF, caseS := h.commission()
	h.light.On = false
	g := h.groupSender(ctlF, testGroup, testEpochKey)
	on := func() bool {
		h.light.On = false
		g.invoke(clusters.IDOnOff, 1, nil)
		return h.light.On
	}

	// A group without membership, a mapped key or an ACL entry is ignored.
	if on() {
		t.Fatal("group command accepted before any setup")
	}
	if st := h.addGroup(caseS, 1, testGroup, "kitchen"); st != im.UnsupportedAccess {
		t.Fatalf("AddGroup without a key mapping: %#x", st)
	}
	if st := h.keySetWrite(caseS, testKeySet, testEpochKey); st != im.Success {
		t.Fatalf("KeySetWrite: %#x", st)
	}
	if st := h.mapGroup(caseS, testGroup, testKeySet); st != im.Success {
		t.Fatalf("group key map: %#x", st)
	}
	if st := h.addGroup(caseS, 1, testGroup, "kitchen"); st != im.Success {
		t.Fatalf("AddGroup: %#x", st)
	}
	want := exchange.GroupMulticastAddr(0xFAB, testGroup).String()
	if len(joined) != 1 || joined[0] != want {
		t.Fatalf("multicast addresses %v, want [%s]", joined, want)
	}
	if on() {
		t.Fatal("group command accepted without an ACL entry")
	}
	if st := h.allowGroup(caseS, testGroup, im.Administer); st != im.ConstraintError {
		t.Fatalf("group ACL entry with Administer: %#x", st)
	}
	if st := h.allowGroup(caseS, testGroup, im.Operate); st != im.Success {
		t.Fatalf("group ACL entry: %#x", st)
	}
	answered := 0
	h.w.Drop = func(p simnet.Packet) bool {
		if p.From == h.devN.Addr {
			answered++
		}
		return false
	}
	if !on() {
		t.Fatal("group On not applied")
	}
	h.w.Drop = nil
	if answered != 0 {
		t.Fatalf("device sent %d packets in reply to a group command", answered)
	}

	// A replayed counter is dropped; a key the device lacks is ignored.
	h.light.On = false
	g.counter--
	g.invoke(clusters.IDOnOff, 1, nil)
	if h.light.On {
		t.Fatal("replayed group message applied")
	}
	if h.groupSender(ctlF, testGroup, []byte("some other key!!")).invoke(clusters.IDOnOff, 1, nil); h.light.On {
		t.Fatal("group message with an unknown key applied")
	}

	// The group survives a restart.
	h2 := newHarnessStore(t, store)
	h2.dev.Node.AddCluster(h2.dev.Node.Endpoint(1), h2.dev.NewGroups(nil))
	if got := h2.dev.MulticastAddrs(); len(got) != 1 || got[0].String() != want {
		t.Fatalf("restored multicast addresses %v", got)
	}
	g.h = h2
	if g.invoke(clusters.IDOnOff, 1, nil); !h2.light.On {
		t.Fatal("group On not applied after restart")
	}

	// Removing the group from the endpoint stops it.
	s2 := h2.connect(ctlF)
	res := h2.invoke(s2, im.CommandPath{Endpoint: 1, Cluster: clusters.IDGroups, Command: 3}, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), testGroup)
	})
	if st := groupStatus(t, res); st != im.Success {
		t.Fatalf("RemoveGroup: %#x", st)
	}
	h2.light.On = false
	if g.invoke(clusters.IDOnOff, 1, nil); h2.light.On {
		t.Fatal("group On applied after RemoveGroup")
	}
	if len(h2.dev.MulticastAddrs()) != 0 {
		t.Fatal("still listening after RemoveGroup")
	}
}

func TestGroupWrite(t *testing.T) {
	h := newHarness(t)
	id := &clusters.Identify{}
	ep := h.dev.Node.Endpoint(1)
	h.dev.Node.AddCluster(ep, id)
	h.dev.Node.AddCluster(ep, h.dev.NewGroups(id))
	ctlF, caseS := h.commission()
	h.keySetWrite(caseS, testKeySet, testEpochKey)
	h.mapGroup(caseS, testGroup, testKeySet)
	h.addGroup(caseS, 1, testGroup, "")
	h.allowGroup(caseS, testGroup, im.Operate)
	g := h.groupSender(ctlF, testGroup, testEpochKey)

	send := func(p im.AttributePath, v uint64) {
		t.Helper()
		g.counter++
		err := h.ctl.M.SendGroup(h.devN.Addr, &g.key, 0x1B669, g.counter, message.ProtocolInteractionModel, im.OpWriteRequest,
			im.EncodeWriteRequest(p, false, func(w *tlv.Writer, tag tlv.Tag) { w.PutUint(tag, v) }))
		if err != nil {
			t.Fatal(err)
		}
		h.w.Advance(10 * time.Millisecond)
	}
	send(im.AttributePath{Endpoint: 1, Cluster: clusters.IDIdentify, Attribute: 0}, 30)
	if id.Identifying() {
		t.Fatal("group write naming an endpoint applied")
	}
	send(im.AttributePath{AnyEndpoint: true, Cluster: clusters.IDIdentify, Attribute: 0}, 30)
	if !id.Identifying() {
		t.Fatal("group write of IdentifyTime not applied")
	}
}

func TestGroupKeyManagementRules(t *testing.T) {
	h := newHarness(t)
	h.dev.Node.AddCluster(h.dev.Node.Endpoint(1), h.dev.NewGroups(nil))
	_, caseS := h.commission()
	gkm := func(cmd uint32, fields func(w *tlv.Writer)) im.InvokeResult {
		return h.invoke(caseS, im.CommandPath{Endpoint: 0, Cluster: clusters.IDGroupKeyManagement, Command: cmd}, fields)
	}
	keySet := func(id uint16, policy uint64, key []byte, start uint64) func(w *tlv.Writer) {
		return func(w *tlv.Writer) {
			w.StartStruct(tlv.ContextTag(0))
			w.PutUint(tlv.ContextTag(0), uint64(id))
			w.PutUint(tlv.ContextTag(1), policy)
			w.PutBytes(tlv.ContextTag(2), key)
			w.PutUint(tlv.ContextTag(3), start)
			w.EndContainer()
		}
	}
	for _, tc := range []struct {
		name   string
		fields func(w *tlv.Writer)
		want   im.Status
	}{
		{"IPK", keySet(0, 0, testEpochKey, 1), im.InvalidCommand},
		{"short key", keySet(1, 0, testEpochKey[:15], 1), im.ConstraintError},
		{"zero start", keySet(1, 0, testEpochKey, 0), im.InvalidCommand},
		{"cache and sync", keySet(1, 1, testEpochKey, 1), im.InvalidCommand},
		{"unknown policy", keySet(1, 7, testEpochKey, 1), im.ConstraintError},
		{"1", keySet(1, 0, testEpochKey, 1), im.Success},
		{"2", keySet(2, 0, testEpochKey, 1), im.Success},
		{"3", keySet(3, 0, testEpochKey, 1), im.Success},
		{"full (with the IPK)", keySet(4, 0, testEpochKey, 1), im.ResourceExhausted},
		{"replace", keySet(3, 0, testEpochKey, 5), im.Success},
	} {
		if st := gkm(0, tc.fields).Status; st != tc.want {
			t.Errorf("KeySetWrite %s: %#x, want %#x", tc.name, st, tc.want)
		}
	}

	// Epoch keys are never read back.
	res := gkm(1, func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 3) })
	r := field(t, res.Fields, 0)
	r.EnterContainer()
	for r.Next() == nil {
		switch tag := r.Tag(); {
		case tag.IsContext(2), tag.IsContext(4), tag.IsContext(6):
			if !r.IsNull() {
				t.Errorf("KeySetRead returned epoch key %v", tag)
			}
		case tag.IsContext(3):
			if v, _ := r.Uint(); v != 5 {
				t.Errorf("start time %d", v)
			}
		}
	}
	if st := gkm(1, func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 9) }).Status; st != im.NotFound {
		t.Errorf("KeySetRead of a missing set: %#x", st)
	}

	if st := h.mapGroup(caseS, 5, 0); st != im.ConstraintError {
		t.Errorf("mapping a group to the IPK: %#x", st)
	}
	if st := h.mapGroup(caseS, 5, 1); st != im.Success {
		t.Errorf("group key map: %#x", st)
	}
	if st := h.mapGroup(caseS, 5, 2); st != im.ConstraintError {
		t.Errorf("mapping a group twice: %#x", st)
	}
	if st := h.addGroup(caseS, 1, 0, ""); st != im.ConstraintError {
		t.Errorf("AddGroup 0: %#x", st)
	}
	if st := h.addGroup(caseS, 1, 5, "seventeen chars!!"); st != im.ConstraintError {
		t.Errorf("AddGroup with a long name: %#x", st)
	}
	if st := h.addGroup(caseS, 1, 5, "sixteen chars!!!"); st != im.Success {
		t.Errorf("AddGroup: %#x", st)
	}

	// Removing a key set removes its mappings.
	if st := gkm(3, func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 0) }).Status; st != im.InvalidCommand {
		t.Errorf("KeySetRemove of the IPK: %#x", st)
	}
	if st := gkm(3, func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 1) }).Status; st != im.Success {
		t.Errorf("KeySetRemove: %#x", st)
	}
	if len(h.dev.Groups.KeyMap) != 0 {
		t.Errorf("mappings left after KeySetRemove: %+v", h.dev.Groups.KeyMap)
	}
}
