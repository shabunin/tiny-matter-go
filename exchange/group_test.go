package exchange

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/message"
)

func testGroupKey(t *testing.T, fabric uint8, group uint16, epoch byte) *GroupKey {
	t.Helper()
	keys, err := message.DeriveGroupKeys(bytes.Repeat([]byte{epoch}, 16), [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	c, err := message.NewCipher(keys.Encryption[:])
	if err != nil {
		t.Fatal(err)
	}
	return &GroupKey{FabricIndex: fabric, GroupID: group, SessionID: keys.SessionID, Cipher: c, PrivacyKey: keys.Privacy}
}

func groupKeys(keys ...*GroupKey) GroupKeyFunc {
	return func(sessionID uint16, yield func(k *GroupKey) bool) {
		for _, k := range keys {
			if k.SessionID == sessionID && !yield(k) {
				return
			}
		}
	}
}

func TestGroupMessage(t *testing.T) {
	w := newWorld(t)
	ctl, dev := w.node(1), w.node(2)
	group := netip.AddrPortFrom(netip.MustParseAddr("ff35:40:fd00::100:1"), 2)
	w.nodes = append(w.nodes, &node{m: dev.m, addr: group}) // dev listens on the group address

	key := testGroupKey(t, 1, 0x0101, 0xAA)
	other := testGroupKey(t, 1, 0x0102, 0xBB) // a group dev is not in
	dev.m.SetGroupKeys(groupKeys(key))

	var got []*Session
	r := &recorder{onMsg: func(now time.Time, ex *Exchange, msg Message) {
		got = append(got, ex.Session())
		if err := ex.Send(now, msg.ProtocolID, 9, nil); err != ErrGroupSession {
			t.Errorf("answering a group message: %v, want ErrGroupSession", err)
		}
		ex.Close(now)
	}}
	dev.m.Register(0x7777, func(ex *Exchange) Delegate { return r })

	send := func(k *GroupKey, counter uint32) {
		t.Helper()
		if err := ctl.m.SendGroup(group, k, 0x1122, counter, 0x7777, 1, []byte("hi")); err != nil {
			t.Fatal(err)
		}
		w.deliver()
	}
	send(key, 100)
	if len(r.msgs) != 1 || string(r.msgs[0].Payload) != "hi" {
		t.Fatalf("delivered %v", r.msgs)
	}
	s := got[0]
	if !s.IsGroup() || s.AuthMode != AuthGroup || s.FabricIndex != 1 || s.GroupID != 0x0101 || s.PeerNodeID() != 0x1122 {
		t.Fatalf("group session %+v", s)
	}
	if w.net.sent != 1 {
		t.Fatalf("%d packets sent, want just the group message (no acknowledgement)", w.net.sent)
	}
	if len(dev.m.exchanges) != 0 || len(dev.m.sessions) != 0 {
		t.Fatalf("group message left %d exchanges, %d sessions", len(dev.m.exchanges), len(dev.m.sessions))
	}

	send(key, 100) // replay
	send(key, 99)  // older, inside the window: not seen, accepted
	send(key, 60)  // too old
	send(other, 101)
	send(key, 101)
	if len(r.msgs) != 3 {
		t.Fatalf("%d messages delivered, want 3 (replay, too old and foreign group dropped)", len(r.msgs))
	}

	// Each sender has its own counters; forgetting a fabric's senders
	// trusts their next counter again.
	if err := ctl.m.SendGroup(group, key, 0x3344, 5, 0x7777, 1, nil); err != nil {
		t.Fatal(err)
	}
	w.deliver()
	if len(r.msgs) != 4 {
		t.Fatal("a second sender's first message was dropped")
	}
	dev.m.ForgetGroupPeers(1)
	send(key, 50)
	if len(r.msgs) != 5 {
		t.Fatal("a counter after ForgetGroupPeers was dropped")
	}

	dev.m.SetGroupKeys(nil)
	send(key, 200)
	if len(r.msgs) != 5 {
		t.Fatal("delivered a group message without group keys")
	}
}

func TestGroupMessageCorrupted(t *testing.T) {
	w := newWorld(t)
	ctl, dev := w.node(1), w.node(2)
	key := testGroupKey(t, 1, 7, 0x11)
	dev.m.SetGroupKeys(groupKeys(key))
	r := &recorder{}
	dev.m.Register(0x7777, func(ex *Exchange) Delegate { return r })
	w.net.drop = func(p packet) bool {
		p.data[len(p.data)-1] ^= 1
		dev.m.HandlePacket(w.now, p.from, p.data)
		return true
	}
	if err := ctl.m.SendGroup(dev.addr, key, 2, 1, 0x7777, 1, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.msgs) != 0 {
		t.Fatal("delivered a message with a bad MIC")
	}
}

func TestGroupMulticastAddr(t *testing.T) {
	got := GroupMulticastAddr(0x1122334455667788, 0x0102)
	if want := netip.MustParseAddr("ff35:40:fd11:2233:4455:6677:8800:102"); got != want {
		t.Fatalf("%v, want %v", got, want)
	}
}
