package mdns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

func TestNodeResolver(t *testing.T) {
	now := time.Unix(1000, 0)
	cfid := [8]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	provider := netip.MustParseAddr("fe80::1234")
	var res *NodeResolver
	var queries int
	// The provider's responder answers the resolver's queries.
	// It has a global address too, listed first: the link-local one wins.
	global := netip.MustParseAddr("2001:db8::1234")
	resp := New("provider", []netip.Addr{global, provider}, func(dst netip.AddrPort, b []byte) error {
		if res != nil {
			res.HandlePacket(now, netip.AddrPortFrom(provider, Port), b)
		}
		return nil
	})
	o := dnssd.Operational{CompressedFabricID: cfid, NodeID: 0x1B669, Port: 5550}
	resp.Advertise([]dnssd.Service{o.Service()})
	for resp.announceLeft > 0 { // finish announcing before the resolver listens
		resp.Poll(now)
		now = now.Add(5 * time.Second)
	}
	res = NewNodeResolver(func(dst netip.AddrPort, b []byte) error {
		if dst.Addr() == Group {
			queries++
			resp.HandlePacket(now, netip.AddrPortFrom(netip.MustParseAddr("fe80::99"), Port), b)
		}
		return nil
	}, func(netip.AddrPort) string { return "wlan0" })

	if _, ok := res.Resolve(now, cfid, 0x1B669); ok || queries != 1 {
		t.Fatalf("first lookup: ok=%v, %d queries", ok, queries)
	}
	a, ok := res.Resolve(now.Add(100*time.Millisecond), cfid, 0x1B669)
	if !ok || a.Addr().WithZone("") != provider || a.Addr().Zone() != "wlan0" || a.Port() != 5550 {
		t.Fatalf("resolved %v %v", a, ok)
	}
	// Another node: nothing known, a new query.
	if _, ok := res.Resolve(now.Add(200*time.Millisecond), cfid, 0x2); ok || queries != 2 {
		t.Fatalf("other node: ok=%v, %d queries", ok, queries)
	}
	// Idle, the resolver keeps nothing.
	res.HandlePacket(now.Add(time.Minute), netip.AddrPortFrom(provider, Port), nil)
	if len(res.q.records) != 0 {
		t.Fatalf("%d records kept while idle", len(res.q.records))
	}
}
