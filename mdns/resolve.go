package mdns

import (
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

// NodeResolver finds the operational address of Matter nodes (spec
// 4.3.2.1) for a node that opens sessions itself, such as an OTA requestor
// reaching its provider. It keeps memory small: responses are recorded
// only while a lookup is in progress, and only for one node at a time.
type NodeResolver struct {
	// Usable, if set, says which addresses the node can reach (for
	// example, only link-local IPv6 and IPv4 on its subnet).
	Usable func(netip.Addr) bool

	q      *Querier
	name   string    // the instance being looked up
	active time.Time // responses are recorded until then
	last   time.Time // the last query sent
}

// resolveWindow is how long responses are recorded after Resolve.
const resolveWindow = 10 * time.Second

// NewNodeResolver returns a resolver that sends queries with send (from
// the mDNS port, so answers arrive at the mDNS group too). zone, if set,
// names the interface of link-local IPv6 addresses (which the network
// layer may leave unzoned).
func NewNodeResolver(send func(dst netip.AddrPort, b []byte) error, zone func(src netip.AddrPort) string) *NodeResolver {
	q := NewQuerier(send)
	q.Zone = zone
	return &NodeResolver{q: q}
}

// HandlePacket takes an mDNS packet received on the mDNS port.
func (r *NodeResolver) HandlePacket(now time.Time, src netip.AddrPort, payload []byte) {
	if now.Before(r.active) {
		r.q.HandlePacket(now, src, payload)
	} else if len(r.q.records) > 0 {
		r.q.records = nil
	}
}

// Resolve looks up a node on a fabric. It returns the node's address once
// a response has given it; until then it sends a query (at most once a
// second) and reports false, so call it again later.
func (r *NodeResolver) Resolve(now time.Time, compressedFabricID [8]byte, nodeID uint64) (netip.AddrPort, bool) {
	o := dnssd.Operational{CompressedFabricID: compressedFabricID, NodeID: nodeID}
	name := instanceName(o.Service())
	if name != r.name {
		r.name, r.q.records, r.last = name, nil, time.Time{}
	}
	r.active = now.Add(resolveWindow)
	in, ok := r.q.Resolve(now, name)
	if a, found := r.pick(in.Addrs); ok && found {
		return netip.AddrPortFrom(a, in.Port), true
	}
	if now.Sub(r.last) >= time.Second {
		r.last = now
		if ok {
			r.q.Query(in.Host, TypeAAAA, TypeA)
		} else {
			r.q.Query(name, TypeSRV, TypeTXT)
		}
	}
	return netip.AddrPort{}, false
}

// pick chooses the address a small node most likely reaches: a usable
// link-local IPv6 address (on the link, no router needed), then IPv4, then
// any other.
func (r *NodeResolver) pick(addrs []netip.Addr) (netip.Addr, bool) {
	rank := func(a netip.Addr) int {
		switch {
		case a.Is6() && a.IsLinkLocalUnicast():
			return 0
		case a.Is4():
			return 1
		}
		return 2
	}
	var best netip.Addr
	for _, a := range addrs {
		if r.Usable != nil && !r.Usable(a) {
			continue
		}
		if !best.IsValid() || rank(a) < rank(best) {
			best = a
		}
	}
	return best, best.IsValid()
}
