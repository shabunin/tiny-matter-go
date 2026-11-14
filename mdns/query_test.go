package mdns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

// lookup wires a querier to a responder: queries reach the responder from
// src, and its answers come back to the querier from the device address
// of the query's family.
type lookup struct {
	t      *testing.T
	now    time.Time
	q      *Querier
	r      *Responder
	src6   netip.AddrPort
	src4   netip.AddrPort
	dev6   netip.AddrPort
	dev4   netip.AddrPort
	queued []sent
}

func newLookup(t *testing.T) *lookup {
	l := &lookup{
		t:    t,
		now:  time.Unix(1000, 0),
		src6: netip.MustParseAddrPort("[fe80::1%eth0]:40000"),
		src4: netip.MustParseAddrPort("192.168.1.10:40000"),
		dev6: netip.MustParseAddrPort("[fe80::2%eth0]:5353"),
		dev4: netip.MustParseAddrPort("192.168.1.20:5353"),
	}
	l.q = NewQuerier(func(dst netip.AddrPort, b []byte) error {
		l.queued = append(l.queued, sent{dst, append([]byte(nil), b...)})
		return nil
	})
	devAddrs := []netip.Addr{netip.MustParseAddr("fe80::2"), netip.MustParseAddr("192.168.1.20")}
	l.r = New("DEVICE", devAddrs, func(dst netip.AddrPort, b []byte) error {
		from := l.dev6
		if dst.Addr().Is4() {
			from = l.dev4
		}
		l.q.HandlePacket(l.now, from, b)
		return nil
	})
	return l
}

// deliver hands the queued queries to the responder.
func (l *lookup) deliver() {
	for _, s := range l.queued {
		src := l.src6
		if s.dst.Addr().Is4() {
			src = l.src4
		}
		l.r.HandlePacket(l.now, src, s.msg)
	}
	l.queued = nil
}

func TestQuerierCommissionable(t *testing.T) {
	l := newLookup(t)
	c := dnssd.Commissionable{Instance: 0xABCD, Port: 5540, Discriminator: 3840, VendorID: 0xFFF1, ProductID: 0x8000, Mode: 1}
	l.r.Advertise([]dnssd.Service{c.Service()})

	if err := l.q.Query("_L3840._sub._matterc._udp.local", TypePTR); err != nil {
		t.Fatal(err)
	}
	if len(l.queued) != 2 || l.queued[0].dst.Addr() != Group || l.queued[1].dst.Addr() != Group4 {
		t.Fatalf("queries: %+v", l.queued)
	}
	l.deliver()
	names := l.q.Browse(l.now, "_L3840._sub._matterc._udp.local")
	if len(names) != 1 || names[0] != "000000000000ABCD._matterc._udp.local" {
		t.Fatalf("browse: %q", names)
	}
	// The PTR answer carries the SRV, TXT and addresses as additional
	// records.
	in, ok := l.q.Resolve(l.now, names[0])
	if !ok || in.Name != "000000000000ABCD" || in.Port != 5540 || in.Host != "DEVICE.local" {
		t.Fatalf("resolve: %+v %v", in, ok)
	}
	if d, _ := in.TXTValue("D"); d != "3840" {
		t.Fatalf("TXT %q", in.TXT)
	}
	if len(in.Addrs) != 2 || in.Addrs[0] != netip.MustParseAddr("fe80::2%eth0") || in.Addrs[1] != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("addresses %v", in.Addrs)
	}
	// Other discriminators find nothing.
	if err := l.q.Query("_L3841._sub._matterc._udp.local", TypePTR); err != nil {
		t.Fatal(err)
	}
	l.deliver()
	if names := l.q.Browse(l.now, "_L3841._sub._matterc._udp.local"); len(names) != 0 {
		t.Fatalf("browse 3841: %q", names)
	}
}

func TestQuerierOperationalAndExpiry(t *testing.T) {
	l := newLookup(t)
	o := dnssd.Operational{CompressedFabricID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, NodeID: 0x2A, Port: 5540}
	l.r.Advertise([]dnssd.Service{o.Service()})
	name := "0102030405060708-000000000000002A._matter._tcp.local"
	if err := l.q.Query(name, TypeSRV, TypeTXT); err != nil {
		t.Fatal(err)
	}
	l.deliver()
	in, ok := l.q.Resolve(l.now, name)
	if !ok || in.Port != 5540 || len(in.Addrs) != 2 {
		t.Fatalf("resolve: %+v %v", in, ok)
	}
	// Names are case-insensitive.
	if _, ok := l.q.Resolve(l.now, "0102030405060708-000000000000002a._MATTER._tcp.local"); !ok {
		t.Fatal("case-sensitive lookup")
	}
	// Legacy unicast answers live 10 s.
	if _, ok := l.q.Resolve(l.now.Add(11*time.Second), name); ok {
		t.Fatal("record outlived its TTL")
	}
}

func TestQuerierGoodbye(t *testing.T) {
	l := newLookup(t)
	c := dnssd.Commissionable{Instance: 0x1234, Port: 5540, Discriminator: 3840, Mode: 1}
	l.r.Advertise([]dnssd.Service{c.Service()})
	l.q.Query("_matterc._udp.local", TypePTR)
	l.deliver()
	if names := l.q.Browse(l.now, "_matterc._udp.local"); len(names) != 1 {
		t.Fatalf("browse: %q", names)
	}
	// Withdrawing the service sends goodbyes (TTL 0), which the querier
	// hears on the group.
	l.r.Advertise(nil)
	for i := 0; i < 5; i++ {
		l.now = l.now.Add(time.Second)
		l.r.Poll(l.now)
	}
	if names := l.q.Browse(l.now, "_matterc._udp.local"); len(names) != 0 {
		t.Fatalf("after goodbye: %q", names)
	}
}

func TestQuerierZoneForIPv4(t *testing.T) {
	l := newLookup(t)
	l.q.Zone = func(src netip.AddrPort) string { return "wlan0" }
	c := dnssd.Commissionable{Instance: 0x1, Port: 5540, Discriminator: 3840, Mode: 1}
	l.r.Advertise([]dnssd.Service{c.Service()})
	l.q.Query("_matterc._udp.local", TypePTR)
	// Only the IPv4 query reaches the device.
	l.queued = l.queued[1:]
	l.deliver()
	in, ok := l.q.Resolve(l.now, "0000000000000001._matterc._udp.local")
	if !ok || len(in.Addrs) != 2 || in.Addrs[0].Zone() != "wlan0" {
		t.Fatalf("%+v", in)
	}
}

func FuzzQuerier(f *testing.F) {
	l := newLookup(&testing.T{})
	c := dnssd.Commissionable{Instance: 0xABCD, Port: 5540, Discriminator: 3840, Mode: 1, DeviceName: "x"}
	var resp []byte
	l.r = New("DEVICE", []netip.Addr{netip.MustParseAddr("fe80::2")}, func(dst netip.AddrPort, b []byte) error {
		resp = append([]byte(nil), b...)
		return nil
	})
	l.r.Advertise([]dnssd.Service{c.Service()})
	l.q.Query("_matterc._udp.local", TypePTR)
	l.deliver()
	f.Add(resp)
	f.Fuzz(func(t *testing.T, b []byte) {
		q := NewQuerier(func(netip.AddrPort, []byte) error { return nil })
		now := time.Unix(1, 0)
		q.HandlePacket(now, netip.MustParseAddrPort("[fe80::2%eth0]:5353"), b)
		for _, n := range q.Browse(now, "_matterc._udp.local") {
			q.Resolve(now, n)
		}
	})
}
