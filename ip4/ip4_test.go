package ip4

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var (
	ourMAC  = [6]byte{0x30, 0xed, 0xa0, 0xc8, 0x87, 0x34}
	peerMAC = [6]byte{0xe4, 0xfc, 0xd9, 0x01, 0x02, 0x03}
	gwMAC   = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ourIP   = netip.MustParseAddr("192.168.2.50")
	peerIP  = netip.MustParseAddr("192.168.2.14")
	gwIP    = netip.MustParseAddr("192.168.2.1")
	subnet  = netip.MustParsePrefix("192.168.2.50/24")
)

type wire struct{ frames [][]byte }

func (w *wire) send(f []byte) error {
	w.frames = append(w.frames, bytes.Clone(f))
	return nil
}

func (w *wire) take() [][]byte {
	f := w.frames
	w.frames = nil
	return f
}

func newStack(t *testing.T) (*Stack, *wire) {
	w := &wire{}
	s := New(ourMAC, w.send)
	s.SetAddr(subnet, gwIP)
	w.take() // gratuitous ARP
	return s, w
}

// ipFrame builds an Ethernet/IPv4 frame with valid checksums.
func ipFrame(srcMAC, dstMAC [6]byte, src, dst netip.Addr, proto uint8, body []byte) []byte {
	f := make([]byte, ethHeaderLen+ipHeaderLen+len(body))
	copy(f[0:], dstMAC[:])
	copy(f[6:], srcMAC[:])
	binary.BigEndian.PutUint16(f[12:], etherTypeIP4)
	p := f[ethHeaderLen:]
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(ipHeaderLen+len(body)))
	p[8], p[9] = 64, proto
	a, d := src.As4(), dst.As4()
	copy(p[12:], a[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint16(p[10:], checksum(p[:ipHeaderLen]))
	copy(p[ipHeaderLen:], body)
	return f
}

func udpFrame(srcMAC, dstMAC [6]byte, src, dst netip.AddrPort, payload []byte) []byte {
	b := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(b[0:], src.Port())
	binary.BigEndian.PutUint16(b[2:], dst.Port())
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(b[6:], pseudoChecksum(src.Addr(), dst.Addr(), protoUDP, b))
	return ipFrame(srcMAC, dstMAC, src.Addr(), dst.Addr(), protoUDP, b)
}

func arpFrame(op uint16, sha [6]byte, spa netip.Addr, tha [6]byte, tpa netip.Addr, dstMAC [6]byte) []byte {
	f := make([]byte, ethHeaderLen+28)
	copy(f[0:], dstMAC[:])
	copy(f[6:], sha[:])
	binary.BigEndian.PutUint16(f[12:], etherTypeARP)
	b := f[ethHeaderLen:]
	binary.BigEndian.PutUint16(b[0:], 1)
	binary.BigEndian.PutUint16(b[2:], etherTypeIP4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:], op)
	a, t := spa.As4(), tpa.As4()
	copy(b[8:], sha[:])
	copy(b[14:], a[:])
	copy(b[18:], tha[:])
	copy(b[24:], t[:])
	return f
}

// parsed is a sent frame, checked for valid checksums.
type parsed struct {
	dstMAC   [6]byte
	typ      uint16
	src, dst netip.Addr
	proto    uint8
	ttl      uint8
	body     []byte // IP payload, or the ARP packet
}

func parse(t *testing.T, f []byte) parsed {
	t.Helper()
	p := parsed{dstMAC: [6]byte(f[0:6]), typ: binary.BigEndian.Uint16(f[12:])}
	if [6]byte(f[6:12]) != ourMAC {
		t.Fatal("wrong source MAC")
	}
	if p.typ == etherTypeARP {
		p.body = f[ethHeaderLen:]
		return p
	}
	ip := f[ethHeaderLen:]
	if checksum(ip[:ipHeaderLen]) != 0 {
		t.Fatal("bad IP header checksum")
	}
	if int(binary.BigEndian.Uint16(ip[2:])) != len(ip) {
		t.Fatal("bad total length")
	}
	p.ttl, p.proto = ip[8], ip[9]
	p.src = netip.AddrFrom4([4]byte(ip[12:16]))
	p.dst = netip.AddrFrom4([4]byte(ip[16:20]))
	p.body = ip[ipHeaderLen:]
	if p.proto == protoUDP && pseudoChecksum(p.src, p.dst, protoUDP, p.body) != 0 {
		t.Fatal("bad UDP checksum")
	}
	return p
}

func TestARPReply(t *testing.T) {
	s, w := newStack(t)
	s.HandleFrame(arpFrame(1, peerMAC, peerIP, [6]byte{}, ourIP, broadcastMAC))
	f := w.take()
	if len(f) != 1 {
		t.Fatalf("%d frames", len(f))
	}
	p := parse(t, f[0])
	if p.typ != etherTypeARP || p.dstMAC != peerMAC || binary.BigEndian.Uint16(p.body[6:]) != 2 ||
		[6]byte(p.body[8:14]) != ourMAC || netip.AddrFrom4([4]byte(p.body[24:28])) != peerIP {
		t.Fatalf("reply %x", f[0])
	}
	// Requests for other hosts are ignored.
	s.HandleFrame(arpFrame(1, peerMAC, peerIP, [6]byte{}, gwIP, broadcastMAC))
	if len(w.take()) != 0 {
		t.Fatal("answered for another host")
	}
}

func TestSendResolves(t *testing.T) {
	s, w := newStack(t)
	payload := []byte("hello matter")
	if err := s.SendUDP(5540, netip.AddrPortFrom(peerIP, 5541), payload); err != ErrNoNeighbor {
		t.Fatal(err)
	}
	f := w.take()
	if len(f) != 1 || parse(t, f[0]).typ != etherTypeARP || f[0][0] != 0xff {
		t.Fatal("no ARP request")
	}
	// No reply: the request is repeated from Poll.
	s.Poll(time.Unix(0, 0).Add(2 * time.Second))
	if len(w.take()) != 1 {
		t.Fatal("ARP not retried")
	}
	s.HandleFrame(arpFrame(2, peerMAC, peerIP, ourMAC, ourIP, ourMAC))
	f = w.take()
	if len(f) != 1 {
		t.Fatalf("%d frames after resolution", len(f))
	}
	p := parse(t, f[0])
	if p.dstMAC != peerMAC || p.dst != peerIP || p.src != ourIP || p.proto != protoUDP ||
		!bytes.Equal(p.body[udpHeaderLen:], payload) || binary.BigEndian.Uint16(p.body[2:]) != 5541 {
		t.Fatalf("datagram %+v", p)
	}
	// Now cached.
	s.SendUDP(5540, netip.AddrPortFrom(peerIP, 5541), payload)
	if f := w.take(); len(f) != 1 || parse(t, f[0]).typ != etherTypeIP4 {
		t.Fatal("not sent directly")
	}
}

func TestGatewayAndReceive(t *testing.T) {
	s, w := newStack(t)
	var got []string
	s.Listen(5540, func(src netip.AddrPort, dst netip.Addr, b []byte) {
		got = append(got, src.String()+">"+dst.String()+":"+string(b))
	})
	// Off-link traffic goes through the gateway.
	s.HandleFrame(arpFrame(2, gwMAC, gwIP, ourMAC, ourIP, ourMAC))
	s.SendUDP(5540, netip.MustParseAddrPort("8.8.8.8:53"), []byte("x"))
	if f := w.take(); len(f) != 1 || parse(t, f[0]).dstMAC != gwMAC || parse(t, f[0]).dst != netip.MustParseAddr("8.8.8.8") {
		t.Fatal("not routed via the gateway")
	}
	// Unicast in, learning the sender's MAC; the reply needs no ARP.
	s.HandleFrame(udpFrame(peerMAC, ourMAC, netip.AddrPortFrom(peerIP, 40000), netip.AddrPortFrom(ourIP, 5540), []byte("a")))
	s.SendUDP(5540, netip.AddrPortFrom(peerIP, 40000), []byte("r"))
	if f := w.take(); len(f) != 1 || parse(t, f[0]).dstMAC != peerMAC {
		t.Fatal("sender not learned")
	}
	// Multicast only once joined; corrupt checksums are dropped.
	mdns := netip.MustParseAddr("224.0.0.251")
	in := udpFrame(peerMAC, groupMAC(mdns), netip.AddrPortFrom(peerIP, 5353), netip.AddrPortFrom(mdns, 5540), []byte("m"))
	s.HandleFrame(in)
	s.Join(mdns)
	s.HandleFrame(in)
	bad := bytes.Clone(in)
	bad[len(bad)-1] ^= 1
	s.HandleFrame(bad)
	// Other hosts' unicast is ignored.
	s.HandleFrame(udpFrame(peerMAC, ourMAC, netip.AddrPortFrom(peerIP, 1), netip.AddrPortFrom(gwIP, 5540), []byte("z")))
	want := []string{"192.168.2.14:40000>192.168.2.50:a", "192.168.2.14:5353>224.0.0.251:m"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("received %q", got)
	}
}

func TestMulticastSendAndIGMP(t *testing.T) {
	s, w := newStack(t)
	mdns := netip.MustParseAddr("224.0.0.251")
	s.Join(mdns)
	f := w.take()
	if len(f) != 1 {
		t.Fatal("no IGMP report on join")
	}
	p := parse(t, f[0])
	if p.proto != protoIGMP || p.dst != mdns || p.ttl != 1 || p.body[0] != igmpV2Report || checksum(p.body) != 0 ||
		p.dstMAC != [6]byte{0x01, 0x00, 0x5e, 0, 0, 0xfb} {
		t.Fatalf("report %+v", p)
	}
	// A general query is answered.
	q := make([]byte, 8)
	q[0] = igmpQuery
	binary.BigEndian.PutUint16(q[2:], checksum(q))
	s.HandleFrame(ipFrame(gwMAC, groupMAC(allSystems), gwIP, allSystems, protoIGMP, q))
	if len(w.take()) != 1 {
		t.Fatal("query not answered")
	}
	s.SendUDP(5353, netip.AddrPortFrom(mdns, 5353), []byte("q"))
	f = w.take()
	if p := parse(t, f[0]); p.dstMAC != groupMAC(mdns) || p.ttl != 255 {
		t.Fatalf("mDNS send %+v", p)
	}
}

func TestEcho(t *testing.T) {
	s, w := newStack(t)
	e := []byte{icmpEchoRequest, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'}
	binary.BigEndian.PutUint16(e[2:], checksum(e))
	s.HandleFrame(ipFrame(peerMAC, ourMAC, peerIP, ourIP, protoICMP, e))
	f := w.take()
	if len(f) != 1 {
		t.Fatal("no echo reply")
	}
	p := parse(t, f[0])
	if p.proto != protoICMP || p.body[0] != icmpEchoReply || checksum(p.body) != 0 || !bytes.Equal(p.body[4:], e[4:]) {
		t.Fatalf("reply %+v", p)
	}
}

// fakeDHCP answers a client's messages like a home router.
type fakeDHCP struct {
	t      *testing.T
	server netip.Addr
	offer  netip.Addr
	nak    bool
}

func (d *fakeDHCP) reply(s *Stack, req []byte, typ uint8) []byte {
	m := make([]byte, dhcpHeaderLen+4)
	m[0], m[1], m[2] = 2, 1, 6
	copy(m[4:8], req[4:8])     // xid
	copy(m[28:44], req[28:44]) // chaddr
	a := d.offer.As4()
	if typ != dhcpNak {
		copy(m[16:20], a[:])
	}
	binary.BigEndian.PutUint32(m[dhcpHeaderLen:], dhcpMagic)
	sv := d.server.As4()
	m = append(m, optMessageType, 1, typ, optServerID, 4)
	m = append(m, sv[:]...)
	if typ != dhcpNak {
		m = append(m, optSubnetMask, 4, 255, 255, 255, 0, optRouter, 4)
		m = append(m, sv[:]...)
		m = append(m, optLeaseTime, 4, 0, 0, 0x02, 0x58) // 600 s
	}
	m = append(m, optEnd)
	return udpFrame(gwMAC, broadcastMAC, netip.AddrPortFrom(d.server, 67), netip.AddrPortFrom(Broadcast, 68), m)
}

// request returns the DHCP message in frame f and its type.
func dhcpMessage(t *testing.T, f []byte) (parsed, []byte, uint8, map[uint8][]byte) {
	t.Helper()
	p := parse(t, f)
	if p.proto != protoUDP || binary.BigEndian.Uint16(p.body[2:]) != 67 {
		t.Fatalf("not DHCP: %+v", p)
	}
	m := p.body[udpHeaderLen:]
	opts := map[uint8][]byte{}
	o := m[dhcpHeaderLen+4:]
	for len(o) > 1 && o[0] != optEnd {
		if o[0] == 0 {
			o = o[1:]
			continue
		}
		opts[o[0]] = o[2 : 2+o[1]]
		o = o[2+o[1]:]
	}
	return p, m, opts[optMessageType][0], opts
}

func TestDHCPLease(t *testing.T) {
	w := &wire{}
	s := New(ourMAC, w.send)
	var changes []netip.Prefix
	s.StartDHCP("30EDA0C88734", func(p netip.Prefix, gw netip.Addr) { changes = append(changes, p) })
	if err := s.SendUDP(1, netip.AddrPortFrom(peerIP, 1), nil); err != ErrNoAddress {
		t.Fatal("sent without an address")
	}
	srv := &fakeDHCP{t: t, server: gwIP, offer: ourIP}
	now := time.Unix(1000, 0)
	s.Poll(now)
	f := w.take()
	if len(f) != 1 {
		t.Fatalf("%d frames", len(f))
	}
	p, m, typ, opts := dhcpMessage(t, f[0])
	if typ != dhcpDiscover || p.dst != Broadcast || p.src != netip.IPv4Unspecified() || p.dstMAC != broadcastMAC ||
		m[10]&0x80 == 0 || string(opts[optHostName]) != "30EDA0C88734" || len(m) < 300 {
		t.Fatalf("discover %+v %x", p, m[:12])
	}
	// No offer: DISCOVER is retried with backoff.
	now = now.Add(5 * time.Second)
	s.Poll(now)
	if _, _, typ, _ = dhcpMessage(t, w.take()[0]); typ != dhcpDiscover {
		t.Fatal("discover not retried")
	}
	s.HandleFrame(srv.reply(s, m, dhcpOffer))
	_, m, typ, opts = dhcpMessage(t, w.take()[0])
	if typ != dhcpRequest || netip.AddrFrom4([4]byte(opts[optRequestedIP])) != ourIP ||
		netip.AddrFrom4([4]byte(opts[optServerID])) != gwIP {
		t.Fatalf("request %v", opts)
	}
	s.HandleFrame(srv.reply(s, m, dhcpAck))
	if s.Addr() != ourIP || s.Prefix() != netip.MustParsePrefix("192.168.2.0/24") || s.Gateway() != gwIP || !s.Bound() {
		t.Fatalf("bound to %v %v %v", s.Addr(), s.Prefix(), s.Gateway())
	}
	if len(changes) != 1 || changes[0] != netip.MustParsePrefix("192.168.2.50/24") {
		t.Fatalf("changes %v", changes)
	}
	if f := w.take(); len(f) != 1 || parse(t, f[0]).typ != etherTypeARP {
		t.Fatal("no gratuitous ARP")
	}

	// T1 (300 s): renew by unicast to the server, which needs its MAC.
	now = now.Add(300 * time.Second)
	s.Poll(now)
	f = w.take()
	if len(f) != 1 || parse(t, f[0]).typ != etherTypeARP {
		t.Fatal("expected an ARP for the server")
	}
	s.HandleFrame(arpFrame(2, gwMAC, gwIP, ourMAC, ourIP, ourMAC))
	p, m, typ, opts = dhcpMessage(t, w.take()[0])
	if typ != dhcpRequest || p.dst != gwIP || p.src != ourIP || netip.AddrFrom4([4]byte(m[12:16])) != ourIP ||
		opts[optRequestedIP] != nil {
		t.Fatalf("renewal %+v", p)
	}
	s.HandleFrame(srv.reply(s, m, dhcpAck))
	if len(changes) != 1 || !s.Bound() {
		t.Fatal("renewal changed the address")
	}

	// The server stops answering: rebinding by broadcast, then expiry.
	for i := 0; i < 40 && s.Addr().IsValid(); i++ {
		now = now.Add(30 * time.Second)
		s.Poll(now)
		w.take()
	}
	if s.Addr().IsValid() || len(changes) != 2 || changes[1].IsValid() {
		t.Fatalf("lease did not expire: %v %v", s.Addr(), changes)
	}

	// Back to DISCOVER; a NAK to the REQUEST restarts.
	s.Poll(now)
	_, m, typ, _ = dhcpMessage(t, w.take()[0])
	if typ != dhcpDiscover {
		t.Fatal("no new discover")
	}
	s.HandleFrame(srv.reply(s, m, dhcpOffer))
	_, m, _, _ = dhcpMessage(t, w.take()[0])
	s.HandleFrame(srv.reply(s, m, dhcpNak))
	s.Poll(now)
	if _, _, typ, _ = dhcpMessage(t, w.take()[0]); typ != dhcpDiscover || s.Bound() {
		t.Fatal("NAK did not restart")
	}
}

func FuzzHandleFrame(f *testing.F) {
	f.Add(arpFrame(1, peerMAC, peerIP, [6]byte{}, ourIP, broadcastMAC))
	f.Add(udpFrame(peerMAC, ourMAC, netip.AddrPortFrom(peerIP, 1), netip.AddrPortFrom(ourIP, 5540), []byte("x")))
	f.Add(udpFrame(gwMAC, broadcastMAC, netip.AddrPortFrom(gwIP, 67), netip.AddrPortFrom(Broadcast, 68), make([]byte, 300)))
	f.Fuzz(func(t *testing.T, frame []byte) {
		w := &wire{}
		s := New(ourMAC, w.send)
		s.SetAddr(subnet, gwIP)
		s.StartDHCP("h", nil)
		s.Listen(5540, func(netip.AddrPort, netip.Addr, []byte) {})
		s.Join(netip.MustParseAddr("224.0.0.251"))
		s.HandleFrame(frame)
		s.Poll(time.Unix(0, 0))
		s.HandleFrame(frame)
	})
}
