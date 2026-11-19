package ip6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// pair connects two stacks through a frame queue.
type pair struct {
	a, b  *Stack
	queue []struct {
		to    *Stack
		frame []byte
	}
	sent int
}

func newPair() *pair {
	p := &pair{}
	p.a = New([6]byte{0x02, 0, 0, 0, 0, 0xaa}, func(f []byte) error { p.enqueue(p.b, f); return nil })
	p.b = New([6]byte{0x30, 0xed, 0xa0, 0xc8, 0x87, 0x34}, func(f []byte) error { p.enqueue(p.a, f); return nil })
	return p
}

func (p *pair) enqueue(to *Stack, f []byte) {
	p.sent++
	p.queue = append(p.queue, struct {
		to    *Stack
		frame []byte
	}{to, append([]byte(nil), f...)})
}

func (p *pair) run() {
	for len(p.queue) > 0 {
		q := p.queue[0]
		p.queue = p.queue[1:]
		q.to.HandleFrame(q.frame)
	}
}

func TestLinkLocal(t *testing.T) {
	got := LinkLocal([6]byte{0x30, 0xed, 0xa0, 0xc8, 0x87, 0x34})
	if want := netip.MustParseAddr("fe80::32ed:a0ff:fec8:8734"); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := solicitedNode(got); got != netip.MustParseAddr("ff02::1:ffc8:8734") {
		t.Fatalf("solicited-node %v", got)
	}
}

func TestUDPWithNeighborDiscovery(t *testing.T) {
	p := newPair()
	var got []byte
	var from netip.AddrPort
	p.b.Listen(5540, func(src netip.AddrPort, dst netip.Addr, b []byte) {
		got, from = append([]byte(nil), b...), src
		if dst != p.b.Addr() {
			t.Errorf("dst %v", dst)
		}
	})
	err := p.a.SendUDP(5550, netip.AddrPortFrom(p.b.Addr(), 5540), []byte("hello matter"))
	if err != ErrNoNeighbor {
		t.Fatalf("first send: %v", err)
	}
	p.run() // NS -> NA -> pending datagram
	if string(got) != "hello matter" || from != netip.AddrPortFrom(p.a.Addr(), 5550) {
		t.Fatalf("got %q from %v", got, from)
	}
	// The reply needs no resolution: b learned a's MAC from the NS.
	var reply []byte
	p.a.Listen(5550, func(src netip.AddrPort, dst netip.Addr, b []byte) { reply = append([]byte(nil), b...) })
	if err := p.b.SendUDP(5540, from, []byte("ack")); err != nil {
		t.Fatal(err)
	}
	p.run()
	if string(reply) != "ack" {
		t.Fatalf("reply %q", reply)
	}
}

func TestCorruptChecksumDropped(t *testing.T) {
	p := newPair()
	n := 0
	p.b.Listen(9, func(netip.AddrPort, netip.Addr, []byte) { n++ })
	p.a.learn(p.b.Addr(), p.b.MAC())
	p.a.SendUDP(9, netip.AddrPortFrom(p.b.Addr(), 9), []byte("x"))
	f := p.queue[0].frame
	f[len(f)-1] ^= 1
	p.run()
	if n != 0 {
		t.Fatal("corrupt datagram delivered")
	}
}

func TestMulticastJoinAndEcho(t *testing.T) {
	p := newPair()
	mdns := netip.MustParseAddr("ff02::fb")
	if err := p.b.Join(mdns); err != nil {
		t.Fatal(err)
	}
	p.queue = nil // MLD report
	n := 0
	p.b.Listen(5353, func(src netip.AddrPort, dst netip.Addr, b []byte) {
		if dst == mdns {
			n++
		}
	})
	p.a.SendUDP(5353, netip.AddrPortFrom(mdns, 5353), []byte("q"))
	if d := p.queue[0].frame[:6]; !bytes.Equal(d, []byte{0x33, 0x33, 0, 0, 0, 0xfb}) {
		t.Fatalf("multicast MAC % x", d)
	}
	p.run()
	if n != 1 {
		t.Fatal("multicast datagram not delivered")
	}
	// Not joined on a: ignored.
	p.b.SendUDP(5353, netip.AddrPortFrom(mdns, 5353), []byte("q"))
	p.a.Listen(5353, func(netip.AddrPort, netip.Addr, []byte) { t.Fatal("delivered to non-member") })
	p.run()

	// Echo request a -> b gets a reply with a valid checksum.
	p.queue = nil
	p.a.learn(p.b.Addr(), p.b.MAC())
	req := p.a.ipPacket(p.b.Addr(), protoICMPv6, 12, 64)
	copy(req, []byte{icmpEchoRequest, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'})
	p.a.finishICMP(p.b.Addr(), req)
	p.a.output(p.b.Addr(), len(req))
	p.b.HandleFrame(p.queue[0].frame)
	if len(p.queue) != 2 {
		t.Fatalf("no echo reply (%d frames)", len(p.queue))
	}
	icmp := p.queue[1].frame[ethHeaderLen+ipHeaderLen:]
	if icmp[0] != icmpEchoReply || string(icmp[8:]) != "ping" || checksum(p.b.Addr(), p.a.Addr(), protoICMPv6, icmp) != 0 {
		t.Fatalf("bad echo reply % x", icmp)
	}

	// An oversized Echo Request (> MTU) is dropped instead of panicking.
	p.queue = nil
	bodyLen := MTU - ipHeaderLen + 1
	big := make([]byte, ethHeaderLen+ipHeaderLen+bodyLen)
	bMAC, aMAC := p.b.MAC(), p.a.MAC()
	copy(big[0:6], bMAC[:])
	copy(big[6:12], aMAC[:])
	binary.BigEndian.PutUint16(big[12:], etherTypeIP6)
	ip := big[ethHeaderLen:]
	ip[0], ip[6], ip[7] = 0x60, protoICMPv6, 64
	binary.BigEndian.PutUint16(ip[4:], uint16(bodyLen))
	src, dst := p.a.Addr().As16(), p.b.Addr().As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	icmpReq := ip[ipHeaderLen:]
	icmpReq[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(icmpReq[2:], checksum(p.a.Addr(), p.b.Addr(), protoICMPv6, icmpReq))
	p.b.HandleFrame(big)
	if len(p.queue) != 0 {
		t.Fatalf("oversized echo generated %d frames", len(p.queue))
	}
}

func TestMLDReport(t *testing.T) {
	var frames [][]byte
	s := New([6]byte{2, 0, 0, 0, 0, 1}, func(f []byte) error { frames = append(frames, append([]byte(nil), f...)); return nil })
	s.Join(netip.MustParseAddr("ff02::fb"))
	if len(frames) != 1 {
		t.Fatalf("%d frames", len(frames))
	}
	f := frames[0]
	ip := f[ethHeaderLen:]
	if ip[6] != protoHopByHop || ip[7] != 1 || !bytes.Equal(f[:6], []byte{0x33, 0x33, 0, 0, 0, 0x16}) {
		t.Fatalf("bad MLD header % x", f[:ethHeaderLen+ipHeaderLen])
	}
	icmp := ip[ipHeaderLen+8:]
	if icmp[0] != icmpMLDv2Report || binary.BigEndian.Uint16(icmp[6:]) != 2 {
		t.Fatalf("bad report % x", icmp)
	}
	if checksum(s.Addr(), mldRouters, protoICMPv6, icmp) != 0 {
		t.Fatal("bad checksum")
	}

	// Leaving reports a change to include mode for just that group, and
	// stops delivery.
	g := netip.MustParseAddr("ff35:40:fd00::100:1")
	s.Join(g)
	if !s.accepts(g) {
		t.Fatal("joined group not accepted")
	}
	frames = nil
	s.Leave(g)
	s.Leave(allNodes) // never left
	if len(frames) != 1 || s.accepts(g) || !s.accepts(allNodes) {
		t.Fatalf("leave: %d frames", len(frames))
	}
	icmp = frames[0][ethHeaderLen+ipHeaderLen+8:]
	if binary.BigEndian.Uint16(icmp[6:]) != 1 || icmp[8] != mldChangeToInclude || netip.AddrFrom16([16]byte(icmp[12:28])) != g {
		t.Fatalf("leave report % x", icmp)
	}
}

// TestChecksumVerifies checks that a buffer carrying its own checksum sums
// to zero, as receivers verify it.
func TestChecksumVerifies(t *testing.T) {
	src, dst := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("ff02::1:ff00:2")
	b := []byte{135, 0, 0, 0, 0, 0, 0, 0, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	c := checksum(src, dst, protoICMPv6, b)
	binary.BigEndian.PutUint16(b[2:], c)
	if checksum(src, dst, protoICMPv6, b) != 0 {
		t.Fatal("checksum does not verify")
	}
}

// raPrefix describes one Prefix Information option for buildRA.
type raPrefix struct {
	prefix      netip.Prefix
	flags       uint8
	valid, pref uint32
}

// buildRA constructs a complete Ethernet + IPv6 + ICMPv6 Router Advertisement frame.
func buildRA(routerMAC [6]byte, routerIP netip.Addr, hopLimit uint8, curHop uint8, routerLife uint16, includeSLLAO bool, prefixes ...raPrefix) []byte {
	var icmp []byte
	var hdr [16]byte
	hdr[0] = icmpRA
	hdr[4] = curHop
	binary.BigEndian.PutUint16(hdr[6:], routerLife)
	icmp = append(icmp, hdr[:]...)
	if includeSLLAO {
		var opt [8]byte
		opt[0], opt[1] = optSourceLLAddr, 1
		copy(opt[2:8], routerMAC[:])
		icmp = append(icmp, opt[:]...)
	}
	for _, p := range prefixes {
		var opt [32]byte
		opt[0], opt[1] = optPrefixInfo, 4
		opt[2] = uint8(p.prefix.Bits())
		opt[3] = p.flags
		binary.BigEndian.PutUint32(opt[4:], p.valid)
		binary.BigEndian.PutUint32(opt[8:], p.pref)
		a := p.prefix.Addr().As16()
		copy(opt[16:32], a[:])
		icmp = append(icmp, opt[:]...)
	}
	dst := allNodes
	binary.BigEndian.PutUint16(icmp[2:], checksum(routerIP, dst, protoICMPv6, icmp))

	frame := make([]byte, ethHeaderLen+ipHeaderLen+len(icmp))
	dmac := multicastMAC(dst)
	copy(frame[0:6], dmac[:])
	copy(frame[6:12], routerMAC[:])
	binary.BigEndian.PutUint16(frame[12:], etherTypeIP6)
	ip := frame[ethHeaderLen:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(icmp)))
	ip[6], ip[7] = protoICMPv6, hopLimit
	s16, d16 := routerIP.As16(), dst.As16()
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])
	copy(ip[ipHeaderLen:], icmp)
	return frame
}

func TestSLAACRouterSolicitationAndRA(t *testing.T) {
	var frames [][]byte
	mac := [6]byte{0x30, 0xed, 0xa0, 0xc8, 0x87, 0x34}
	s := New(mac, func(f []byte) error {
		frames = append(frames, append([]byte(nil), f...))
		return nil
	})
	changes := 0
	s.StartSLAAC(func() { changes++ })

	now := time.Unix(1000, 0)
	next := s.Poll(now)
	if len(frames) != 1 {
		t.Fatalf("expected 1 RS on first Poll, got %d", len(frames))
	}
	rs := frames[0]
	if !bytes.Equal(rs[:6], []byte{0x33, 0x33, 0, 0, 0, 2}) || rs[ethHeaderLen+7] != ndpHopLimit {
		t.Fatalf("bad RS Ethernet/IPv6 header: % x", rs[:ethHeaderLen+ipHeaderLen])
	}
	icmp := rs[ethHeaderLen+ipHeaderLen:]
	if icmp[0] != icmpRS || icmp[8] != optSourceLLAddr || !bytes.Equal(icmp[10:16], mac[:]) || checksum(s.Addr(), allRouters, protoICMPv6, icmp) != 0 {
		t.Fatalf("bad RS ICMPv6: % x", icmp)
	}
	if !next.Equal(now.Add(rsInterval)) {
		t.Fatalf("next RS at %v, want %v", next, now.Add(rsInterval))
	}

	// Second RS fires after rsInterval.
	now = now.Add(rsInterval)
	s.Poll(now)
	if len(frames) != 2 {
		t.Fatalf("expected 2 RS frames, got %d", len(frames))
	}

	routerMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	routerIP := LinkLocal(routerMAC)

	// Invalid RAs must be ignored (bad hop limit, non-link-local src, /48, pref > valid, link-local PIO).
	s.HandleFrame(buildRA(routerMAC, routerIP, 64, 64, 1800, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800}))
	s.HandleFrame(buildRA(routerMAC, netip.MustParseAddr("2001:db8:1::1"), ndpHopLimit, 64, 1800, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800}))
	s.HandleFrame(buildRA(routerMAC, routerIP, ndpHopLimit, 64, 0, true,
		raPrefix{netip.MustParsePrefix("2001:db8::/48"), pioFlagOnLink | pioFlagAuto, 3600, 1800},
		raPrefix{netip.MustParsePrefix("2001:db8:2::/64"), pioFlagOnLink | pioFlagAuto, 100, 200},
		raPrefix{netip.MustParsePrefix("fe80::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800}))
	if s.HasGlobal() || s.Router().IsValid() || changes != 0 {
		t.Fatalf("invalid RAs accepted: global=%v router=%v changes=%d", s.HasGlobal(), s.Router(), changes)
	}

	// Valid RA with both a global /64 and a ULA /64 stops further RS bursts.
	s.HandleFrame(buildRA(routerMAC, routerIP, ndpHopLimit, 64, 1800, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800},
		raPrefix{netip.MustParsePrefix("fd12:3456:789a::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800}))
	if changes != 1 || !s.HasGlobal() || s.Router() != routerIP {
		t.Fatalf("RA not applied: changes=%d global=%v router=%v", changes, s.HasGlobal(), s.Router())
	}
	wantGlobal := netip.MustParseAddr("2001:db8:1::32ed:a0ff:fec8:8734")
	wantULA := netip.MustParseAddr("fd12:3456:789a::32ed:a0ff:fec8:8734")
	addrs := s.Addrs()
	if len(addrs) != 3 || addrs[0] != s.Addr() || addrs[1] != wantGlobal || addrs[2] != wantULA {
		t.Fatalf("Addrs = %v, want [%v %v %v]", addrs, s.Addr(), wantGlobal, wantULA)
	}

	// No third RS sent after RA arrived.
	frames = nil
	s.Poll(now.Add(rsInterval))
	if len(frames) != 0 {
		t.Fatalf("unexpected RS after RA: %d frames", len(frames))
	}

	// SolicitRouter re-arms the RS burst (e.g. after Wi-Fi rejoin).
	s.SolicitRouter()
	s.Poll(now.Add(2 * rsInterval))
	if len(frames) != 1 {
		t.Fatalf("expected RS after SolicitRouter, got %d", len(frames))
	}
}

func TestSLAACOnLinkUDPAndNDP(t *testing.T) {
	p := newPair()
	routerMAC := [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	ra := buildRA(routerMAC, LinkLocal(routerMAC), ndpHopLimit, 64, 1800, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800})
	now := time.Unix(2000, 0)
	p.a.Poll(now)
	p.b.Poll(now)
	p.a.HandleFrame(ra)
	p.b.HandleFrame(ra)

	aGlobal := p.a.Addrs()[1]
	bGlobal := p.b.Addrs()[1]

	var got []byte
	var from netip.AddrPort
	var gotDst netip.Addr
	p.b.Listen(5540, func(src netip.AddrPort, dst netip.Addr, b []byte) {
		got, from, gotDst = append([]byte(nil), b...), src, dst
	})
	if err := p.a.SendUDP(5550, netip.AddrPortFrom(bGlobal, 5540), []byte("global-hello")); err != ErrNoNeighbor {
		t.Fatalf("first global send: %v", err)
	}
	p.run() // NS for bGlobal -> NA from bGlobal -> flushed UDP
	if string(got) != "global-hello" || from != netip.AddrPortFrom(aGlobal, 5550) || gotDst != bGlobal {
		t.Fatalf("got %q from %v dst %v, want from %v dst %v", got, from, gotDst, aGlobal, bGlobal)
	}

	// Echo request to bGlobal gets a reply from bGlobal.
	p.queue = nil
	req := p.a.ipPacketFrom(aGlobal, bGlobal, protoICMPv6, 12, 64)
	copy(req, []byte{icmpEchoRequest, 0, 0, 0, 0, 1, 0, 2, 'p', 'o', 'n', 'g'})
	p.a.finishICMPFrom(aGlobal, bGlobal, req)
	p.a.output(bGlobal, len(req))
	p.b.HandleFrame(p.queue[0].frame)
	if len(p.queue) != 2 {
		t.Fatalf("no global echo reply (%d frames)", len(p.queue))
	}
	repIP := p.queue[1].frame[ethHeaderLen:]
	repSrc := netip.AddrFrom16([16]byte(repIP[8:24]))
	repICMP := repIP[ipHeaderLen:]
	if repSrc != bGlobal || repICMP[0] != icmpEchoReply || checksum(bGlobal, aGlobal, protoICMPv6, repICMP) != 0 {
		t.Fatalf("bad global echo reply from %v: % x", repSrc, repICMP)
	}
}

func TestSLAACOffLinkRoutingAndSourceSelection(t *testing.T) {
	var sent [][]byte
	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	s := New(mac, func(f []byte) error {
		sent = append(sent, append([]byte(nil), f...))
		return nil
	})
	now := time.Unix(3000, 0)
	s.Poll(now)

	remoteGlobal := netip.MustParseAddr("2001:db8:99::42")
	remoteULA := netip.MustParseAddr("fd99::1")
	if err := s.SendUDP(5540, netip.AddrPortFrom(remoteGlobal, 5540), []byte("hi")); err != ErrNoRoute {
		t.Fatalf("send without router: %v, want ErrNoRoute", err)
	}

	routerMAC := [6]byte{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01}
	routerIP := LinkLocal(routerMAC)
	s.HandleFrame(buildRA(routerMAC, routerIP, ndpHopLimit, 64, 1800, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800},
		raPrefix{netip.MustParsePrefix("fd12::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800}))

	// Off-link global destination routes through routerMAC and picks global source.
	if err := s.SendUDP(5540, netip.AddrPortFrom(remoteGlobal, 5540), []byte("g")); err != nil {
		t.Fatalf("off-link global send: %v", err)
	}
	if len(sent) != 1 || !bytes.Equal(sent[0][:6], routerMAC[:]) {
		t.Fatalf("off-link frame dst MAC % x, want router % x", sent[0][:6], routerMAC)
	}
	gotSrc := netip.AddrFrom16([16]byte(sent[0][ethHeaderLen+8 : ethHeaderLen+24]))
	if gotSrc != s.Addrs()[1] {
		t.Fatalf("global dst picked src %v, want %v", gotSrc, s.Addrs()[1])
	}

	// Off-link ULA destination routes through routerMAC and picks ULA source.
	sent = nil
	if err := s.SendUDP(5540, netip.AddrPortFrom(remoteULA, 5540), []byte("u")); err != nil {
		t.Fatalf("off-link ULA send: %v", err)
	}
	gotSrc = netip.AddrFrom16([16]byte(sent[0][ethHeaderLen+8 : ethHeaderLen+24]))
	if gotSrc != s.Addrs()[2] {
		t.Fatalf("ULA dst picked src %v, want %v", gotSrc, s.Addrs()[2])
	}

	// Incoming off-link UDP must NOT pollute neighbor cache with remoteGlobal.
	var delivered bool
	s.Listen(5540, func(src netip.AddrPort, dst netip.Addr, payload []byte) {
		delivered = src.Addr() == remoteGlobal && dst == s.Addrs()[1] && string(payload) == "from-wan"
	})
	pkt := make([]byte, ethHeaderLen+ipHeaderLen+udpHeaderLen+8)
	copy(pkt[0:6], mac[:])
	copy(pkt[6:12], routerMAC[:])
	binary.BigEndian.PutUint16(pkt[12:], etherTypeIP6)
	ip := pkt[ethHeaderLen:]
	ip[0], ip[6], ip[7] = 0x60, protoUDP, 60
	binary.BigEndian.PutUint16(ip[4:], udpHeaderLen+8)
	r16, d16 := remoteGlobal.As16(), s.Addrs()[1].As16()
	copy(ip[8:24], r16[:])
	copy(ip[24:40], d16[:])
	udp := ip[ipHeaderLen:]
	binary.BigEndian.PutUint16(udp[0:], 6000)
	binary.BigEndian.PutUint16(udp[2:], 5540)
	binary.BigEndian.PutUint16(udp[4:], udpHeaderLen+8)
	copy(udp[udpHeaderLen:], "from-wan")
	binary.BigEndian.PutUint16(udp[6:], checksum(remoteGlobal, s.Addrs()[1], protoUDP, udp))
	s.HandleFrame(pkt)
	if !delivered {
		t.Fatal("off-link UDP not delivered")
	}
	if _, cached := s.lookup(remoteGlobal); cached {
		t.Fatal("off-link source IP polluted neighbor cache")
	}
}

func TestSLAACLifetimesAndWithdrawal(t *testing.T) {
	s := New([6]byte{0x02, 0, 0, 0, 0, 0x22}, func([]byte) error { return nil })
	changes := 0
	s.StartSLAAC(func() { changes++ })
	now := time.Unix(4000, 0)
	s.Poll(now)

	routerMAC := [6]byte{0x02, 0x99, 0x88, 0x77, 0x66, 0x55}
	routerIP := LinkLocal(routerMAC)
	s.HandleFrame(buildRA(routerMAC, routerIP, ndpHopLimit, 64, 60, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 120, 30},
		raPrefix{netip.MustParsePrefix("2001:db8:2::/64"), pioFlagOnLink | pioFlagAuto, 300, 300}))
	if changes != 1 || len(s.Addrs()) != 3 {
		t.Fatalf("initial addrs=%v changes=%d", s.Addrs(), changes)
	}
	addr1, addr2 := s.Addrs()[1], s.Addrs()[2]

	// After 40s, addr1 is deprecated so addr2 is preferred for off-link global destinations.
	s.Poll(now.Add(40 * time.Second))
	if got := s.selectSrc(netip.MustParseAddr("2001:db8:99::1")); got != addr2 {
		t.Fatalf("expected preferred %v over deprecated %v, got %v", addr2, addr1, got)
	}
	// After 60s, default router expires.
	s.Poll(now.Add(60 * time.Second))
	if s.Router().IsValid() {
		t.Fatalf("router did not expire: %v", s.Router())
	}
	// After 120s, addr1 valid lifetime expires and onChange fires.
	s.Poll(now.Add(120 * time.Second))
	if changes != 2 || len(s.Addrs()) != 2 || s.Addrs()[1] != addr2 {
		t.Fatalf("after addr1 expiry: addrs=%v changes=%d", s.Addrs(), changes)
	}

	// Explicit withdrawal with valid=0 removes addr2 immediately.
	s.HandleFrame(buildRA(routerMAC, routerIP, ndpHopLimit, 64, 0, true,
		raPrefix{netip.MustParsePrefix("2001:db8:2::/64"), pioFlagOnLink | pioFlagAuto, 0, 0}))
	if changes != 3 || s.HasGlobal() || len(s.Addrs()) != 1 {
		t.Fatalf("after withdrawal: addrs=%v changes=%d", s.Addrs(), changes)
	}
}

func FuzzHandleFrame(f *testing.F) {
	p := newPair()
	p.a.learn(p.b.Addr(), p.b.MAC())
	p.a.SendUDP(1, netip.AddrPortFrom(p.b.Addr(), 5540), []byte("seed"))
	f.Add(p.queue[0].frame)
	routerMAC := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	f.Add(buildRA(routerMAC, LinkLocal(routerMAC), ndpHopLimit, 64, 1800, true,
		raPrefix{netip.MustParsePrefix("2001:db8:1::/64"), pioFlagOnLink | pioFlagAuto, 3600, 1800}))
	f.Fuzz(func(t *testing.T, frame []byte) {
		s := New([6]byte{0x30, 0xed, 0xa0, 0xc8, 0x87, 0x34}, func([]byte) error { return nil })
		s.StartSLAAC(func() {})
		s.Poll(time.Unix(1000, 0))
		s.Listen(5540, func(netip.AddrPort, netip.Addr, []byte) {})
		s.HandleFrame(frame)
	})
}
