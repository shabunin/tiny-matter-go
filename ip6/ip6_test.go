package ip6

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
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

func FuzzHandleFrame(f *testing.F) {
	p := newPair()
	p.a.learn(p.b.Addr(), p.b.MAC())
	p.a.SendUDP(1, netip.AddrPortFrom(p.b.Addr(), 5540), []byte("seed"))
	f.Add(p.queue[0].frame)
	f.Fuzz(func(t *testing.T, frame []byte) {
		s := New([6]byte{0x30, 0xed, 0xa0, 0xc8, 0x87, 0x34}, func([]byte) error { return nil })
		s.Listen(5540, func(netip.AddrPort, netip.Addr, []byte) {})
		s.HandleFrame(frame)
	})
}
