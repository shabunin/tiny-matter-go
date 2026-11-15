// Package ip6 is a minimal IPv6 host for Matter over raw Ethernet frames.
// It is meant for microcontrollers whose network driver hands over Ethernet
// frames: ESP32 Wi-Fi, CYW43439 (Pico W) and WIZnet chips in MACRAW mode.
//
// It does only what a Matter node on a single link needs: a link-local
// address derived from the MAC (EUI-64), Neighbor Discovery (answering
// Neighbor Solicitations and resolving peers), Echo replies, MLDv2 reports
// for joined groups, and UDP with checksums. There is no fragmentation,
// routing or SLAAC.
//
// The Stack does not lock or start goroutines. Feed it received frames
// with HandleFrame and call its methods from the same goroutine.
package ip6

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ethHeaderLen = 14
	ipHeaderLen  = 40
	udpHeaderLen = 8
	etherTypeIP6 = 0x86DD

	protoHopByHop = 0
	protoUDP      = 17
	protoICMPv6   = 58

	icmpEchoRequest  = 128
	icmpEchoReply    = 129
	icmpMLDQuery     = 130
	icmpNS           = 135
	icmpNA           = 136
	icmpMLDv2Report  = 143
	optSourceLLAddr  = 1
	optTargetLLAddr  = 2
	ndpHopLimit      = 255
	defaultHopLimit  = 255 // all our traffic is link-local
	neighborCacheLen = 8
	maxUDPHandlers   = 4
	maxGroups        = 6

	// MTU is the largest IPv6 packet sent or accepted (Ethernet payload).
	MTU = 1500
	// MaxUDPPayload is the largest UDP payload SendUDP accepts.
	MaxUDPPayload = MTU - ipHeaderLen - udpHeaderLen
)

var (
	ErrTooLarge   = errors.New("ip6: payload too large")
	ErrNoNeighbor = errors.New("ip6: neighbor not resolved yet")
	ErrFull       = errors.New("ip6: table full")
)

var (
	allNodes   = netip.MustParseAddr("ff02::1")
	mldRouters = netip.MustParseAddr("ff02::16")
)

// UDPHandler receives UDP datagrams. src is the sender, dst the address the
// datagram was sent to (unicast or a joined group). payload is only valid
// during the call.
type UDPHandler func(src netip.AddrPort, dst netip.Addr, payload []byte)

type neighbor struct {
	ip  netip.Addr
	mac [6]byte
}

type udpBinding struct {
	port uint16
	h    UDPHandler
}

// Stack is an IPv6 host on one Ethernet link.
type Stack struct {
	mac  [6]byte
	addr netip.Addr
	send func(frame []byte) error

	groups    []netip.Addr
	udp       []udpBinding
	neighbors [neighborCacheLen]neighbor
	nextEvict int

	// pending is one packet waiting for its neighbor to be resolved.
	pending   []byte
	pendingTo netip.Addr

	tx [ethHeaderLen + MTU]byte
}

// New returns a Stack for the interface with the given MAC address. send
// transmits one Ethernet frame (header included, no FCS); the frame is
// only valid during the call.
func New(mac [6]byte, send func(frame []byte) error) *Stack {
	s := &Stack{mac: mac, send: send, addr: LinkLocal(mac)}
	s.groups = append(s.groups, allNodes, solicitedNode(s.addr))
	return s
}

// LinkLocal returns the EUI-64 link-local address for mac.
func LinkLocal(mac [6]byte) netip.Addr {
	var a [16]byte
	a[0], a[1] = 0xfe, 0x80
	a[8], a[9], a[10] = mac[0]^0x02, mac[1], mac[2]
	a[11], a[12] = 0xff, 0xfe
	a[13], a[14], a[15] = mac[3], mac[4], mac[5]
	return netip.AddrFrom16(a)
}

func solicitedNode(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 11: 0x01, 12: 0xff, 13: b[13], 14: b[14], 15: b[15]})
}

func multicastMAC(a netip.Addr) [6]byte {
	b := a.As16()
	return [6]byte{0x33, 0x33, b[12], b[13], b[14], b[15]}
}

// Addr returns the link-local address of the stack.
func (s *Stack) Addr() netip.Addr { return s.addr }

// MAC returns the interface hardware address.
func (s *Stack) MAC() [6]byte { return s.mac }

// Join joins multicast group g (for example ff02::fb for mDNS) and reports
// the membership to MLD snooping switches.
func (s *Stack) Join(g netip.Addr) error {
	if !g.Is6() || !g.IsMulticast() {
		return errors.New("ip6: not a multicast address")
	}
	for _, x := range s.groups {
		if x == g {
			return nil
		}
	}
	if len(s.groups) >= maxGroups {
		return ErrFull
	}
	s.groups = append(s.groups, g)
	return s.ReportGroups()
}

// Listen delivers UDP datagrams for port to h, replacing any previous
// handler for the port.
func (s *Stack) Listen(port uint16, h UDPHandler) error {
	for i := range s.udp {
		if s.udp[i].port == port {
			s.udp[i].h = h
			return nil
		}
	}
	if len(s.udp) >= maxUDPHandlers {
		return ErrFull
	}
	s.udp = append(s.udp, udpBinding{port, h})
	return nil
}

func (s *Stack) accepts(dst netip.Addr) bool {
	if dst == s.addr {
		return true
	}
	for _, g := range s.groups {
		if g == dst {
			return true
		}
	}
	return false
}

// HandleFrame processes one received Ethernet frame. Frames that are not
// for this host are ignored.
func (s *Stack) HandleFrame(frame []byte) {
	if len(frame) < ethHeaderLen+ipHeaderLen || binary.BigEndian.Uint16(frame[12:]) != etherTypeIP6 {
		return
	}
	var srcMAC [6]byte
	copy(srcMAC[:], frame[6:12])
	p := frame[ethHeaderLen:]
	if p[0]>>4 != 6 {
		return
	}
	plen := int(binary.BigEndian.Uint16(p[4:]))
	if plen > len(p)-ipHeaderLen || plen > MTU-ipHeaderLen {
		return
	}
	p = p[:ipHeaderLen+plen]
	next, hopLimit := p[6], p[7]
	src := netip.AddrFrom16([16]byte(p[8:24]))
	dst := netip.AddrFrom16([16]byte(p[24:40]))
	if !s.accepts(dst) || src.IsMulticast() || srcMAC[0]&1 != 0 {
		return
	}
	body := p[ipHeaderLen:]
	if next == protoHopByHop {
		if len(body) < 8 {
			return
		}
		n := 8 + int(body[1])*8
		if n > len(body) {
			return
		}
		next, body = body[0], body[n:]
	}
	if src.IsLinkLocalUnicast() && next != protoICMPv6 {
		s.learn(src, srcMAC) // ICMPv6 learns from NDP options instead
	}
	if checksum(src, dst, next, body) != 0 {
		return
	}
	switch next {
	case protoUDP:
		s.handleUDP(src, dst, body)
	case protoICMPv6:
		s.handleICMP(src, dst, srcMAC, hopLimit, body)
	}
}

func (s *Stack) handleUDP(src, dst netip.Addr, b []byte) {
	if len(b) < udpHeaderLen {
		return
	}
	n := int(binary.BigEndian.Uint16(b[4:]))
	if n < udpHeaderLen || n > len(b) || binary.BigEndian.Uint16(b[6:]) == 0 {
		return // a zero checksum is not allowed over IPv6
	}
	sport, dport := binary.BigEndian.Uint16(b[0:]), binary.BigEndian.Uint16(b[2:])
	for _, u := range s.udp {
		if u.port == dport {
			u.h(netip.AddrPortFrom(src, sport), dst, b[udpHeaderLen:n])
			return
		}
	}
}

func (s *Stack) handleICMP(src, dst netip.Addr, srcMAC [6]byte, hopLimit uint8, b []byte) {
	if len(b) < 4 {
		return
	}
	switch b[0] {
	case icmpEchoRequest:
		if dst != s.addr {
			return
		}
		s.learn(src, srcMAC)
		out := s.ipPacket(src, protoICMPv6, len(b), defaultHopLimit)
		copy(out, b)
		out[0] = icmpEchoReply
		s.finishICMP(src, out)
		s.output(src, len(b))
	case icmpNS:
		if hopLimit != ndpHopLimit || len(b) < 24 {
			return
		}
		target := netip.AddrFrom16([16]byte(b[8:24]))
		if target != s.addr {
			return
		}
		to, solicited := src, true
		if src.IsUnspecified() {
			to, solicited = allNodes, false // reply to duplicate address detection
		} else if mac, ok := linkLayerOption(b[24:], optSourceLLAddr); ok {
			s.learn(src, mac)
		} else {
			s.learn(src, srcMAC)
		}
		s.sendNA(to, solicited)
	case icmpNA:
		if hopLimit != ndpHopLimit || len(b) < 24 {
			return
		}
		target := netip.AddrFrom16([16]byte(b[8:24]))
		if mac, ok := linkLayerOption(b[24:], optTargetLLAddr); ok {
			s.learn(target, mac)
		} else if target == src {
			s.learn(target, srcMAC)
		}
	case icmpMLDQuery:
		s.ReportGroups()
	}
}

func linkLayerOption(opts []byte, typ uint8) (mac [6]byte, ok bool) {
	for len(opts) >= 8 {
		n := int(opts[1]) * 8
		if n == 0 || n > len(opts) {
			return mac, false
		}
		if opts[0] == typ && n >= 8 {
			copy(mac[:], opts[2:8])
			return mac, true
		}
		opts = opts[n:]
	}
	return mac, false
}

func (s *Stack) learn(ip netip.Addr, mac [6]byte) {
	if !ip.IsLinkLocalUnicast() || mac[0]&1 != 0 {
		return
	}
	for i := range s.neighbors {
		if s.neighbors[i].ip == ip {
			s.neighbors[i].mac = mac
			s.flushPending(ip)
			return
		}
	}
	s.neighbors[s.nextEvict] = neighbor{ip, mac}
	s.nextEvict = (s.nextEvict + 1) % len(s.neighbors)
	s.flushPending(ip)
}

func (s *Stack) lookup(ip netip.Addr) ([6]byte, bool) {
	if ip.IsMulticast() {
		return multicastMAC(ip), true
	}
	for _, n := range s.neighbors {
		if n.ip == ip {
			return n.mac, true
		}
	}
	return [6]byte{}, false
}

func (s *Stack) flushPending(ip netip.Addr) {
	if len(s.pending) == 0 || s.pendingTo != ip {
		return
	}
	n := copy(s.tx[ethHeaderLen:], s.pending)
	s.pending = s.pending[:0]
	s.output(ip, n-ipHeaderLen)
}

// ipPacket writes an IPv6 header to dst into the transmit buffer and returns
// the buffer for the n-byte upper-layer payload.
func (s *Stack) ipPacket(dst netip.Addr, proto uint8, n int, hopLimit uint8) []byte {
	p := s.tx[ethHeaderLen:]
	p[0], p[1], p[2], p[3] = 0x60, 0, 0, 0
	binary.BigEndian.PutUint16(p[4:], uint16(n))
	p[6], p[7] = proto, hopLimit
	src := s.addr.As16()
	d := dst.As16()
	copy(p[8:], src[:])
	copy(p[24:], d[:])
	return p[ipHeaderLen : ipHeaderLen+n]
}

func (s *Stack) finishICMP(dst netip.Addr, b []byte) {
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint16(b[2:], checksum(s.addr, dst, protoICMPv6, b))
}

// output sends the packet in the transmit buffer (n payload bytes), or
// parks it and solicits the neighbor if its MAC is unknown.
func (s *Stack) output(dst netip.Addr, n int) error {
	mac, ok := s.lookup(dst)
	if !ok {
		s.pending = append(s.pending[:0], s.tx[ethHeaderLen:ethHeaderLen+ipHeaderLen+n]...)
		s.pendingTo = dst
		s.sendNS(dst)
		return ErrNoNeighbor
	}
	f := s.tx[:ethHeaderLen+ipHeaderLen+n]
	copy(f[0:6], mac[:])
	copy(f[6:12], s.mac[:])
	binary.BigEndian.PutUint16(f[12:], etherTypeIP6)
	return s.send(f)
}

func (s *Stack) sendNA(to netip.Addr, solicited bool) {
	b := s.ipPacket(to, protoICMPv6, 32, ndpHopLimit)
	clear(b)
	b[0] = icmpNA
	b[4] = 0x20 // override
	if solicited {
		b[4] |= 0x40
	}
	a := s.addr.As16()
	copy(b[8:24], a[:])
	b[24], b[25] = optTargetLLAddr, 1
	copy(b[26:32], s.mac[:])
	s.finishICMP(to, b)
	s.output(to, len(b))
}

func (s *Stack) sendNS(target netip.Addr) {
	to := solicitedNode(target)
	// The pending packet is stored outside tx, so tx can be reused here.
	b := s.ipPacket(to, protoICMPv6, 32, ndpHopLimit)
	clear(b)
	b[0] = icmpNS
	t := target.As16()
	copy(b[8:24], t[:])
	b[24], b[25] = optSourceLLAddr, 1
	copy(b[26:32], s.mac[:])
	s.finishICMP(to, b)
	s.output(to, len(b))
}

// ReportGroups sends an MLDv2 report listing the joined groups. Join calls
// it; call it again after the link (re)connects.
func (s *Stack) ReportGroups() error {
	var groups []netip.Addr
	for _, g := range s.groups {
		if g != allNodes { // never reported (RFC 3810 section 6)
			groups = append(groups, g)
		}
	}
	const hbh = 8
	n := hbh + 8 + 20*len(groups)
	p := s.ipPacket(mldRouters, protoHopByHop, n, 1)
	clear(p)
	// Hop-by-hop header with a Router Alert option (RFC 2711) and PadN.
	copy(p, []byte{protoICMPv6, 0, 5, 2, 0, 0, 1, 0})
	b := p[hbh:]
	b[0] = icmpMLDv2Report
	binary.BigEndian.PutUint16(b[6:], uint16(len(groups)))
	for i, g := range groups {
		r := b[8+20*i:]
		r[0] = 2 // MODE_IS_EXCLUDE with no sources: listening
		a := g.As16()
		copy(r[4:20], a[:])
	}
	binary.BigEndian.PutUint16(b[2:], checksum(s.addr, mldRouters, protoICMPv6, b))
	return s.output(mldRouters, n)
}

// SendUDP sends payload from srcPort to dst. When dst's link-layer address
// is not known yet the datagram is held (one at a time), a Neighbor
// Solicitation is sent, and ErrNoNeighbor is returned; the datagram goes
// out when the neighbor answers.
func (s *Stack) SendUDP(srcPort uint16, dst netip.AddrPort, payload []byte) error {
	if len(payload) > MaxUDPPayload {
		return ErrTooLarge
	}
	to := dst.Addr().WithZone("")
	n := udpHeaderLen + len(payload)
	b := s.ipPacket(to, protoUDP, n, defaultHopLimit)
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dst.Port())
	binary.BigEndian.PutUint16(b[4:], uint16(n))
	b[6], b[7] = 0, 0
	copy(b[udpHeaderLen:], payload)
	c := checksum(s.addr, to, protoUDP, b)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(b[6:], c)
	return s.output(to, n)
}

// checksum returns the Internet checksum of b with the IPv6 pseudo-header.
// Over a packet that carries a valid checksum it returns 0.
func checksum(src, dst netip.Addr, proto uint8, b []byte) uint16 {
	var sum uint32
	add := func(p []byte) {
		for len(p) >= 2 {
			sum += uint32(p[0])<<8 | uint32(p[1])
			p = p[2:]
		}
		if len(p) == 1 {
			sum += uint32(p[0]) << 8
		}
	}
	a, d := src.As16(), dst.As16()
	add(a[:])
	add(d[:])
	sum += uint32(len(b)>>16) + uint32(len(b)&0xffff) + uint32(proto)
	add(b)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
