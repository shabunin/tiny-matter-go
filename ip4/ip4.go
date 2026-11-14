// Package ip4 is a minimal IPv4 host for Matter over raw Ethernet frames,
// the IPv4 companion of package ip6. Many controllers and home networks
// still discover and reach devices over IPv4 first.
//
// It does what a node on one subnet needs: an address from DHCP (or set
// statically), ARP, a default gateway, Echo replies, IGMPv2 reports for
// joined groups, and UDP with checksums. There is no fragmentation.
//
// The Stack does not lock or start goroutines. Feed it received frames
// with HandleFrame, call Poll for its timers, and call its methods from the
// same goroutine.
package ip4

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

const (
	ethHeaderLen = 14
	ipHeaderLen  = 20
	udpHeaderLen = 8
	etherTypeIP4 = 0x0800
	etherTypeARP = 0x0806

	protoICMP = 1
	protoIGMP = 2
	protoUDP  = 17

	icmpEchoReply   = 0
	icmpEchoRequest = 8
	igmpQuery       = 0x11
	igmpV2Report    = 0x16

	defaultTTL     = 64
	arpCacheLen    = 8
	arpRetry       = time.Second
	maxUDPHandlers = 4
	maxGroups      = 4

	// MTU is the largest IPv4 packet sent or accepted (Ethernet payload).
	MTU = 1500
	// MaxUDPPayload is the largest UDP payload SendUDP accepts.
	MaxUDPPayload = MTU - ipHeaderLen - udpHeaderLen
)

var (
	ErrTooLarge   = errors.New("ip4: payload too large")
	ErrNoNeighbor = errors.New("ip4: neighbor not resolved yet")
	ErrNoAddress  = errors.New("ip4: no address yet")
	ErrFull       = errors.New("ip4: table full")
)

// Broadcast is the limited broadcast address.
var Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// UDPHandler receives UDP datagrams. src is the sender, dst the address the
// datagram was sent to (unicast, broadcast or a joined group). payload is
// only valid during the call.
type UDPHandler func(src netip.AddrPort, dst netip.Addr, payload []byte)

type neighbor struct {
	ip  netip.Addr
	mac [6]byte
}

type udpBinding struct {
	port uint16
	h    UDPHandler
}

// Stack is an IPv4 host on one Ethernet link.
type Stack struct {
	mac  [6]byte
	send func(frame []byte) error

	addr    netip.Addr   // invalid until configured
	prefix  netip.Prefix // our subnet
	gateway netip.Addr   // invalid if none

	groups    []netip.Addr
	udp       []udpBinding
	neighbors [arpCacheLen]neighbor
	nextEvict int

	// pending is one packet waiting for its next hop to be resolved.
	pending   []byte
	pendingTo netip.Addr // next hop
	arpAt     time.Time  // when to repeat the ARP request
	now       time.Time

	dhcp *dhcpClient
	id   uint16 // IP identification

	tx [ethHeaderLen + MTU]byte
}

// New returns a Stack for the interface with the given MAC address. send
// transmits one Ethernet frame (header included, no FCS); the frame is
// only valid during the call. The stack has no address until SetAddr or
// StartDHCP configures one.
func New(mac [6]byte, send func(frame []byte) error) *Stack {
	return &Stack{mac: mac, send: send}
}

// Addr returns the configured address (invalid if none).
func (s *Stack) Addr() netip.Addr { return s.addr }

// Prefix returns the configured subnet.
func (s *Stack) Prefix() netip.Prefix { return s.prefix }

// Gateway returns the default gateway (invalid if none).
func (s *Stack) Gateway() netip.Addr { return s.gateway }

// MAC returns the interface hardware address.
func (s *Stack) MAC() [6]byte { return s.mac }

// SetAddr configures a static address on subnet p (p.Addr() is the
// address) with an optional gateway, and announces it with a gratuitous
// ARP. A zero prefix removes the address.
func (s *Stack) SetAddr(p netip.Prefix, gateway netip.Addr) {
	if !p.IsValid() || !p.Addr().Is4() {
		s.addr, s.prefix, s.gateway = netip.Addr{}, netip.Prefix{}, netip.Addr{}
		return
	}
	changed := s.addr != p.Addr()
	s.addr, s.prefix, s.gateway = p.Addr(), p.Masked(), gateway
	if changed {
		for i := range s.neighbors {
			s.neighbors[i] = neighbor{}
		}
		s.sendARP(1, broadcastMAC, s.addr) // gratuitous request
		s.ReportGroups()
	}
}

func groupMAC(g netip.Addr) [6]byte {
	b := g.As4()
	return [6]byte{0x01, 0x00, 0x5e, b[1] & 0x7f, b[2], b[3]}
}

// Join joins multicast group g (for example 224.0.0.251 for mDNS) and
// reports the membership to IGMP snooping switches once an address is
// configured.
func (s *Stack) Join(g netip.Addr) error {
	if !g.Is4() || !g.IsMulticast() {
		return errors.New("ip4: not a multicast address")
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
	s.reportGroup(g)
	return nil
}

// ReportGroups sends an IGMPv2 report for each joined group. SetAddr calls
// it; call it again after the link (re)connects.
func (s *Stack) ReportGroups() {
	for _, g := range s.groups {
		s.reportGroup(g)
	}
}

func (s *Stack) reportGroup(g netip.Addr) {
	if !s.addr.IsValid() || g == allSystems {
		return
	}
	b := s.ipPacket(g, protoIGMP, 8, 1)
	b[0], b[1] = igmpV2Report, 0
	b[2], b[3] = 0, 0
	a := g.As4()
	copy(b[4:8], a[:])
	binary.BigEndian.PutUint16(b[2:], checksum(b))
	s.output(g, len(b))
}

var allSystems = netip.AddrFrom4([4]byte{224, 0, 0, 1})

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

func (s *Stack) subnetBroadcast() netip.Addr {
	if !s.prefix.IsValid() {
		return netip.Addr{}
	}
	a := s.prefix.Addr().As4()
	v := binary.BigEndian.Uint32(a[:]) | (1<<(32-s.prefix.Bits()) - 1)
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a)
}

func (s *Stack) accepts(dst netip.Addr) bool {
	if s.addr.IsValid() && dst == s.addr || dst == Broadcast || dst == allSystems {
		return true
	}
	if b := s.subnetBroadcast(); b.IsValid() && dst == b {
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
	if len(frame) < ethHeaderLen {
		return
	}
	var srcMAC [6]byte
	copy(srcMAC[:], frame[6:12])
	switch binary.BigEndian.Uint16(frame[12:]) {
	case etherTypeARP:
		s.handleARP(frame[ethHeaderLen:])
		return
	case etherTypeIP4:
	default:
		return
	}
	p := frame[ethHeaderLen:]
	if len(p) < ipHeaderLen || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:]))
	if ihl < ipHeaderLen || total < ihl || total > len(p) || checksum(p[:ihl]) != 0 {
		return
	}
	if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
		return // a fragment
	}
	proto := p[9]
	src := netip.AddrFrom4([4]byte(p[12:16]))
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	if src.IsMulticast() || src == Broadcast || srcMAC[0]&1 != 0 {
		return
	}
	body := p[ihl:total]
	if proto == protoUDP && s.dhcp != nil && len(body) >= 4 && binary.BigEndian.Uint16(body[2:]) == dhcpClientPort {
		// Offers and acks come before we have an address.
		if udp, ok := s.udpPayload(src, dst, body); ok {
			s.dhcp.handle(s, udp)
		}
		return
	}
	if !s.accepts(dst) {
		return
	}
	if s.onLink(src) && dst == s.addr {
		s.learn(src, srcMAC)
	}
	switch proto {
	case protoUDP:
		if b, ok := s.udpPayload(src, dst, body); ok {
			sport, dport := binary.BigEndian.Uint16(body[0:]), binary.BigEndian.Uint16(body[2:])
			for _, u := range s.udp {
				if u.port == dport {
					u.h(netip.AddrPortFrom(src, sport), dst, b)
					return
				}
			}
		}
	case protoICMP:
		if len(body) >= 8 && body[0] == icmpEchoRequest && dst == s.addr && checksum(body) == 0 {
			out := s.ipPacket(src, protoICMP, len(body), defaultTTL)
			copy(out, body)
			out[0], out[2], out[3] = icmpEchoReply, 0, 0
			binary.BigEndian.PutUint16(out[2:], checksum(out))
			s.output(s.nextHop(src), len(out))
		}
	case protoIGMP:
		if len(body) >= 8 && body[0] == igmpQuery && checksum(body) == 0 {
			g := netip.AddrFrom4([4]byte(body[4:8]))
			for _, x := range s.groups {
				if g.IsUnspecified() || g == x {
					s.reportGroup(x)
				}
			}
		}
	}
}

// udpPayload validates a UDP datagram and returns its payload.
func (s *Stack) udpPayload(src, dst netip.Addr, b []byte) ([]byte, bool) {
	if len(b) < udpHeaderLen {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[4:]))
	if n < udpHeaderLen || n > len(b) {
		return nil, false
	}
	b = b[:n]
	if binary.BigEndian.Uint16(b[6:]) != 0 && pseudoChecksum(src, dst, protoUDP, b) != 0 {
		return nil, false // a zero checksum means none over IPv4
	}
	return b[udpHeaderLen:], true
}

func (s *Stack) handleARP(b []byte) {
	if len(b) < 28 || binary.BigEndian.Uint16(b[0:]) != 1 || binary.BigEndian.Uint16(b[2:]) != etherTypeIP4 ||
		b[4] != 6 || b[5] != 4 {
		return
	}
	op := binary.BigEndian.Uint16(b[6:])
	var sha [6]byte
	copy(sha[:], b[8:14])
	spa := netip.AddrFrom4([4]byte(b[14:18]))
	tpa := netip.AddrFrom4([4]byte(b[24:28]))
	if !s.addr.IsValid() {
		return
	}
	if s.onLink(spa) && spa != s.addr {
		if tpa == s.addr {
			s.learn(spa, sha)
		} else {
			s.refresh(spa, sha) // RFC 826: update, but do not add
		}
	}
	if op == 1 && tpa == s.addr && spa != s.addr {
		s.sendARP(2, sha, spa)
	}
}

// sendARP sends an ARP request (op 1) for target, or a reply (op 2) to
// target at mac.
func (s *Stack) sendARP(op uint16, mac [6]byte, target netip.Addr) {
	f := s.tx[:ethHeaderLen+28]
	copy(f[0:6], mac[:])
	copy(f[6:12], s.mac[:])
	binary.BigEndian.PutUint16(f[12:], etherTypeARP)
	b := f[ethHeaderLen:]
	binary.BigEndian.PutUint16(b[0:], 1)
	binary.BigEndian.PutUint16(b[2:], etherTypeIP4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:], op)
	copy(b[8:14], s.mac[:])
	a := s.addr.As4()
	copy(b[14:18], a[:])
	if op == 1 {
		clear(b[18:24])
	} else {
		copy(b[18:24], mac[:])
	}
	t := target.As4()
	copy(b[24:28], t[:])
	s.send(f)
}

func (s *Stack) onLink(a netip.Addr) bool { return s.prefix.IsValid() && s.prefix.Contains(a) }

func (s *Stack) refresh(ip netip.Addr, mac [6]byte) {
	for i := range s.neighbors {
		if s.neighbors[i].ip == ip {
			s.neighbors[i].mac = mac
			s.flushPending(ip)
			return
		}
	}
}

func (s *Stack) learn(ip netip.Addr, mac [6]byte) {
	if mac[0]&1 != 0 {
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
	switch {
	case ip.IsMulticast():
		return groupMAC(ip), true
	case ip == Broadcast || ip == s.subnetBroadcast():
		return broadcastMAC, true
	}
	for _, n := range s.neighbors {
		if n.ip == ip {
			return n.mac, true
		}
	}
	return [6]byte{}, false
}

// nextHop returns the address whose MAC a packet to dst is sent to.
func (s *Stack) nextHop(dst netip.Addr) netip.Addr {
	if dst.IsMulticast() || dst == Broadcast || s.onLink(dst) || !s.gateway.IsValid() {
		return dst
	}
	return s.gateway
}

func (s *Stack) flushPending(hop netip.Addr) {
	if len(s.pending) == 0 || s.pendingTo != hop {
		return
	}
	n := copy(s.tx[ethHeaderLen:], s.pending)
	s.pending = s.pending[:0]
	s.output(hop, n-ipHeaderLen)
}

// ipPacket writes an IPv4 header to dst into the transmit buffer and
// returns the buffer for the n-byte payload.
func (s *Stack) ipPacket(dst netip.Addr, proto uint8, n int, ttl uint8) []byte {
	p := s.tx[ethHeaderLen:]
	s.id++
	p[0], p[1] = 0x45, 0
	binary.BigEndian.PutUint16(p[2:], uint16(ipHeaderLen+n))
	binary.BigEndian.PutUint16(p[4:], s.id)
	p[6], p[7] = 0x40, 0 // don't fragment
	p[8], p[9] = ttl, proto
	p[10], p[11] = 0, 0
	var src [4]byte
	if s.addr.IsValid() {
		src = s.addr.As4()
	}
	d := dst.As4()
	copy(p[12:16], src[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:], checksum(p[:ipHeaderLen]))
	return p[ipHeaderLen : ipHeaderLen+n]
}

// output sends the packet in the transmit buffer (n payload bytes) to the
// next hop, or parks it and sends an ARP request if its MAC is unknown.
func (s *Stack) output(hop netip.Addr, n int) error {
	mac, ok := s.lookup(hop)
	if !ok {
		s.pending = append(s.pending[:0], s.tx[ethHeaderLen:ethHeaderLen+ipHeaderLen+n]...)
		s.pendingTo = hop
		s.arpAt = s.now.Add(arpRetry)
		s.sendARP(1, broadcastMAC, hop)
		return ErrNoNeighbor
	}
	f := s.tx[:ethHeaderLen+ipHeaderLen+n]
	copy(f[0:6], mac[:])
	copy(f[6:12], s.mac[:])
	binary.BigEndian.PutUint16(f[12:], etherTypeIP4)
	return s.send(f)
}

// SendUDP sends payload from srcPort to dst. When the next hop's MAC is not
// known yet the datagram is held (one at a time), an ARP request is sent,
// and ErrNoNeighbor is returned; the datagram goes out when the neighbor
// answers.
func (s *Stack) SendUDP(srcPort uint16, dst netip.AddrPort, payload []byte) error {
	if !s.addr.IsValid() {
		return ErrNoAddress
	}
	return s.sendUDP(srcPort, dst, payload)
}

func (s *Stack) sendUDP(srcPort uint16, dst netip.AddrPort, payload []byte) error {
	if len(payload) > MaxUDPPayload {
		return ErrTooLarge
	}
	to := dst.Addr().Unmap()
	n := udpHeaderLen + len(payload)
	ttl := uint8(defaultTTL)
	if to.IsMulticast() {
		ttl = 255 // mDNS wants 255 (RFC 6762 11)
	}
	b := s.ipPacket(to, protoUDP, n, ttl)
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dst.Port())
	binary.BigEndian.PutUint16(b[4:], uint16(n))
	b[6], b[7] = 0, 0
	copy(b[udpHeaderLen:], payload)
	src := netip.AddrFrom4([4]byte{})
	if s.addr.IsValid() {
		src = s.addr
	}
	c := pseudoChecksum(src, to, protoUDP, b)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(b[6:], c)
	return s.output(s.nextHop(to), n)
}

// Poll runs the DHCP client and ARP retries, returning when it next needs
// to run (zero if idle).
func (s *Stack) Poll(now time.Time) time.Time {
	s.now = now
	var next time.Time
	if len(s.pending) > 0 {
		if !now.Before(s.arpAt) {
			s.arpAt = now.Add(arpRetry)
			s.sendARP(1, broadcastMAC, s.pendingTo)
		}
		next = s.arpAt
	}
	if s.dhcp != nil {
		if t := s.dhcp.poll(s, now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	return next
}

// checksum returns the Internet checksum of b; over data that carries a
// valid checksum it returns 0.
func checksum(b []byte) uint16 { return fold(sum(0, b)) }

func pseudoChecksum(src, dst netip.Addr, proto uint8, b []byte) uint16 {
	a, d := src.As4(), dst.As4()
	v := sum(0, a[:])
	v = sum(v, d[:])
	v += uint32(proto) + uint32(len(b))
	return fold(sum(v, b))
}

func sum(v uint32, p []byte) uint32 {
	for len(p) >= 2 {
		v += uint32(p[0])<<8 | uint32(p[1])
		p = p[2:]
	}
	if len(p) == 1 {
		v += uint32(p[0]) << 8
	}
	return v
}

func fold(v uint32) uint16 {
	for v>>16 != 0 {
		v = v&0xffff + v>>16
	}
	return ^uint16(v)
}
