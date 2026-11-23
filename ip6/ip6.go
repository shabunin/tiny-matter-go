// Package ip6 is a minimal IPv6 host for Matter over raw Ethernet frames.
// It is meant for microcontrollers whose network driver hands over Ethernet
// frames: ESP32 Wi-Fi, CYW43439 (Pico W) and WIZnet chips in MACRAW mode.
//
// It provides an EUI-64 link-local address, SLAAC global and ULA addresses
// from Router Advertisements (RFC 4861, RFC 4862) with default-router
// forwarding, Neighbor Discovery (answering Neighbor Solicitations and
// resolving peers), Echo replies, MLDv2 reports for joined groups, and UDP
// with checksums. There is no fragmentation or DHCPv6.
//
// The Stack does not lock or start goroutines. Feed it received frames
// with HandleFrame and call Poll and its other methods from the same
// goroutine.
package ip6

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

const (
	ethHeaderLen = 14
	ipHeaderLen  = 40
	udpHeaderLen = 8
	etherTypeIP6 = 0x86DD

	protoHopByHop = 0
	protoUDP      = 17
	protoICMPv6   = 58

	icmpEchoRequest = 128
	icmpEchoReply   = 129
	icmpMLDQuery    = 130
	icmpRS          = 133
	icmpRA          = 134
	icmpNS          = 135
	icmpNA          = 136
	icmpMLDv2Report = 143

	optSourceLLAddr = 1
	optTargetLLAddr = 2
	optPrefixInfo   = 3

	pioFlagOnLink = 0x80
	pioFlagAuto   = 0x40
	infiniteLife  = 0xffffffff

	ndpHopLimit      = 255
	defaultHopLimit  = 64
	neighborCacheLen = 8
	maxUDPHandlers   = 4
	maxGroups        = 24 // all-nodes, solicited-node, mDNS and Matter groups
	maxPrefixes      = 4  // SLAAC / on-link prefixes learned from RAs

	// Router Solicitation parameters (RFC 4861 section 10).
	rsInterval = 4 * time.Second
	maxRS      = 3

	// MTU is the largest IPv6 packet sent or accepted (Ethernet payload).
	MTU = 1500
	// MaxUDPPayload is the largest UDP payload SendUDP accepts.
	MaxUDPPayload = MTU - ipHeaderLen - udpHeaderLen
)

var (
	ErrTooLarge   = errors.New("ip6: payload too large")
	ErrNoNeighbor = errors.New("ip6: neighbor not resolved yet")
	ErrNoRoute    = errors.New("ip6: no route to destination")
	ErrFull       = errors.New("ip6: table full")
)

var (
	allNodes   = netip.MustParseAddr("ff02::1")
	allRouters = netip.MustParseAddr("ff02::2")
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

// prefixEntry holds an on-link prefix and/or SLAAC address learned from a
// Router Advertisement Prefix Information option.
type prefixEntry struct {
	prefix     netip.Prefix // /64 prefix
	addr       netip.Addr   // SLAAC address when hasAddr is true
	hasAddr    bool         // A flag: autonomous address formed
	onLink     bool         // L flag: destinations in prefix are on-link
	validSec   uint32       // pending valid lifetime until Poll anchors it
	prefSec    uint32       // pending preferred lifetime until Poll anchors it
	validUntil time.Time    // zero when infinite or not yet anchored
	prefUntil  time.Time    // zero when infinite or not yet anchored
	infiniteV  bool
	infiniteP  bool
	anchored   bool
}

func (e *prefixEntry) used() bool { return e.prefix.IsValid() }

func (e *prefixEntry) preferred(now time.Time) bool {
	if !e.hasAddr {
		return false
	}
	if e.infiniteP {
		return true
	}
	if !e.anchored {
		return e.prefSec > 0
	}
	return now.Before(e.prefUntil)
}

func (e *prefixEntry) expired(now time.Time) bool {
	if !e.used() || e.infiniteV || !e.anchored {
		return false
	}
	return !now.Before(e.validUntil)
}

// Stack is an IPv6 host on one Ethernet link.
type Stack struct {
	mac      [6]byte
	addr     netip.Addr // EUI-64 link-local address
	send     func(frame []byte) error
	hopLimit uint8

	groups    []netip.Addr
	udp       []udpBinding
	neighbors [neighborCacheLen]neighbor
	nextEvict int

	// SLAAC state learned from Router Advertisements.
	slaacOn      bool
	onChange     func()
	now          time.Time
	rsLeft       int
	rsAt         time.Time
	router       netip.Addr // default router's link-local address
	routerSec    uint32
	routerUntil  time.Time
	routerAnchor bool
	prefixes     [maxPrefixes]prefixEntry

	// pending is one packet waiting for its next-hop neighbor to be resolved.
	pending        []byte
	pendingNextHop netip.Addr

	tx [ethHeaderLen + MTU]byte
}

// New returns a Stack for the interface with the given MAC address. send
// transmits one Ethernet frame (header included, no FCS); the frame is
// only valid during the call.
func New(mac [6]byte, send func(frame []byte) error) *Stack {
	s := &Stack{mac: mac, send: send, addr: LinkLocal(mac), hopLimit: defaultHopLimit}
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

func isULA(a netip.Addr) bool {
	b := a.As16()
	return b[0]&0xfe == 0xfc
}

// Addr returns the link-local address of the stack.
func (s *Stack) Addr() netip.Addr { return s.addr }

// Addrs returns the stack's unicast addresses: its link-local address
// followed by any valid SLAAC addresses (preferred before deprecated).
func (s *Stack) Addrs() []netip.Addr {
	out := make([]netip.Addr, 0, 1+maxPrefixes)
	out = append(out, s.addr)
	for i := range s.prefixes {
		if s.prefixes[i].hasAddr && s.prefixes[i].preferred(s.now) {
			out = append(out, s.prefixes[i].addr)
		}
	}
	for i := range s.prefixes {
		if s.prefixes[i].hasAddr && !s.prefixes[i].preferred(s.now) {
			out = append(out, s.prefixes[i].addr)
		}
	}
	return out
}

// HasGlobal reports whether the stack has at least one valid SLAAC address
// (global unicast or ULA).
func (s *Stack) HasGlobal() bool {
	for i := range s.prefixes {
		if s.prefixes[i].hasAddr {
			return true
		}
	}
	return false
}

// Router returns the default router's link-local address, or the invalid
// address if none has been learned.
func (s *Stack) Router() netip.Addr { return s.router }

// MAC returns the interface hardware address.
func (s *Stack) MAC() [6]byte { return s.mac }

// StartSLAAC enables Router Solicitation and SLAAC address tracking.
// onChange, if non-nil, is called whenever the set of SLAAC addresses
// changes. Drive timers with Poll.
func (s *Stack) StartSLAAC(onChange func()) {
	s.slaacOn = true
	s.onChange = onChange
	s.SolicitRouter()
}

// SolicitRouter schedules a fresh burst of Router Solicitations, for
// example after the Wi-Fi link reconnects.
func (s *Stack) SolicitRouter() {
	if !s.slaacOn {
		return
	}
	s.rsLeft = maxRS
	s.rsAt = time.Time{}
}

// Poll drives Router Solicitations and expires router and SLAAC prefix
// lifetimes. It returns when it next needs to run, or the zero time when
// idle.
func (s *Stack) Poll(now time.Time) time.Time {
	s.now = now
	changed := false

	// Anchor any lifetimes learned from RAs received before the first Poll.
	if s.router.IsValid() && !s.routerAnchor {
		s.routerUntil = now.Add(time.Duration(s.routerSec) * time.Second)
		s.routerAnchor = true
	}
	if s.router.IsValid() && !now.Before(s.routerUntil) {
		s.router = netip.Addr{}
		s.routerAnchor = false
	}
	for i := range s.prefixes {
		e := &s.prefixes[i]
		if !e.used() {
			continue
		}
		if !e.anchored {
			if !e.infiniteV {
				e.validUntil = now.Add(time.Duration(e.validSec) * time.Second)
			}
			if !e.infiniteP {
				e.prefUntil = now.Add(time.Duration(e.prefSec) * time.Second)
			}
			e.anchored = true
		}
		if e.expired(now) {
			if e.hasAddr {
				changed = true
			}
			*e = prefixEntry{}
		}
	}
	if changed && s.onChange != nil {
		s.onChange()
	}

	var next time.Time
	consider := func(at time.Time) {
		if !at.IsZero() && (next.IsZero() || at.Before(next)) {
			next = at
		}
	}

	if s.slaacOn && s.rsLeft > 0 {
		if s.rsAt.IsZero() || !now.Before(s.rsAt) {
			s.sendRS()
			s.rsLeft--
			if s.rsLeft > 0 {
				s.rsAt = now.Add(rsInterval)
			} else {
				s.rsAt = time.Time{}
			}
		}
		consider(s.rsAt)
	}
	if s.router.IsValid() && s.routerAnchor {
		consider(s.routerUntil)
	}
	for i := range s.prefixes {
		e := &s.prefixes[i]
		if e.used() && e.anchored && !e.infiniteV {
			consider(e.validUntil)
		}
	}
	return next
}

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

// Groups returns the multicast groups the stack listens on: all-nodes,
// the solicited-node group and those joined. A radio with a hardware
// multicast filter must pass their MAC addresses. The slice is the
// stack's own; do not change it.
func (s *Stack) Groups() []netip.Addr { return s.groups }

// Leave leaves multicast group g, telling MLD snooping switches.
func (s *Stack) Leave(g netip.Addr) error {
	for i, x := range s.groups {
		if x == g && g != allNodes && g != solicitedNode(s.addr) {
			s.groups = append(s.groups[:i], s.groups[i+1:]...)
			return s.report(mldChangeToInclude, []netip.Addr{g})
		}
	}
	return nil
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

func (s *Stack) isOwn(ip netip.Addr) bool {
	if ip == s.addr {
		return true
	}
	for i := range s.prefixes {
		if s.prefixes[i].hasAddr && s.prefixes[i].addr == ip {
			return true
		}
	}
	return false
}

func (s *Stack) isOnLink(ip netip.Addr) bool {
	if ip.IsLinkLocalUnicast() {
		return true
	}
	for i := range s.prefixes {
		if s.prefixes[i].used() && s.prefixes[i].onLink && s.prefixes[i].prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Stack) accepts(dst netip.Addr) bool {
	if s.isOwn(dst) {
		return true
	}
	for _, g := range s.groups {
		if g == dst {
			return true
		}
	}
	return false
}

// selectSrc chooses the source address for packets sent to dst (simplified
// RFC 6724: link-local for link-local destinations, otherwise preferring a
// preferred SLAAC address matching dst's prefix or ULA/global scope).
func (s *Stack) selectSrc(dst netip.Addr) netip.Addr {
	if dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() {
		return s.addr
	}
	dstULA := isULA(dst)
	var best netip.Addr
	bestRank := -1
	for i := range s.prefixes {
		e := &s.prefixes[i]
		if !e.hasAddr {
			continue
		}
		rank := 0
		if e.preferred(s.now) {
			rank += 4
		}
		if e.prefix.Contains(dst) {
			rank += 2
		} else if !dst.IsMulticast() && isULA(e.addr) == dstULA {
			rank += 1
		}
		if rank > bestRank {
			bestRank = rank
			best = e.addr
		}
	}
	if best.IsValid() {
		return best
	}
	return s.addr
}

// nextHop returns the link-layer target IP for dst, or ErrNoRoute if dst is
// off-link and no default router is known.
func (s *Stack) nextHop(dst netip.Addr) (netip.Addr, error) {
	if dst.IsMulticast() || s.isOnLink(dst) {
		return dst, nil
	}
	if s.router.IsValid() {
		return s.router, nil
	}
	return netip.Addr{}, ErrNoRoute
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
	if s.isOnLink(src) && next != protoICMPv6 {
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
		if !s.isOwn(dst) {
			return
		}
		if s.isOnLink(src) {
			s.learn(src, srcMAC)
		}
		hl := s.hopLimit
		if src.IsLinkLocalUnicast() {
			hl = ndpHopLimit
		}
		out := s.ipPacketFrom(dst, src, protoICMPv6, len(b), hl)
		copy(out, b)
		out[0] = icmpEchoReply
		s.finishICMPFrom(dst, src, out)
		s.output(src, len(b))
	case icmpRA:
		s.handleRA(src, srcMAC, hopLimit, b)
	case icmpNS:
		if hopLimit != ndpHopLimit || len(b) < 24 {
			return
		}
		target := netip.AddrFrom16([16]byte(b[8:24]))
		if !s.isOwn(target) {
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
		s.sendNA(target, to, solicited)
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

// handleRA processes an ICMPv6 Router Advertisement (RFC 4861 section 6.3.4,
// RFC 4862 section 5.5.3): learns the default router, hop limit, on-link
// prefixes and /64 SLAAC addresses.
func (s *Stack) handleRA(src netip.Addr, srcMAC [6]byte, hopLimit uint8, b []byte) {
	if hopLimit != ndpHopLimit || b[1] != 0 || len(b) < 16 || !src.IsLinkLocalUnicast() {
		return
	}
	if b[4] > 0 {
		s.hopLimit = b[4]
	}
	routerLife := binary.BigEndian.Uint16(b[6:8])
	if routerLife > 0 {
		s.router = src
		s.routerSec = uint32(routerLife)
		if !s.now.IsZero() {
			s.routerUntil = s.now.Add(time.Duration(routerLife) * time.Second)
			s.routerAnchor = true
		} else {
			s.routerAnchor = false
		}
		s.rsLeft = 0
		s.rsAt = time.Time{}
	} else if s.router == src {
		s.router = netip.Addr{}
		s.routerAnchor = false
	}

	// Parse options; learn router MAC (prefer Source Link-Layer Address option).
	routerMAC := srcMAC
	changed := false
	opts := b[16:]
	for len(opts) >= 8 {
		n := int(opts[1]) * 8
		if n == 0 || n > len(opts) {
			break
		}
		switch opts[0] {
		case optSourceLLAddr:
			copy(routerMAC[:], opts[2:8])
		case optPrefixInfo:
			if n == 32 && s.applyPrefixInfo(opts[:32]) {
				changed = true
			}
		}
		opts = opts[n:]
	}
	if routerLife > 0 {
		s.learn(src, routerMAC)
	}
	if changed {
		s.rsLeft = 0
		s.rsAt = time.Time{}
		if s.onChange != nil {
			s.onChange()
		}
	}
}

// applyPrefixInfo updates the prefix table from one 32-byte PIO option.
// It reports whether the set of SLAAC addresses changed.
func (s *Stack) applyPrefixInfo(opt []byte) bool {
	prefixLen := opt[2]
	flags := opt[3]
	onLink := flags&pioFlagOnLink != 0
	auto := flags&pioFlagAuto != 0
	valid := binary.BigEndian.Uint32(opt[4:8])
	pref := binary.BigEndian.Uint32(opt[8:12])
	if (!onLink && !auto) || prefixLen != 64 || pref > valid {
		return false
	}
	var raw [16]byte
	copy(raw[:8], opt[16:24])
	pAddr := netip.AddrFrom16(raw)
	if pAddr.IsLinkLocalUnicast() || pAddr.IsMulticast() || pAddr.IsUnspecified() {
		return false
	}
	pfx := netip.PrefixFrom(pAddr, 64)

	// Form EUI-64 SLAAC address using the same interface ID as the link-local address.
	ll := s.addr.As16()
	var full [16]byte
	copy(full[:8], raw[:8])
	copy(full[8:], ll[8:])
	addr := netip.AddrFrom16(full)

	idx := -1
	free := -1
	for i := range s.prefixes {
		if s.prefixes[i].used() && s.prefixes[i].prefix == pfx {
			idx = i
			break
		}
		if !s.prefixes[i].used() && free < 0 {
			free = i
		}
	}

	if valid == 0 {
		if idx < 0 {
			return false
		}
		hadAddr := s.prefixes[idx].hasAddr
		s.prefixes[idx] = prefixEntry{}
		return hadAddr
	}

	addedAddr := false
	if idx < 0 {
		if free < 0 {
			return false
		}
		idx = free
		addedAddr = auto
	} else if auto && !s.prefixes[idx].hasAddr {
		addedAddr = true
	}

	e := &s.prefixes[idx]
	e.prefix = pfx
	if onLink {
		e.onLink = true
	}
	if auto {
		e.addr = addr
		e.hasAddr = true
	}
	e.validSec, e.prefSec = valid, pref
	e.infiniteV = valid == infiniteLife
	e.infiniteP = pref == infiniteLife
	if !s.now.IsZero() {
		if !e.infiniteV {
			e.validUntil = s.now.Add(time.Duration(valid) * time.Second)
		}
		if !e.infiniteP {
			e.prefUntil = s.now.Add(time.Duration(pref) * time.Second)
		}
		e.anchored = true
	} else {
		e.anchored = false
	}
	return addedAddr
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
	if !s.isOnLink(ip) || mac[0]&1 != 0 {
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

func (s *Stack) flushPending(nextHop netip.Addr) {
	if len(s.pending) == 0 || s.pendingNextHop != nextHop {
		return
	}
	n := copy(s.tx[ethHeaderLen:], s.pending)
	s.pending = s.pending[:0]
	s.pendingNextHop = netip.Addr{}
	s.outputToNextHop(nextHop, n-ipHeaderLen)
}

// ipPacket writes an IPv6 header from the link-local address to dst into
// the transmit buffer and returns the buffer for the n-byte payload.
func (s *Stack) ipPacket(dst netip.Addr, proto uint8, n int, hopLimit uint8) []byte {
	return s.ipPacketFrom(s.addr, dst, proto, n, hopLimit)
}

func (s *Stack) ipPacketFrom(src, dst netip.Addr, proto uint8, n int, hopLimit uint8) []byte {
	p := s.tx[ethHeaderLen:]
	p[0], p[1], p[2], p[3] = 0x60, 0, 0, 0
	binary.BigEndian.PutUint16(p[4:], uint16(n))
	p[6], p[7] = proto, hopLimit
	a := src.As16()
	d := dst.As16()
	copy(p[8:], a[:])
	copy(p[24:], d[:])
	return p[ipHeaderLen : ipHeaderLen+n]
}

func (s *Stack) finishICMP(dst netip.Addr, b []byte) {
	s.finishICMPFrom(s.addr, dst, b)
}

func (s *Stack) finishICMPFrom(src, dst netip.Addr, b []byte) {
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint16(b[2:], checksum(src, dst, protoICMPv6, b))
}

// output sends the packet in the transmit buffer (n payload bytes) to dst
// (directly if on-link/multicast, or via the default router), parking it
// and soliciting the next-hop neighbor if its MAC is unknown.
func (s *Stack) output(dst netip.Addr, n int) error {
	hop, err := s.nextHop(dst)
	if err != nil {
		return err
	}
	return s.outputToNextHop(hop, n)
}

func (s *Stack) outputToNextHop(hop netip.Addr, n int) error {
	mac, ok := s.lookup(hop)
	if !ok {
		s.pending = append(s.pending[:0], s.tx[ethHeaderLen:ethHeaderLen+ipHeaderLen+n]...)
		s.pendingNextHop = hop
		s.sendNS(hop)
		return ErrNoNeighbor
	}
	f := s.tx[:ethHeaderLen+ipHeaderLen+n]
	copy(f[0:6], mac[:])
	copy(f[6:12], s.mac[:])
	binary.BigEndian.PutUint16(f[12:], etherTypeIP6)
	return s.send(f)
}

func (s *Stack) sendRS() {
	b := s.ipPacket(allRouters, protoICMPv6, 16, ndpHopLimit)
	clear(b)
	b[0] = icmpRS
	b[8], b[9] = optSourceLLAddr, 1
	copy(b[10:16], s.mac[:])
	s.finishICMP(allRouters, b)
	s.outputToNextHop(allRouters, len(b))
}

func (s *Stack) sendNA(target, to netip.Addr, solicited bool) {
	b := s.ipPacketFrom(target, to, protoICMPv6, 32, ndpHopLimit)
	clear(b)
	b[0] = icmpNA
	b[4] = 0x20 // override
	if solicited {
		b[4] |= 0x40
	}
	a := target.As16()
	copy(b[8:24], a[:])
	b[24], b[25] = optTargetLLAddr, 1
	copy(b[26:32], s.mac[:])
	s.finishICMPFrom(target, to, b)
	s.output(to, len(b))
}

func (s *Stack) sendNS(target netip.Addr) {
	to := solicitedNode(target)
	src := s.selectSrc(target)
	// The pending packet is stored outside tx, so tx can be reused here.
	b := s.ipPacketFrom(src, to, protoICMPv6, 32, ndpHopLimit)
	clear(b)
	b[0] = icmpNS
	t := target.As16()
	copy(b[8:24], t[:])
	b[24], b[25] = optSourceLLAddr, 1
	copy(b[26:32], s.mac[:])
	s.finishICMPFrom(src, to, b)
	s.outputToNextHop(to, len(b))
}

// ReportGroups sends an MLDv2 report listing the joined groups. Join calls
// it; call it again after the link (re)connects.
func (s *Stack) ReportGroups() error {
	var groups [maxGroups]netip.Addr
	n := 0
	for _, g := range s.groups {
		if g != allNodes { // never reported (RFC 3810 section 6)
			groups[n] = g
			n++
		}
	}
	return s.report(mldIsExclude, groups[:n])
}

// MLDv2 multicast address record types (RFC 3810 section 5.2.12), each
// with no sources.
const (
	mldIsExclude       = 2 // listening
	mldChangeToInclude = 3 // stopped listening
)

func (s *Stack) report(recordType byte, groups []netip.Addr) error {
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
		r[0] = recordType
		a := g.As16()
		copy(r[4:20], a[:])
	}
	binary.BigEndian.PutUint16(b[2:], checksum(s.addr, mldRouters, protoICMPv6, b))
	return s.outputToNextHop(mldRouters, n)
}

// SendUDP sends payload from srcPort to dst. When the next hop's
// link-layer address is not known yet the datagram is held (one at a
// time), a Neighbor Solicitation is sent, and ErrNoNeighbor is returned;
// the datagram goes out when the neighbor answers.
func (s *Stack) SendUDP(srcPort uint16, dst netip.AddrPort, payload []byte) error {
	if len(payload) > MaxUDPPayload {
		return ErrTooLarge
	}
	to := dst.Addr().WithZone("")
	if _, err := s.nextHop(to); err != nil {
		return err
	}
	src := s.selectSrc(to)
	hl := s.hopLimit
	if to.IsLinkLocalUnicast() || to.IsLinkLocalMulticast() {
		hl = ndpHopLimit
	}
	n := udpHeaderLen + len(payload)
	b := s.ipPacketFrom(src, to, protoUDP, n, hl)
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dst.Port())
	binary.BigEndian.PutUint16(b[4:], uint16(n))
	b[6], b[7] = 0, 0
	copy(b[udpHeaderLen:], payload)
	c := checksum(src, to, protoUDP, b)
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
