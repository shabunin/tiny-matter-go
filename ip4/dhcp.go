package ip4

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// DHCP client (RFC 2131): DISCOVER, OFFER, REQUEST, ACK; renewal at T1
// (unicast to the server), rebinding at T2 (broadcast), and back to the
// start when the lease expires or the server NAKs.

const (
	dhcpServerPort = 67
	dhcpClientPort = 68
	dhcpHeaderLen  = 236
	dhcpMagic      = 0x63825363

	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6

	optSubnetMask   = 1
	optRouter       = 3
	optHostName     = 12
	optRequestedIP  = 50
	optLeaseTime    = 51
	optMessageType  = 53
	optServerID     = 54
	optParamRequest = 55
	optRenewalTime  = 58
	optRebindTime   = 59
	optClientID     = 61
	optEnd          = 255

	dhcpMinRetry     = 4 * time.Second
	dhcpMaxRetry     = 32 * time.Second
	dhcpRequestTries = 4
	defaultLease     = time.Hour
)

type dhcpState uint8

const (
	dhcpInit dhcpState = iota
	dhcpSelecting
	dhcpRequesting
	dhcpBound
	dhcpRenewing
	dhcpRebinding
)

type dhcpClient struct {
	state    dhcpState
	host     string
	xid      uint32
	nextAt   time.Time // next transmission or state timer
	retry    time.Duration
	tries    int
	onChange func(p netip.Prefix, gateway netip.Addr)

	offered, server netip.Addr
	boundAt         time.Time
	t1, t2, lease   time.Duration
}

// StartDHCP configures the address with DHCP from the next Poll on.
// hostname (optional) is sent to the server. onChange, if set, is called
// with the new subnet and gateway whenever the lease is bound or changes,
// and with a zero prefix when the address is lost.
func (s *Stack) StartDHCP(hostname string, onChange func(p netip.Prefix, gateway netip.Addr)) {
	s.dhcp = &dhcpClient{host: hostname, onChange: onChange}
}

// RenewDHCP asks the server to confirm the lease now, for example after
// the link reconnects (possibly to another network).
func (s *Stack) RenewDHCP() {
	c := s.dhcp
	if c == nil {
		return
	}
	if c.state >= dhcpBound {
		c.state, c.nextAt, c.retry = dhcpRebinding, time.Time{}, dhcpMinRetry
	} else {
		c.state, c.nextAt = dhcpInit, time.Time{}
	}
}

// Bound reports whether a DHCP lease is held.
func (s *Stack) Bound() bool { return s.dhcp != nil && s.dhcp.state >= dhcpBound }

func (c *dhcpClient) poll(s *Stack, now time.Time) time.Time {
	if !c.nextAt.IsZero() && now.Before(c.nextAt) {
		return c.nextAt
	}
	switch c.state {
	case dhcpInit:
		c.xid = c.xid*1103515245 + uint32(now.UnixNano()) ^ binary.BigEndian.Uint32(s.mac[2:])
		c.state, c.retry, c.tries = dhcpSelecting, dhcpMinRetry, 0
		c.send(s, dhcpDiscover)
		c.nextAt = now.Add(c.retry)
	case dhcpSelecting:
		c.backoff(now)
		c.send(s, dhcpDiscover)
	case dhcpRequesting:
		if c.tries++; c.tries >= dhcpRequestTries {
			c.state, c.nextAt = dhcpInit, time.Time{}
			return now
		}
		c.backoff(now)
		c.send(s, dhcpRequest)
	case dhcpBound:
		c.state, c.retry = dhcpRenewing, dhcpMinRetry
		fallthrough
	case dhcpRenewing, dhcpRebinding:
		if !now.Before(c.boundAt.Add(c.lease)) {
			c.expire(s)
			return now
		}
		if c.state == dhcpRenewing && !now.Before(c.boundAt.Add(c.t2)) {
			c.state, c.retry = dhcpRebinding, dhcpMinRetry
		}
		c.send(s, dhcpRequest)
		// RFC 2131 4.4.5: retry at half the remaining time, at least 60 s.
		end := c.boundAt.Add(c.t2)
		if c.state == dhcpRebinding {
			end = c.boundAt.Add(c.lease)
		}
		wait := end.Sub(now) / 2
		if wait < time.Minute {
			wait = time.Minute
		}
		if c.retry < wait { // after a reconnect, ask quickly first
			wait = c.retry
			c.retry *= 2
		}
		c.nextAt = now.Add(wait)
		if t := end; t.Before(c.nextAt) {
			c.nextAt = t
		}
	}
	return c.nextAt
}

func (c *dhcpClient) backoff(now time.Time) {
	if c.retry < dhcpMaxRetry {
		c.retry *= 2
	}
	c.nextAt = now.Add(c.retry)
}

func (c *dhcpClient) expire(s *Stack) {
	s.SetAddr(netip.Prefix{}, netip.Addr{})
	c.state, c.nextAt = dhcpInit, time.Time{}
	if c.onChange != nil {
		c.onChange(netip.Prefix{}, netip.Addr{})
	}
}

func (c *dhcpClient) send(s *Stack, typ uint8) {
	var m [dhcpHeaderLen + 4 + 64]byte
	b := m[:]
	b[0], b[1], b[2] = 1, 1, 6 // BOOTREQUEST, Ethernet
	binary.BigEndian.PutUint32(b[4:], c.xid)
	renewing := typ == dhcpRequest && c.state >= dhcpBound
	if !renewing {
		b[10] = 0x80 // broadcast replies: we cannot take unicast yet
	} else {
		a := s.addr.As4()
		copy(b[12:16], a[:]) // ciaddr
	}
	copy(b[28:34], s.mac[:])
	binary.BigEndian.PutUint32(b[dhcpHeaderLen:], dhcpMagic)
	o := b[:dhcpHeaderLen+4]
	o = append(o, optMessageType, 1, typ)
	o = append(o, optClientID, 7, 1)
	o = append(o, s.mac[:]...)
	if typ == dhcpRequest && !renewing {
		a, sv := c.offered.As4(), c.server.As4()
		o = append(o, optRequestedIP, 4)
		o = append(o, a[:]...)
		o = append(o, optServerID, 4)
		o = append(o, sv[:]...)
	}
	if h := c.host; h != "" {
		if len(h) > 32 {
			h = h[:32]
		}
		o = append(o, optHostName, byte(len(h)))
		o = append(o, h...)
	}
	o = append(o, optParamRequest, 5, optSubnetMask, optRouter, optLeaseTime, optRenewalTime, optRebindTime)
	o = append(o, optEnd)
	for len(o) < 300 { // BOOTP minimum, which some servers still expect
		o = append(o, 0)
	}
	dst := netip.AddrPortFrom(Broadcast, dhcpServerPort)
	if renewing && c.state == dhcpRenewing && c.server.IsValid() {
		dst = netip.AddrPortFrom(c.server, dhcpServerPort)
	}
	s.sendUDP(dhcpClientPort, dst, o)
}

type dhcpReply struct {
	typ              uint8
	yiaddr           netip.Addr
	server, router   netip.Addr
	maskBits         int
	lease, t1, t2    uint32
	hasLease, hasT12 [2]bool
}

func (c *dhcpClient) parse(s *Stack, b []byte) (r dhcpReply, ok bool) {
	if len(b) < dhcpHeaderLen+4 || b[0] != 2 || binary.BigEndian.Uint32(b[4:]) != c.xid ||
		[6]byte(b[28:34]) != s.mac || binary.BigEndian.Uint32(b[dhcpHeaderLen:]) != dhcpMagic {
		return r, false
	}
	r.yiaddr = netip.AddrFrom4([4]byte(b[16:20]))
	r.maskBits = -1
	opts := b[dhcpHeaderLen+4:]
	for len(opts) > 0 {
		code := opts[0]
		if code == 0 {
			opts = opts[1:]
			continue
		}
		if code == optEnd || len(opts) < 2 || int(opts[1])+2 > len(opts) {
			break
		}
		v := opts[2 : 2+int(opts[1])]
		opts = opts[2+len(v):]
		switch {
		case code == optMessageType && len(v) == 1:
			r.typ = v[0]
		case code == optServerID && len(v) == 4:
			r.server = netip.AddrFrom4([4]byte(v))
		case code == optRouter && len(v) >= 4:
			r.router = netip.AddrFrom4([4]byte(v[:4]))
		case code == optSubnetMask && len(v) == 4:
			m := binary.BigEndian.Uint32(v)
			bits := 0
			for m&0x80000000 != 0 {
				bits++
				m <<= 1
			}
			if m == 0 { // contiguous
				r.maskBits = bits
			}
		case code == optLeaseTime && len(v) == 4:
			r.lease, r.hasLease[0] = binary.BigEndian.Uint32(v), true
		case code == optRenewalTime && len(v) == 4:
			r.t1, r.hasT12[0] = binary.BigEndian.Uint32(v), true
		case code == optRebindTime && len(v) == 4:
			r.t2, r.hasT12[1] = binary.BigEndian.Uint32(v), true
		}
	}
	return r, r.typ != 0
}

func (c *dhcpClient) handle(s *Stack, b []byte) {
	r, ok := c.parse(s, b)
	if !ok {
		return
	}
	switch {
	case c.state == dhcpSelecting && r.typ == dhcpOffer:
		if !r.server.IsValid() || !r.yiaddr.IsGlobalUnicast() && !r.yiaddr.IsPrivate() {
			return
		}
		c.offered, c.server = r.yiaddr, r.server
		c.state, c.retry, c.tries = dhcpRequesting, dhcpMinRetry, 0
		c.send(s, dhcpRequest)
		c.nextAt = s.now.Add(c.retry)
	case c.state == dhcpRequesting || c.state >= dhcpBound:
		if r.typ == dhcpNak {
			if c.state >= dhcpBound {
				c.expire(s)
			} else {
				c.state, c.nextAt = dhcpInit, time.Time{}
			}
			return
		}
		if r.typ != dhcpAck || !r.yiaddr.IsValid() || r.yiaddr.IsUnspecified() {
			return
		}
		c.bind(s, r)
	}
}

func (c *dhcpClient) bind(s *Stack, r dhcpReply) {
	c.lease = defaultLease
	if r.hasLease[0] {
		c.lease = time.Duration(r.lease) * time.Second
		if r.lease == 0xffffffff {
			c.lease = 1 << 62 // infinite
		}
	}
	c.t1, c.t2 = c.lease/2, c.lease*7/8
	if r.hasT12[0] && time.Duration(r.t1)*time.Second < c.lease {
		c.t1 = time.Duration(r.t1) * time.Second
	}
	if r.hasT12[1] && time.Duration(r.t2)*time.Second < c.lease {
		c.t2 = time.Duration(r.t2) * time.Second
	}
	if c.t1 > c.t2 {
		c.t1 = c.t2
	}
	if r.server.IsValid() {
		c.server = r.server
	}
	c.boundAt = s.now
	c.state, c.nextAt = dhcpBound, s.now.Add(c.t1)
	bits := r.maskBits
	if bits < 0 {
		bits = 24
	}
	p := netip.PrefixFrom(r.yiaddr, bits)
	changed := p != netip.PrefixFrom(s.addr, s.prefix.Bits()) || r.router != s.gateway
	s.SetAddr(p, r.router)
	if changed && c.onChange != nil {
		c.onChange(p, r.router)
	}
}
