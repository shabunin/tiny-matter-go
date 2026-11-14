// Package mdns is a small multicast DNS responder (RFC 6762) with DNS-SD
// (RFC 6763) records, enough to publish Matter services from a device
// without a full mDNS implementation. It answers PTR, SRV, TXT, A and AAAA
// questions for its own names over IPv6 and IPv4, announces services when
// they change and
// sends goodbyes for removed ones. It does not probe for conflicts or
// cache other hosts' records.
package mdns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

// Port is the mDNS UDP port.
const Port = 5353

// Group is the IPv6 mDNS multicast group.
var Group = netip.MustParseAddr("ff02::fb")

// Group4 is the IPv4 mDNS multicast group.
var Group4 = netip.MustParseAddr("224.0.0.251")

const (
	typeA    = 1
	typePTR  = 12
	typeTXT  = 16
	typeAAAA = 28
	typeSRV  = 33
	typeANY  = 255

	classIN    = 1
	cacheFlush = 0x8000
	unicastBit = 0x8000

	ttlHost  = 120  // SRV, AAAA (RFC 6762 section 10)
	ttlOther = 4500 // PTR, TXT

	maxPacket = 1232
	announces = 3
)

var errMalformed = errors.New("mdns: malformed message")

// Responder publishes DNS-SD services for one host.
type Responder struct {
	host  string // "<host>.local"
	addrs []netip.Addr
	send  func(dst netip.AddrPort, b []byte) error

	services []dnssd.Service
	goodbye  []dnssd.Service

	announceLeft int
	announceAt   time.Time
	now          time.Time
	buf          []byte
}

// New returns a responder for host (a label such as "30EDA0C88734",
// published as host.local) reachable at addrs (IPv6 and IPv4). send
// transmits one UDP datagram from port 5353, over IPv4 or IPv6 by dst.
// Announcements go to the group of each address family in addrs.
func New(host string, addrs []netip.Addr, send func(dst netip.AddrPort, b []byte) error) *Responder {
	return &Responder{host: host + ".local", addrs: addrs, send: send, buf: make([]byte, 0, maxPacket)}
}

// SetAddrs replaces the host addresses, for example when DHCP assigns an
// IPv4 address, and announces them again.
func (r *Responder) SetAddrs(addrs []netip.Addr) {
	r.addrs = append(r.addrs[:0:0], addrs...)
	r.Reannounce()
}

// groups returns the multicast destinations for announcements.
func (r *Responder) groups() []netip.AddrPort {
	var g []netip.AddrPort
	has := func(v4 bool) bool {
		for _, a := range r.addrs {
			if a.Is4() == v4 {
				return true
			}
		}
		return false
	}
	if has(false) {
		g = append(g, netip.AddrPortFrom(Group, Port))
	}
	if has(true) {
		g = append(g, netip.AddrPortFrom(Group4, Port))
	}
	return g
}

// Advertise replaces the published services (dnssd.Advertiser). Changes
// are announced from Poll.
func (r *Responder) Advertise(svcs []dnssd.Service) {
	for _, old := range r.services {
		if !containsService(svcs, old) {
			r.goodbye = append(r.goodbye, old)
		}
	}
	r.services = append(r.services[:0:0], svcs...)
	r.announceLeft, r.announceAt = announces, time.Time{}
}

// Reannounce announces all services again, for example after the network
// link comes back.
func (r *Responder) Reannounce() { r.announceLeft, r.announceAt = announces, time.Time{} }

func containsService(list []dnssd.Service, s dnssd.Service) bool {
	for _, x := range list {
		if x.Instance == s.Instance && x.Type == s.Type {
			return true
		}
	}
	return false
}

// Poll sends due announcements and returns when it next needs to run (zero
// when idle).
func (r *Responder) Poll(now time.Time) time.Time {
	r.now = now
	if len(r.goodbye) > 0 {
		for _, s := range r.goodbye {
			r.announce(s, 0)
		}
		r.goodbye = r.goodbye[:0]
	}
	if r.announceLeft == 0 {
		return time.Time{}
	}
	if !r.announceAt.IsZero() && now.Before(r.announceAt) {
		return r.announceAt
	}
	for _, s := range r.services {
		r.announce(s, 1)
	}
	r.announceLeft--
	// RFC 6762 8.3: at least one second apart, doubling.
	r.announceAt = now.Add(time.Second << (announces - 1 - r.announceLeft))
	if r.announceLeft == 0 {
		return time.Time{}
	}
	return r.announceAt
}

// announce multicasts every record of s; ttlScale 0 sends a goodbye.
func (r *Responder) announce(s dnssd.Service, ttlScale uint32) {
	w := r.message(0, 0)
	n := 0
	inst := instanceName(s)
	n += w.ptr(serviceName(s), inst, ttlOther*ttlScale)
	for _, st := range s.Subtypes {
		n += w.ptr(st+"._sub."+serviceName(s), inst, ttlOther*ttlScale)
	}
	n += w.srv(s, r.host, ttlHost*ttlScale)
	n += w.txt(s, ttlOther*ttlScale)
	if ttlScale != 0 {
		n += r.addrRecords(w, ttlHost, typeANY)
	}
	for _, g := range r.groups() {
		r.flush(w, 0, n, 0, g)
	}
}

func serviceName(s dnssd.Service) string  { return s.Type + ".local" }
func instanceName(s dnssd.Service) string { return s.Instance + "." + s.Type + ".local" }

// addrRecords writes the host's A and AAAA records (those of type want, or
// both for typeANY).
func (r *Responder) addrRecords(w *writer, ttl uint32, want uint16) int {
	n := 0
	for _, a := range r.addrs {
		if a.Is4() && (want == typeA || want == typeANY) {
			w.record(r.host, typeA, classIN|cacheFlush, ttl)
			b := a.As4()
			w.rdata(b[:])
			n++
		} else if a.Is6() && (want == typeAAAA || want == typeANY) {
			w.record(r.host, typeAAAA, classIN|cacheFlush, ttl)
			b := a.As16()
			w.rdata(b[:])
			n++
		}
	}
	return n
}

// HandlePacket processes a datagram received on port 5353 (or a legacy
// unicast query sent to it).
func (r *Responder) HandlePacket(now time.Time, src netip.AddrPort, payload []byte) {
	r.now = now
	if len(payload) < 12 {
		return
	}
	id := binary.BigEndian.Uint16(payload)
	flags := binary.BigEndian.Uint16(payload[2:])
	if flags&0x8000 != 0 || flags&0x7800 != 0 {
		return // a response, or not a standard query
	}
	qd := int(binary.BigEndian.Uint16(payload[4:]))
	off := 12
	legacy := src.Port() != Port
	unicast := legacy

	// Collect answers into a fresh message; additional records follow.
	w := r.message(id, 0x8400)
	var questions []question
	for i := 0; i < qd; i++ {
		name, n, err := readName(payload, off)
		if err != nil || n+4 > len(payload) {
			return
		}
		q := question{name: name, typ: binary.BigEndian.Uint16(payload[n:]), class: binary.BigEndian.Uint16(payload[n+2:])}
		off = n + 4
		if q.class&unicastBit != 0 {
			unicast = true
		}
		questions = append(questions, q)
	}
	if legacy {
		// Legacy unicast responses repeat the question (RFC 6762 6.7).
		for _, q := range questions {
			w.name(q.name)
			w.u16(q.typ)
			w.u16(q.class &^ unicastBit)
		}
	}
	ttlCap := uint32(0)
	if legacy {
		ttlCap = 10
	}
	w.ttlCap = ttlCap
	an, ar := 0, 0
	var addSrv []dnssd.Service
	var addHost bool
	for _, q := range questions {
		a, srv, host := r.answer(w, q)
		an += a
		addSrv = append(addSrv, srv...)
		addHost = addHost || host
	}
	if an == 0 {
		return
	}
	for _, s := range addSrv {
		ar += w.srv(s, r.host, ttlHost)
		ar += w.txt(s, ttlOther)
	}
	if addHost || len(addSrv) > 0 {
		ar += r.addrRecords(w, ttlHost, typeANY)
	}
	qdOut := 0
	if legacy {
		qdOut = len(questions)
	}
	dst := netip.AddrPortFrom(Group, Port)
	if src.Addr().Unmap().Is4() {
		dst = netip.AddrPortFrom(Group4, Port) // answer on the query's family
	}
	if unicast {
		dst = src
	}
	r.flush(w, qdOut, an, ar, dst)
}

type question struct {
	name       string
	typ, class uint16
}

// answer writes the answers to q and returns their count, the services
// whose SRV/TXT belong in the additional section, and whether the host
// address does.
func (r *Responder) answer(w *writer, q question) (n int, additional []dnssd.Service, host bool) {
	match := func(t uint16) bool { return q.typ == t || q.typ == typeANY }
	if strings.EqualFold(q.name, "_services._dns-sd._udp.local") && match(typePTR) {
		seen := map[string]bool{}
		for _, s := range r.services {
			if !seen[s.Type] {
				seen[s.Type] = true
				n += w.ptr(q.name, serviceName(s), ttlOther)
			}
		}
		return n, nil, false
	}
	if strings.EqualFold(q.name, r.host) {
		switch {
		case q.typ == typeANY:
			return r.addrRecords(w, ttlHost, typeANY), nil, false
		case q.typ == typeA || q.typ == typeAAAA:
			return r.addrRecords(w, ttlHost, q.typ), nil, false
		}
		return 0, nil, false
	}
	for _, s := range r.services {
		inst := instanceName(s)
		switch {
		case strings.EqualFold(q.name, inst):
			if match(typeSRV) {
				n += w.srv(s, r.host, ttlHost)
				host = true
			}
			if match(typeTXT) {
				n += w.txt(s, ttlOther)
			}
		case match(typePTR) && strings.EqualFold(q.name, serviceName(s)):
			n += w.ptr(q.name, inst, ttlOther)
			additional = append(additional, s)
		case match(typePTR) && isSubtypeOf(q.name, s):
			n += w.ptr(q.name, inst, ttlOther)
			additional = append(additional, s)
		}
	}
	return n, additional, host
}

func isSubtypeOf(name string, s dnssd.Service) bool {
	for _, st := range s.Subtypes {
		if strings.EqualFold(name, st+"._sub."+serviceName(s)) {
			return true
		}
	}
	return false
}

// flush fills in the header counts and sends the message.
func (r *Responder) flush(w *writer, qd, an, ar int, dst netip.AddrPort) {
	if w.overflow || an == 0 {
		return
	}
	b := w.b
	binary.BigEndian.PutUint16(b[4:], uint16(qd))
	binary.BigEndian.PutUint16(b[6:], uint16(an))
	binary.BigEndian.PutUint16(b[10:], uint16(ar))
	r.send(dst, b)
}

// message starts a DNS message in the responder's buffer.
func (r *Responder) message(id, flags uint16) *writer {
	w := &writer{b: r.buf[:0]}
	if flags == 0 {
		flags = 0x8400 // response, authoritative
	}
	w.u16(id)
	w.u16(flags)
	w.u16(0)
	w.u16(0)
	w.u16(0)
	w.u16(0)
	return w
}

type writer struct {
	b        []byte
	ttlCap   uint32
	overflow bool
}

func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }

func (w *writer) name(n string) {
	for _, l := range strings.Split(n, ".") {
		if l == "" {
			continue
		}
		if len(l) > 63 {
			l = l[:63]
		}
		w.b = append(w.b, byte(len(l)))
		w.b = append(w.b, l...)
	}
	w.b = append(w.b, 0)
}

func (w *writer) record(name string, typ, class uint16, ttl uint32) {
	if w.ttlCap != 0 && ttl > w.ttlCap {
		ttl = w.ttlCap
	}
	w.name(name)
	w.u16(typ)
	w.u16(class)
	w.b = binary.BigEndian.AppendUint32(w.b, ttl)
}

// rdata appends a length-prefixed RDATA.
func (w *writer) rdata(d []byte) {
	w.u16(uint16(len(d)))
	w.b = append(w.b, d...)
	w.check()
}

func (w *writer) check() {
	if len(w.b) > maxPacket {
		w.overflow = true
	}
}

// beginRdata reserves the RDATA length and returns its offset.
func (w *writer) beginRdata() int {
	w.u16(0)
	return len(w.b)
}

func (w *writer) endRdata(start int) {
	binary.BigEndian.PutUint16(w.b[start-2:], uint16(len(w.b)-start))
	w.check()
}

func (w *writer) ptr(name, target string, ttl uint32) int {
	w.record(name, typePTR, classIN, ttl)
	s := w.beginRdata()
	w.name(target)
	w.endRdata(s)
	return 1
}

func (w *writer) srv(s dnssd.Service, host string, ttl uint32) int {
	w.record(instanceName(s), typeSRV, classIN|cacheFlush, ttl)
	st := w.beginRdata()
	w.u16(0) // priority
	w.u16(0) // weight
	w.u16(s.Port)
	w.name(host)
	w.endRdata(st)
	return 1
}

func (w *writer) txt(s dnssd.Service, ttl uint32) int {
	w.record(instanceName(s), typeTXT, classIN|cacheFlush, ttl)
	st := w.beginRdata()
	if len(s.TXT) == 0 {
		w.b = append(w.b, 0)
	}
	for _, t := range s.TXT {
		if len(t) > 255 {
			t = t[:255]
		}
		w.b = append(w.b, byte(len(t)))
		w.b = append(w.b, t...)
	}
	w.endRdata(st)
	return 1
}

// readName decodes a possibly compressed name at off and returns it in
// dotted form with the offset just past it.
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errMalformed
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return sb.String(), end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errMalformed
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 16 {
				return "", 0, errMalformed
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errMalformed
		default:
			if off+1+l > len(msg) || sb.Len()+l > 255 {
				return "", 0, errMalformed
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(msg[off+1 : off+1+l])
			off += 1 + l
		}
	}
}
