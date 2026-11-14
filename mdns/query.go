package mdns

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"time"
)

// Querier looks up DNS-SD services with one-shot mDNS queries (RFC 6762
// section 5.1): it sends questions from an ordinary port, responders
// answer it directly, and it keeps the answers until their TTLs run out.
// It is driven like the Responder: Query sends, HandlePacket takes the
// responses, and Browse and Resolve read what has arrived.
type Querier struct {
	send func(dst netip.AddrPort, b []byte) error
	// Zone, if set, names the zone (interface) of link-local IPv6
	// addresses in a response from src that arrived over IPv4.
	Zone func(src netip.AddrPort) string

	records []cached
	id      uint16
}

// cached is a cached resource record.
type cached struct {
	name    string // lower case, without the trailing dot
	typ     uint16
	expires time.Time
	target  string     // PTR, SRV
	port    uint16     // SRV
	txt     []string   // TXT
	addr    netip.Addr // A, AAAA
}

// NewQuerier returns a querier that sends queries with send, which
// transmits one UDP datagram to the IPv6 or IPv4 mDNS group by dst.
func NewQuerier(send func(dst netip.AddrPort, b []byte) error) *Querier {
	return &Querier{send: send}
}

// Instance is a resolved DNS-SD service instance.
type Instance struct {
	Name  string // instance label, such as "4F2E8BA3C1D0E6F7-0000000000000001"
	Host  string
	Port  uint16
	TXT   []string
	Addrs []netip.Addr // link-local IPv6 addresses carry their zone
}

// TXTValue returns the value of key in the instance's TXT record.
func (in *Instance) TXTValue(key string) (string, bool) {
	for _, t := range in.TXT {
		if k, v, ok := strings.Cut(t, "="); ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// Query asks for name (such as "_matterc._udp.local" or an instance name)
// with the given record types, over IPv6 and IPv4.
func (q *Querier) Query(name string, types ...uint16) error {
	q.id++
	w := &writer{b: make([]byte, 0, 512)}
	w.u16(q.id)
	w.u16(0) // standard query
	w.u16(uint16(len(types)))
	w.u16(0)
	w.u16(0)
	w.u16(0)
	for _, t := range types {
		w.name(name)
		w.u16(t)
		w.u16(classIN)
	}
	err6 := q.send(netip.AddrPortFrom(Group, Port), w.b)
	err4 := q.send(netip.AddrPortFrom(Group4, Port), w.b)
	if err6 != nil && err4 != nil {
		return err6
	}
	return nil
}

// Record types for Query.
const (
	TypeA    = typeA
	TypePTR  = typePTR
	TypeTXT  = typeTXT
	TypeAAAA = typeAAAA
	TypeSRV  = typeSRV
	TypeANY  = typeANY
)

// HandlePacket records the answers of a response received from src.
func (q *Querier) HandlePacket(now time.Time, src netip.AddrPort, payload []byte) {
	if len(payload) < 12 {
		return
	}
	flags := binary.BigEndian.Uint16(payload[2:])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x000F != 0 {
		return // not a successful standard response
	}
	qd := int(binary.BigEndian.Uint16(payload[4:]))
	n := int(binary.BigEndian.Uint16(payload[6:])) + int(binary.BigEndian.Uint16(payload[8:])) +
		int(binary.BigEndian.Uint16(payload[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, end, err := readName(payload, off)
		if err != nil || end+4 > len(payload) {
			return
		}
		off = end + 4
	}
	zone := ""
	if a := src.Addr(); a.Is6() && !a.Is4In6() {
		zone = a.Zone()
	} else if q.Zone != nil {
		zone = q.Zone(src)
	}
	for i := 0; i < n; i++ {
		name, end, err := readName(payload, off)
		if err != nil || end+10 > len(payload) {
			return
		}
		typ := binary.BigEndian.Uint16(payload[end:])
		ttl := binary.BigEndian.Uint32(payload[end+4:])
		rdlen := int(binary.BigEndian.Uint16(payload[end+8:]))
		rd := end + 10
		if rd+rdlen > len(payload) {
			return
		}
		off = rd + rdlen
		r := cached{name: strings.ToLower(name), typ: typ, expires: now.Add(time.Duration(ttl) * time.Second)}
		switch typ {
		case typePTR:
			if r.target, _, err = readName(payload, rd); err != nil {
				continue
			}
		case typeSRV:
			if rdlen < 7 {
				continue
			}
			r.port = binary.BigEndian.Uint16(payload[rd+4:])
			if r.target, _, err = readName(payload, rd+6); err != nil {
				continue
			}
		case typeTXT:
			for p := rd; p < rd+rdlen; {
				l := int(payload[p])
				if p+1+l > rd+rdlen {
					break
				}
				if l > 0 {
					r.txt = append(r.txt, string(payload[p+1:p+1+l]))
				}
				p += 1 + l
			}
		case typeA:
			if rdlen != 4 {
				continue
			}
			r.addr = netip.AddrFrom4([4]byte(payload[rd : rd+4]))
		case typeAAAA:
			if rdlen != 16 {
				continue
			}
			r.addr = netip.AddrFrom16([16]byte(payload[rd : rd+16]))
			if r.addr.IsLinkLocalUnicast() && zone != "" {
				r.addr = r.addr.WithZone(zone)
			}
		default:
			continue
		}
		q.add(now, r, ttl == 0)
	}
}

// add caches a record, replacing an equal one; a zero TTL (a goodbye)
// removes it.
func (q *Querier) add(now time.Time, r cached, goodbye bool) {
	recs := q.records[:0]
	for _, o := range q.records {
		same := o.name == r.name && o.typ == r.typ && o.target == r.target && o.port == r.port &&
			o.addr == r.addr && strings.Join(o.txt, "\x00") == strings.Join(r.txt, "\x00")
		if !same && now.Before(o.expires) {
			recs = append(recs, o)
		}
	}
	q.records = recs
	if !goodbye {
		q.records = append(q.records, r)
	}
}

func (q *Querier) find(now time.Time, name string, typ uint16, f func(r *cached)) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for i := range q.records {
		r := &q.records[i]
		if r.name == name && r.typ == typ && now.Before(r.expires) {
			f(r)
		}
	}
}

// Browse returns the names of the instances of a service type, such as
// "_matterc._udp.local" or "_L3840._sub._matterc._udp.local", seen so far.
func (q *Querier) Browse(now time.Time, service string) []string {
	var out []string
	q.find(now, service, typePTR, func(r *cached) {
		for _, o := range out {
			if o == r.target {
				return
			}
		}
		out = append(out, r.target)
	})
	return out
}

// Resolve returns what is known of a service instance (its full name,
// such as "ABCD._matterc._udp.local"): ok once its SRV record has
// arrived; addresses may still be missing.
func (q *Querier) Resolve(now time.Time, instance string) (in Instance, ok bool) {
	in.Name, _, _ = strings.Cut(instance, ".")
	q.find(now, instance, typeSRV, func(r *cached) {
		in.Host, in.Port, ok = r.target, r.port, true
	})
	q.find(now, instance, typeTXT, func(r *cached) { in.TXT = r.txt })
	if ok {
		in.Addrs = q.Addrs(now, in.Host)
	}
	return in, ok
}

// Addrs returns the usable addresses known for a host name: IPv6 first,
// and link-local IPv6 addresses only with a zone.
func (q *Querier) Addrs(now time.Time, host string) []netip.Addr {
	var out []netip.Addr
	for _, typ := range []uint16{typeAAAA, typeA} {
		q.find(now, host, typ, func(r *cached) {
			a := r.addr
			if a.IsLinkLocalUnicast() && a.Is6() && a.Zone() == "" {
				return // heard over IPv4: the interface is unknown
			}
			for _, o := range out {
				if o == a {
					return
				}
			}
			out = append(out, a)
		})
	}
	return out
}
