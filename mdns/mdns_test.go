package mdns

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

type sent struct {
	dst netip.AddrPort
	msg []byte
}

type rr struct {
	name       string
	typ, class uint16
	ttl        uint32
	data       string // decoded: name for PTR, "port host" for SRV, joined TXT, address
}

func parse(t *testing.T, b []byte) (qd int, an, ar []rr) {
	t.Helper()
	qd = int(binary.BigEndian.Uint16(b[4:]))
	n := int(binary.BigEndian.Uint16(b[6:]))
	m := int(binary.BigEndian.Uint16(b[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, e, err := readName(b, off)
		if err != nil {
			t.Fatal(err)
		}
		off = e + 4
	}
	for i := 0; i < n+m; i++ {
		name, e, err := readName(b, off)
		if err != nil {
			t.Fatal(err)
		}
		r := rr{name: name, typ: binary.BigEndian.Uint16(b[e:]), class: binary.BigEndian.Uint16(b[e+2:]), ttl: binary.BigEndian.Uint32(b[e+4:])}
		l := int(binary.BigEndian.Uint16(b[e+8:]))
		d := b[e+10 : e+10+l]
		switch r.typ {
		case typePTR:
			r.data, _, _ = readName(b, e+10)
		case typeSRV:
			h, _, _ := readName(b, e+16)
			r.data = itoa(int(binary.BigEndian.Uint16(d[4:]))) + " " + h
		case typeTXT:
			var parts []string
			for len(d) > 0 {
				parts = append(parts, string(d[1:1+d[0]]))
				d = d[1+d[0]:]
			}
			r.data = strings.Join(parts, ",")
		case typeAAAA:
			r.data = netip.AddrFrom16([16]byte(d)).String()
		case typeA:
			r.data = netip.AddrFrom4([4]byte(d)).String()
		}
		off = e + 10 + l
		if i < n {
			an = append(an, r)
		} else {
			ar = append(ar, r)
		}
	}
	return qd, an, ar
}

func itoa(v int) string {
	s := ""
	for {
		s = string(rune('0'+v%10)) + s
		if v /= 10; v == 0 {
			return s
		}
	}
}

func query(id uint16, name string, typ, class uint16) []byte {
	w := &writer{}
	w.u16(id)
	w.u16(0)
	w.u16(1)
	w.u16(0)
	w.u16(0)
	w.u16(0)
	w.name(name)
	w.u16(typ)
	w.u16(class)
	return w.b
}

var addr = netip.MustParseAddr("fe80::32ed:a0ff:fec8:8734")

func newResponder() (*Responder, *[]sent) {
	var out []sent
	r := New("30EDA0C88734", []netip.Addr{addr}, func(dst netip.AddrPort, b []byte) error {
		out = append(out, sent{dst, append([]byte(nil), b...)})
		return nil
	})
	c := dnssd.Commissionable{Instance: 0x1122334455667788, Port: 5540, Discriminator: 3840, VendorID: 0xFFF1, ProductID: 0x8000, Mode: 1}
	r.Advertise([]dnssd.Service{c.Service()})
	return r, &out
}

func TestSubtypeQuery(t *testing.T) {
	r, out := newResponder()
	src := netip.AddrPortFrom(netip.MustParseAddr("fe80::1"), Port)
	r.HandlePacket(time.Now(), src, query(0, "_L3840._sub._matterc._udp.local", typePTR, classIN))
	if len(*out) != 1 || (*out)[0].dst != netip.AddrPortFrom(Group, Port) {
		t.Fatalf("sent %v", *out)
	}
	_, an, ar := parse(t, (*out)[0].msg)
	if len(an) != 1 || an[0].data != "1122334455667788._matterc._udp.local" {
		t.Fatalf("answers %+v", an)
	}
	var kinds []uint16
	for _, x := range ar {
		kinds = append(kinds, x.typ)
		switch x.typ {
		case typeSRV:
			if x.data != "5540 30EDA0C88734.local" || x.class != classIN|cacheFlush {
				t.Fatalf("SRV %+v", x)
			}
		case typeTXT:
			if !strings.Contains(x.data, "D=3840") || !strings.Contains(x.data, "VP=65521+32768") {
				t.Fatalf("TXT %+v", x)
			}
		case typeAAAA:
			if x.data != addr.String() || x.name != "30EDA0C88734.local" {
				t.Fatalf("AAAA %+v", x)
			}
		}
	}
	if len(kinds) != 3 {
		t.Fatalf("additional %v", kinds)
	}

	// Unknown names get no reply.
	r.HandlePacket(time.Now(), src, query(0, "_L1._sub._matterc._udp.local", typePTR, classIN))
	if len(*out) != 1 {
		t.Fatal("answered a foreign subtype")
	}
}

func TestLegacyAndQU(t *testing.T) {
	r, out := newResponder()
	legacy := netip.AddrPortFrom(netip.MustParseAddr("fe80::1"), 40000)
	r.HandlePacket(time.Now(), legacy, query(0x4242, "1122334455667788._matterc._udp.local", typeSRV, classIN))
	m := (*out)[0]
	if m.dst != legacy || binary.BigEndian.Uint16(m.msg) != 0x4242 {
		t.Fatalf("legacy reply to %v id %x", m.dst, m.msg[:2])
	}
	qd, an, _ := parse(t, m.msg)
	if qd != 1 || len(an) != 1 || an[0].ttl > 10 {
		t.Fatalf("legacy reply qd=%d an=%+v", qd, an)
	}
	qu := netip.AddrPortFrom(netip.MustParseAddr("fe80::2"), Port)
	r.HandlePacket(time.Now(), qu, query(0, "30eda0c88734.local", typeAAAA, classIN|unicastBit))
	if m := (*out)[1]; m.dst != qu {
		t.Fatalf("QU reply to %v", m.dst)
	}
}

func TestCompressedQuestion(t *testing.T) {
	r, out := newResponder()
	// Two questions; the second points into the first.
	q := query(0, "_matterc._udp.local", typePTR, classIN)
	binary.BigEndian.PutUint16(q[4:], 2)
	q = append(q, 3, '_', 'L', '9', 0xC0, 12, 0, typePTR, 0, classIN)
	r.HandlePacket(time.Now(), netip.AddrPortFrom(addr, Port), q)
	_, an, _ := parse(t, (*out)[0].msg)
	if len(an) != 1 {
		t.Fatalf("answers %+v", an)
	}
}

func TestAnnounceAndGoodbye(t *testing.T) {
	r, out := newResponder()
	now := time.Unix(100, 0)
	next := r.Poll(now)
	if len(*out) != 1 || next != now.Add(time.Second) {
		t.Fatalf("first announce: %d next %v", len(*out), next)
	}
	_, an, _ := parse(t, (*out)[0].msg)
	if len(an) != 1+4+1+1+1 { // type PTR, 4 subtype PTRs, SRV, TXT, AAAA
		t.Fatalf("announcement has %d records", len(an))
	}
	r.Poll(next)
	next = r.Poll(next.Add(2 * time.Second))
	if len(*out) != 3 || !next.IsZero() {
		t.Fatalf("announcements %d next %v", len(*out), next)
	}
	r.Advertise(nil)
	r.Poll(now)
	_, an, _ = parse(t, (*out)[3].msg)
	for _, x := range an {
		if x.ttl != 0 {
			t.Fatalf("goodbye with ttl %+v", x)
		}
	}
}

func FuzzHandlePacket(f *testing.F) {
	f.Add(query(0, "_L3840._sub._matterc._udp.local", typePTR, classIN))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _ := newResponder()
		r.HandlePacket(time.Now(), netip.AddrPortFrom(addr, Port), b)
	})
}

func TestDualStack(t *testing.T) {
	r, out := newResponder()
	v4 := netip.MustParseAddr("192.168.2.50")
	r.SetAddrs([]netip.Addr{addr, v4})

	// Announcements go to both groups with both address records.
	r.Poll(time.Now())
	if len(*out) != 2 || (*out)[0].dst != netip.AddrPortFrom(Group, Port) || (*out)[1].dst != netip.AddrPortFrom(Group4, Port) {
		t.Fatalf("announced to %v", *out)
	}
	_, an, _ := parse(t, (*out)[1].msg)
	var a, aaaa string
	for _, x := range an {
		switch x.typ {
		case typeA:
			a = x.data
		case typeAAAA:
			aaaa = x.data
		}
	}
	if a != v4.String() || aaaa != addr.String() {
		t.Fatalf("announcement A=%q AAAA=%q", a, aaaa)
	}

	// An IPv4 query is answered on the IPv4 group.
	*out = nil
	src := netip.AddrPortFrom(netip.MustParseAddr("192.168.2.14"), Port)
	r.HandlePacket(time.Now(), src, query(0, "_matterc._udp.local", typePTR, classIN))
	if len(*out) != 1 || (*out)[0].dst != netip.AddrPortFrom(Group4, Port) {
		t.Fatalf("replied to %v", *out)
	}
	_, _, ar := parse(t, (*out)[0].msg)
	n := 0
	for _, x := range ar {
		if x.typ == typeA || x.typ == typeAAAA {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("additional address records: %+v", ar)
	}

	// A host query for A gets only the IPv4 address.
	*out = nil
	r.HandlePacket(time.Now(), src, query(0, "30EDA0C88734.local", typeA, classIN))
	_, an, _ = parse(t, (*out)[0].msg)
	if len(an) != 1 || an[0].typ != typeA || an[0].data != v4.String() {
		t.Fatalf("A answer %+v", an)
	}

	// An IPv6-only responder does not announce over IPv4.
	*out = nil
	r.SetAddrs([]netip.Addr{addr})
	r.Poll(time.Now().Add(time.Hour))
	for _, m := range *out {
		if m.dst.Addr().Is4() {
			t.Fatal("announced over IPv4 without an IPv4 address")
		}
	}
}
