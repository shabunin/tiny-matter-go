package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/shabunin/tiny-matter-go/mdns"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

// discovery finds Matter nodes with one-shot mDNS queries sent from
// ephemeral ports, so it works next to a system responder (avahi) that
// owns port 5353. Some responders (matter.js) answer such queries by
// multicast rather than to the querier's port, so it also listens to the
// mDNS group, sharing the port with the system responder.
type discovery struct {
	mu     sync.Mutex
	q      *mdns.Querier
	c6, c4 *net.UDPConn
	mc     []*net.UDPConn // multicast listeners on port 5353
}

func newDiscovery() (*discovery, error) {
	d := &discovery{}
	var err6, err4 error
	d.c6, err6 = net.ListenUDP("udp6", &net.UDPAddr{})
	d.c4, err4 = net.ListenUDP("udp4", &net.UDPAddr{})
	if err6 != nil && err4 != nil {
		return nil, err6
	}
	d.q = mdns.NewQuerier(d.send)
	d.q.Zone = zoneOf
	d.mc = listenMulticast()
	for _, c := range d.conns() {
		go d.read(c)
	}
	return d, nil
}

func (d *discovery) conns() []*net.UDPConn {
	var out []*net.UDPConn
	for _, c := range append([]*net.UDPConn{d.c6, d.c4}, d.mc...) {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// listenMulticast joins the mDNS groups on the multicast interfaces.
// Failures only lose answers from responders that need it.
func listenMulticast() []*net.UDPConn {
	group4 := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	group6 := &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353}
	var out []*net.UDPConn
	ifs, _ := net.Interfaces()
	for i := range ifs {
		ifc := &ifs[i]
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		var has4, has6 bool
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if n.IP.To4() != nil {
					has4 = true
				} else {
					has6 = true
				}
			}
		}
		if has4 {
			if c, err := net.ListenMulticastUDP("udp4", ifc, group4); err == nil {
				out = append(out, c)
			}
		}
		if has6 {
			if c, err := net.ListenMulticastUDP("udp6", ifc, group6); err == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

func (d *discovery) close() {
	for _, c := range d.conns() {
		c.Close()
	}
}

func (d *discovery) read(c *net.UDPConn) {
	buf := make([]byte, 9000)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		d.mu.Lock()
		d.q.HandlePacket(time.Now(), from, buf[:n])
		d.mu.Unlock()
	}
}

// send transmits a query: over IPv6 on every multicast interface, over
// IPv4 on the default one.
func (d *discovery) send(dst netip.AddrPort, b []byte) error {
	if dst.Addr().Is4() {
		if d.c4 == nil {
			return errors.New("no IPv4")
		}
		_, err := d.c4.WriteToUDPAddrPort(b, dst)
		return err
	}
	if d.c6 == nil {
		return errors.New("no IPv6")
	}
	ifs, _ := net.Interfaces()
	var err error = errors.New("no IPv6 multicast interface")
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		to := netip.AddrPortFrom(dst.Addr().WithZone(ifc.Name), dst.Port())
		if _, e := d.c6.WriteToUDPAddrPort(b, to); e == nil {
			err = nil
		}
	}
	return err
}

// zoneOf names the interface on whose IPv4 network src is, for the
// link-local IPv6 addresses in its responses.
func zoneOf(src netip.AddrPort) string {
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.Contains(net.IP(src.Addr().AsSlice())) {
				return ifc.Name
			}
		}
	}
	return ""
}

// lookup sends queries (again at growing intervals) until done reports a
// result or ctx ends.
func (d *discovery) lookup(ctx context.Context, query func() error, done func(now time.Time) bool) error {
	next, gap := time.Now(), 250*time.Millisecond
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		now := time.Now()
		d.mu.Lock()
		ok := done(now)
		var err error
		if !ok && !now.Before(next) {
			err = query()
			next, gap = now.Add(gap), min(2*gap, 2*time.Second)
		}
		d.mu.Unlock()
		if ok {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// resolve completes an instance: SRV and TXT, then the host's addresses.
// It must be called with d.mu held, from a lookup's done function.
func (d *discovery) resolve(now time.Time, name string) (mdns.Instance, bool) {
	in, ok := d.q.Resolve(now, name)
	return in, ok && len(in.Addrs) > 0
}

// followUp asks for what an instance still lacks (d.mu held).
func (d *discovery) followUp(now time.Time, name string) error {
	in, ok := d.q.Resolve(now, name)
	if !ok {
		return d.q.Query(name, mdns.TypeSRV, mdns.TypeTXT)
	}
	return d.q.Query(in.Host, mdns.TypeAAAA, mdns.TypeA)
}

// operational finds a node of a fabric.
func (d *discovery) operational(ctx context.Context, cfid [8]byte, node uint64) (mdns.Instance, error) {
	name := fmt.Sprintf("%016X-%016X._matter._tcp.local", cfid, node)
	var in mdns.Instance
	err := d.lookup(ctx, func() error { return d.followUp(time.Now(), name) },
		func(now time.Time) (ok bool) {
			in, ok = d.resolve(now, name)
			return ok
		})
	return in, err
}

// Commissionable is a device in commissioning mode found on the network.
type Commissionable struct {
	mdns.Instance
	Discriminator       uint16
	VendorID, ProductID uint16
	Mode                int // commissioning mode: 1 basic, 2 enhanced
	DeviceType          uint32
	DeviceName          string
}

func commissionable(in mdns.Instance) Commissionable {
	c := Commissionable{Instance: in}
	if v, ok := in.TXTValue("D"); ok {
		n, _ := strconv.ParseUint(v, 10, 16)
		c.Discriminator = uint16(n)
	}
	if v, ok := in.TXTValue("CM"); ok {
		c.Mode, _ = strconv.Atoi(v)
	}
	if v, ok := in.TXTValue("VP"); ok {
		vid, pid, _ := bytes.Cut([]byte(v), []byte("+"))
		n, _ := strconv.ParseUint(string(vid), 10, 16)
		c.VendorID = uint16(n)
		n, _ = strconv.ParseUint(string(pid), 10, 16)
		c.ProductID = uint16(n)
	}
	if v, ok := in.TXTValue("DT"); ok {
		n, _ := strconv.ParseUint(v, 10, 32)
		c.DeviceType = uint32(n)
	}
	c.DeviceName, _ = in.TXTValue("DN")
	return c
}

// commissionable finds devices in commissioning mode: those matching the
// payload's discriminator, or all of them for a nil payload. Without a
// payload it collects answers until ctx ends.
func (d *discovery) commissionable(ctx context.Context, p *onboarding.Payload) ([]Commissionable, error) {
	service := "_matterc._udp.local"
	if p != nil {
		if p.ShortOnly {
			service = fmt.Sprintf("_S%d._sub._matterc._udp.local", p.ShortDiscriminator())
		} else {
			service = fmt.Sprintf("_L%d._sub._matterc._udp.local", p.Discriminator)
		}
	}
	var found []Commissionable
	err := d.lookup(ctx, func() error {
		now := time.Now()
		if err := d.q.Query(service, mdns.TypePTR); err != nil {
			return err
		}
		for _, name := range d.q.Browse(now, service) {
			if _, ok := d.resolve(now, name); !ok {
				d.followUp(now, name)
			}
		}
		return nil
	}, func(now time.Time) bool {
		found = found[:0]
		for _, name := range d.q.Browse(now, service) {
			if in, ok := d.resolve(now, name); ok {
				found = append(found, commissionable(in))
			}
		}
		return p != nil && len(found) > 0
	})
	if p == nil && errors.Is(err, context.DeadlineExceeded) {
		err = nil // a scan ends with its deadline
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found, err
}

// Discover lists the devices in commissioning mode that answer within
// the context's deadline.
func (c *Controller) Discover(ctx context.Context) ([]Commissionable, error) {
	if c.disc == nil {
		return nil, errors.New("controller: discovery disabled")
	}
	return c.disc.commissionable(ctx, nil)
}

// instanceAddrs returns an instance's addresses with its port, preferring
// routable IPv6, then link-local IPv6, then IPv4, then loopback.
func instanceAddrs(in mdns.Instance) []netip.AddrPort {
	rank := func(a netip.Addr) int {
		switch {
		case a.IsLoopback():
			return 3
		case a.Is6() && !a.IsLinkLocalUnicast():
			return 0
		case a.Is6():
			return 1
		}
		return 2
	}
	addrs := append([]netip.Addr(nil), in.Addrs...)
	sort.SliceStable(addrs, func(i, j int) bool { return rank(addrs[i]) < rank(addrs[j]) })
	out := make([]netip.AddrPort, len(addrs))
	for i, a := range addrs {
		out[i] = netip.AddrPortFrom(a, in.Port)
	}
	return out
}
