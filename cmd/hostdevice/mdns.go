package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shabunin/tiny-matter-go/dnssd"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/mdns"
)

// hostMDNS combines DNS-SD advertising and operational node resolution.
type hostMDNS struct {
	advertiser dnssd.Advertiser
	resolve    func(now time.Time, cfid [8]byte, nodeID uint64) (exchange.Addr, bool)
	poll       func(now time.Time) time.Time
	close      func()
}

// selectMDNSBackend resolves "auto" to "avahi" on Linux when avahi-publish
// is installed, and to "builtin" everywhere else.
func selectMDNSBackend(mode string) (string, error) {
	switch mode {
	case "auto":
		if runtime.GOOS == "linux" {
			if _, err := exec.LookPath("avahi-publish"); err == nil {
				return "avahi", nil
			}
		}
		return "builtin", nil
	case "builtin", "avahi":
		return mode, nil
	default:
		return "", fmt.Errorf("unknown -mdns-backend %q (want auto, builtin or avahi)", mode)
	}
}

func startHostMDNS(mode string) (*hostMDNS, error) {
	backend, err := selectMDNSBackend(mode)
	if err != nil {
		return nil, err
	}
	if backend == "avahi" {
		adv := newAvahiAdvertiser()
		res := &avahiResolver{}
		return &hostMDNS{
			advertiser: adv,
			resolve:    res.Resolve,
			poll:       func(time.Time) time.Time { return time.Time{} },
			close:      func() { adv.Advertise(nil) },
		}, nil
	}
	b, err := newBuiltinMDNS()
	if err != nil {
		return nil, err
	}
	log.Printf("mDNS: using built-in responder (%s.local, %d address(es))", b.host, len(b.addrs))
	return &hostMDNS{
		advertiser: b,
		resolve:    b.Resolve,
		poll:       b.Poll,
		close:      b.Close,
	}, nil
}

// builtinMDNS runs the stack's own pure-Go mdns.Responder and
// mdns.NodeResolver over host UDP sockets, with no external daemon.
type builtinMDNS struct {
	host   string
	addrs  []netip.Addr
	c6, c4 *net.UDPConn
	mc     []*net.UDPConn

	mu     sync.Mutex
	resp   *mdns.Responder
	nodes  *mdns.NodeResolver
	closed bool
}

func newBuiltinMDNS() (*builtinMDNS, error) {
	host := sanitizeHostLabel(hostnameOrDefault())
	addrs := hostAddrs()
	if len(addrs) == 0 {
		addrs = []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	}
	b := &builtinMDNS{host: host, addrs: addrs}
	var err6, err4 error
	b.c6, err6 = net.ListenUDP("udp6", &net.UDPAddr{})
	b.c4, err4 = net.ListenUDP("udp4", &net.UDPAddr{})
	if err6 != nil && err4 != nil {
		return nil, err6
	}
	b.resp = mdns.New(host, addrs, b.send)
	b.nodes = mdns.NewNodeResolver(b.send, zoneOf)
	b.mc = listenMDNSMulticast()
	for _, c := range b.conns() {
		go b.read(c)
	}
	return b, nil
}

func (b *builtinMDNS) conns() []*net.UDPConn {
	var out []*net.UDPConn
	for _, c := range append([]*net.UDPConn{b.c6, b.c4}, b.mc...) {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

func (b *builtinMDNS) Advertise(svcs []dnssd.Service) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.resp.Advertise(svcs)
}

func (b *builtinMDNS) Resolve(now time.Time, cfid [8]byte, nodeID uint64) (exchange.Addr, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return exchange.Addr{}, false
	}
	return b.nodes.Resolve(now, cfid, nodeID)
}

func (b *builtinMDNS) Poll(now time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return time.Time{}
	}
	return b.resp.Poll(now)
}

func (b *builtinMDNS) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.resp.Advertise(nil)
	b.resp.Poll(time.Now())
	b.closed = true
	b.mu.Unlock()
	for _, c := range b.conns() {
		c.Close()
	}
}

func (b *builtinMDNS) read(c *net.UDPConn) {
	buf := make([]byte, 9000)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		b.mu.Lock()
		if !b.closed {
			now := time.Now()
			b.resp.HandlePacket(now, from, buf[:n])
			b.nodes.HandlePacket(now, from, buf[:n])
		}
		b.mu.Unlock()
	}
}

func (b *builtinMDNS) send(dst netip.AddrPort, pkt []byte) error {
	if dst.Addr().Is4() {
		if b.c4 == nil {
			return errors.New("mdns: no IPv4 socket")
		}
		_, err := b.c4.WriteToUDPAddrPort(pkt, dst)
		return err
	}
	if b.c6 == nil {
		return errors.New("mdns: no IPv6 socket")
	}
	if !dst.Addr().IsMulticast() {
		_, err := b.c6.WriteToUDPAddrPort(pkt, dst)
		return err
	}
	ifs, _ := net.Interfaces()
	var err error = errors.New("mdns: no IPv6 multicast interface")
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		to := netip.AddrPortFrom(dst.Addr().WithZone(ifc.Name), dst.Port())
		if _, e := b.c6.WriteToUDPAddrPort(pkt, to); e == nil {
			err = nil
		}
	}
	return err
}

func listenMDNSMulticast() []*net.UDPConn {
	group4 := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdns.Port}
	group6 := &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: mdns.Port}
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

func hostnameOrDefault() string {
	h, err := os.Hostname()
	if err != nil {
		return "hostdevice"
	}
	return h
}

func sanitizeHostLabel(name string) string {
	if _, err := netip.ParseAddr(name); err == nil {
		return "hostdevice"
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	var b strings.Builder
	for i := 0; i < len(name) && b.Len() < 63; i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteByte(c)
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "hostdevice"
	}
	return out
}

func hostAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap().WithZone("")
			if !ip.IsValid() || ip.IsLoopback() || ip.IsMulticast() || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

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
