// Package wifinode runs a Matter device over Wi-Fi on an ESP32 (classic
// or S3) with espradio: it joins the network, runs IPv6 (link-local and
// SLAAC) and IPv4 (DHCP) stacks, advertises the node with mDNS on both,
// finds other nodes for the device, joins its group addresses and feeds it
// Matter messages. The firmware creates the device with the node's
// Transport, Advertiser and Resolve, then calls Join and Run.
package wifinode

import (
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/dnssd"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/ip4"
	"github.com/shabunin/tiny-matter-go/ip6"
	"github.com/shabunin/tiny-matter-go/mdns"
	"tinygo.org/x/espradio"
)

// MatterPort is the UDP port Matter listens on.
const MatterPort = 5540

// Sender carries messages to one peer over another link (BTP over BLE).
type Sender interface {
	Send(pkt []byte) error
}

// Transport carries Matter messages over UDP, and to Peer over Link (set
// while BLE commissioning runs). Link is reliable, so MRP is not used
// over it.
type Transport struct {
	Link Sender
	Peer exchange.Addr
	// HasPeer marks Peer as the link's address (it is reliable).
	HasPeer bool

	ip *network
}

func (t *Transport) Send(to exchange.Addr, pkt []byte) error {
	if t.HasPeer && to == t.Peer {
		if t.Link == nil {
			return nil
		}
		return t.Link.Send(pkt)
	}
	if t.ip == nil {
		return nil
	}
	return t.ip.sendUDP(MatterPort, to, pkt)
}

func (t *Transport) Reliable(to exchange.Addr) bool { return t.HasPeer && to == t.Peer }

// network sends UDP over IPv6 or IPv4 by destination.
type network struct {
	s6 *ip6.Stack
	s4 *ip4.Stack
}

func (n *network) sendUDP(port uint16, to netip.AddrPort, b []byte) error {
	var err error
	if to.Addr().Unmap().Is4() {
		err = n.s4.SendUDP(port, netip.AddrPortFrom(to.Addr().Unmap(), to.Port()), b)
	} else {
		err = n.s6.SendUDP(port, to, b)
	}
	if err == ip6.ErrNoNeighbor || err == ip4.ErrNoNeighbor {
		return nil // sent once the neighbor answers
	}
	return err
}

// Advertiser holds the DNS-SD services until the mDNS responder exists.
type Advertiser struct {
	r    *mdns.Responder
	svcs []dnssd.Service
}

func (a *Advertiser) Advertise(svcs []dnssd.Service) {
	a.svcs = append(a.svcs[:0], svcs...)
	if a.r != nil {
		a.r.Advertise(a.svcs)
	}
}

// Node is the Wi-Fi side of a device.
type Node struct {
	MAC        [6]byte
	Radio      espradio.Config // as passed to espradio.Enable
	Transport  *Transport
	Advertiser *Advertiser
	// Log, if set, receives progress messages.
	Log func(msg string)

	d       *device.Device
	link    espradio.Link
	nw      clusters.WiFiNetwork
	params  espradio.STAConfig
	s6      *ip6.Stack
	s4      *ip4.Stack
	ipv4    netip.Addr
	nodes   *mdns.NodeResolver
	wifiOn  bool
	linkUp  atomic.Bool
	changed atomic.Bool // the link went up or down
	rejoin  atomic.Bool // the link came back

	nIP6, nMcast6, nIP4, nTX, nTXErr, nMDNS int
}

// New returns the node for the radio (enabled with cfg) and station
// address mac.
func New(mac [6]byte, cfg espradio.Config) *Node {
	return &Node{MAC: mac, Radio: cfg, Transport: &Transport{}, Advertiser: &Advertiser{}}
}

func (n *Node) log(msg string) {
	if n.Log != nil {
		n.Log(msg)
	}
}

// Resolve finds another node (for device.Config.Resolve).
func (n *Node) Resolve(now time.Time, cfid [8]byte, node uint64) (netip.AddrPort, bool) {
	if n.nodes == nil {
		return netip.AddrPort{}, false
	}
	a, ok := n.nodes.Resolve(now, cfid, node)
	// One interface: the stack reports peers without a zone.
	return netip.AddrPortFrom(a.Addr().WithZone(""), a.Port()), ok
}

// LinkUp reports whether the station is associated.
func (n *Node) LinkUp() bool { return n.linkUp.Load() }

// Attach reports the Wi-Fi interface in d's General Diagnostics and
// scans for its Network Commissioning cluster (with scan, if not nil,
// while Wi-Fi is off).
func (n *Node) Attach(d *device.Device, offScan func() []espradio.AccessPoint) {
	n.d = d
	d.Diagnostics.Interfaces = func() []clusters.NetworkInterface {
		ni := clusters.NetworkInterface{Name: "wlan0", Operational: n.linkUp.Load(),
			HardwareAddress: n.MAC[:], Type: clusters.InterfaceWiFi}
		if n.s6 != nil {
			ni.IPv6 = n.s6.Addrs()
		}
		if n.ipv4.IsValid() {
			ni.IPv4 = []netip.Addr{n.ipv4}
		}
		return []clusters.NetworkInterface{ni}
	}
	if d.WiFiDiagnostics != nil {
		// espradio reports the RSSI only; BSSID, channel and version read
		// as null, and the security type as unspecified unless the network
		// is open.
		d.WiFiDiagnostics.Status = func() clusters.WiFiStatus {
			st := clusters.WiFiStatus{Connected: n.linkUp.Load()}
			if !st.Connected {
				return st
			}
			if len(n.nw.Credentials) == 0 {
				st.Security = clusters.WiFiSecurityNone
			}
			if v, err := espradio.RSSI(); err == nil && v >= -128 && v <= 127 {
				st.RSSI, st.HasRSSI = int8(v), true
			}
			return st
		}
	}
	d.Net.Scan = func(ctx *im.Context, want []byte) ([]clusters.WiFiScanResult, clusters.NetworkingStatus) {
		var aps []espradio.AccessPoint
		if n.wifiOn {
			var err error
			if aps, err = espradio.Scan(); err != nil {
				return nil, clusters.NetworkUnknownError
			}
		} else if offScan != nil {
			aps = offScan()
		}
		return ScanResults(aps, want), clusters.NetworkOK
	}
}

// Join starts Wi-Fi and joins nw, retrying every 3 s; poll runs while it
// waits. giveUp, if set, is asked after each failure whether to stop
// trying; Join then returns false.
func (n *Node) Join(nw clusters.WiFiNetwork, poll func(now time.Time), giveUp func() bool) bool {
	if err := espradio.Start(); err != nil {
		n.log("wifi start: " + err.Error())
		return false
	}
	n.wifiOn = true
	if m, err := espradio.StationMAC(); err == nil && m != n.MAC {
		n.log("station MAC differs from eFuse: " + HexMAC(m))
		n.MAC = m
	}
	n.nw = nw
	n.params = espradio.STAConfig{SSID: string(nw.SSID), Password: string(nw.Credentials)}
	n.link = espradio.Link{Config: n.Radio}
	n.link.LinkNotify(func(connected bool) (int, espradio.STAConfig) {
		if connected {
			n.log("wifi link up")
		} else {
			n.log("wifi link down")
		}
		n.linkUp.Store(connected)
		n.changed.Store(true)
		if !connected {
			return 3, n.params
		}
		n.rejoin.Store(true)
		return 0, espradio.STAConfig{}
	})
	for {
		if poll != nil {
			poll(time.Now())
		}
		err := n.link.LinkConnect(n.params)
		if err == nil {
			break
		}
		n.log("wifi connect: " + err.Error())
		if giveUp != nil && giveUp() {
			return false
		}
		for i := 0; i < 60; i++ {
			if poll != nil {
				poll(time.Now())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	n.linkUp.Store(true)
	n.changed.Store(false)
	n.rejoin.Store(false)
	n.d.Net.SetConnected(n.d.Node, nw.SSID)
	n.d.Net.SetLastConnect(n.d.Node, nw.SSID, clusters.NetworkOK, 0, false)
	return true
}

// Run brings up the IP stacks and mDNS and serves the device for good,
// calling poll every pass.
func (n *Node) Run(poll func(now time.Time)) {
	d := n.d
	nd := n.link.NetDev()
	sendFrame := func(f []byte) error {
		n.nTX++
		err := nd.SendOffsetEthFrame(f)
		if err != nil {
			n.nTXErr++
			if n.nTXErr < 10 {
				n.log("tx error: " + err.Error())
			}
		}
		return err
	}
	n.s6 = ip6.New(n.MAC, sendFrame)
	n.s4 = ip4.New(n.MAC, sendFrame)
	s6, s4 := n.s6, n.s4
	net := &network{s6, s4}
	n.log("wifi up, mac " + HexMAC(n.MAC) + " address " + s6.Addr().String())

	resp := mdns.New(HexMAC(n.MAC), []netip.Addr{s6.Addr()}, func(dst netip.AddrPort, b []byte) error {
		return net.sendUDP(mdns.Port, dst, b)
	})
	if err := s6.Join(mdns.Group); err != nil {
		n.log("join mdns: " + err.Error())
	}
	s4.Join(mdns.Group4)
	// Listen on the multicast addresses of the device's groups.
	var groupAddrs []netip.Addr
	setGroups := func(addrs []netip.Addr) {
		for _, a := range groupAddrs {
			if !slices.Contains(addrs, a) {
				s6.Leave(a)
			}
		}
		for _, a := range addrs {
			if !slices.Contains(groupAddrs, a) {
				if err := s6.Join(a); err != nil {
					n.log("join group address " + a.String() + ": " + err.Error())
				}
			}
		}
		groupAddrs = append(groupAddrs[:0], addrs...)
	}
	setGroups(d.MulticastAddrs())
	d.OnMulticast = setGroups
	updateAddrs := func() {
		addrs := s6.Addrs()
		if n.ipv4.IsValid() {
			addrs = append(addrs, n.ipv4)
		}
		resp.SetAddrs(addrs)
	}
	s6.StartSLAAC(func() {
		for _, a := range s6.Addrs()[1:] {
			n.log("ipv6 address " + a.String())
		}
		updateAddrs()
	})
	s4.StartDHCP(HexMAC(n.MAC), func(p netip.Prefix, gw netip.Addr) {
		n.ipv4 = netip.Addr{}
		if p.IsValid() {
			n.log("ipv4 address " + p.String() + " gateway " + gw.String())
			n.ipv4 = p.Addr()
		} else {
			n.log("ipv4 address lost")
		}
		updateAddrs()
	})
	n.Transport.ip = net
	n.Advertiser.r = resp
	resp.Advertise(n.Advertiser.svcs)

	onMatter := func(src netip.AddrPort, dst netip.Addr, b []byte) {
		if err := d.HandlePacket(time.Now(), src, b); err != nil {
			n.log("drop from " + src.String() + " " + err.Error())
		}
	}
	n.nodes = mdns.NewNodeResolver(func(dst netip.AddrPort, b []byte) error {
		return net.sendUDP(mdns.Port, dst, b)
	}, func(netip.AddrPort) string { return "wlan0" })
	n.nodes.Usable = func(a netip.Addr) bool {
		return a.Is4() || a.IsLinkLocalUnicast() || s6.HasGlobal()
	}
	onMDNS := func(src netip.AddrPort, dst netip.Addr, b []byte) {
		n.nMDNS++
		now := time.Now()
		resp.HandlePacket(now, src, b)
		n.nodes.HandlePacket(now, src, b)
	}
	s6.Listen(MatterPort, onMatter)
	s6.Listen(mdns.Port, onMDNS)
	s4.Listen(MatterPort, onMatter)
	s4.Listen(mdns.Port, onMDNS)
	if d.Commissioned() {
		n.log("commissioned; reachable over CASE")
	}

	// The frame buffer is on the heap, not main's stack, which packet
	// handling (CASE, certificate checks) takes close to its end. (Not a
	// package-level var: on the classic ESP32, growing .bss by that much
	// breaks the Wi-Fi handshake, "auth expired".)
	frame := make([]byte, espradio.MaxFrameSize)
	lastReport := time.Now()
	for {
		for i := 0; i < 8; i++ {
			off, size, err := nd.EthPoll(frame)
			if err != nil || size == 0 {
				break
			}
			f := frame[off : off+size]
			n.count(f)
			s6.HandleFrame(f)
			s4.HandleFrame(f)
		}
		now := time.Now()
		if n.changed.Swap(false) {
			if n.linkUp.Load() {
				d.Net.SetConnected(d.Node, n.nw.SSID)
			} else {
				d.Net.SetConnected(d.Node, nil)
			}
		}
		if n.rejoin.Swap(false) {
			s6.ReportGroups()
			s6.SolicitRouter()
			s4.ReportGroups()
			s4.RenewDHCP()
			resp.Reannounce()
		}
		d.Poll(now)
		resp.Poll(now)
		s6.Poll(now)
		s4.Poll(now)
		if poll != nil {
			poll(now)
		}
		if now.Sub(lastReport) > 30*time.Second {
			lastReport = now
			rx, drops := espradio.NetifRxStats()
			println("alive: rx frames", rx, "ring drops", drops, "ipv6", n.nIP6, "v6 multicast", n.nMcast6, "ipv4", n.nIP4, "tx", n.nTX, "txerr", n.nTXErr, "mdns rx", n.nMDNS)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (n *Node) count(f []byte) {
	if len(f) < 14 {
		return
	}
	switch {
	case f[12] == 0x86 && f[13] == 0xDD:
		n.nIP6++
		if f[0] == 0x33 && f[1] == 0x33 {
			n.nMcast6++
		}
	case f[12] == 0x08:
		n.nIP4++
	}
}

// ScanResults lists the networks of aps (only want, if set), strongest
// first, each once, at most 8. The radio reports only names and signal
// strengths: WPA2 on 2.4 GHz is assumed.
func ScanResults(aps []espradio.AccessPoint, want []byte) []clusters.WiFiScanResult {
	sorted := append([]espradio.AccessPoint(nil), aps...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].RSSI > sorted[j-1].RSSI; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var res []clusters.WiFiScanResult
next:
	for _, ap := range sorted {
		if ap.SSID == "" || want != nil && ap.SSID != string(want) {
			continue
		}
		for _, r := range res {
			if string(r.SSID) == ap.SSID {
				continue next
			}
		}
		res = append(res, clusters.WiFiScanResult{Security: clusters.WiFiWPA2, SSID: []byte(ap.SSID),
			Band: clusters.WiFiBand2G4, RSSI: int8(max(min(ap.RSSI, 0), -128))})
		if len(res) == 8 {
			break
		}
	}
	return res
}

// HexMAC formats a MAC address as 12 upper-case hex digits.
func HexMAC(mac [6]byte) string {
	const digits = "0123456789ABCDEF"
	b := make([]byte, 0, 12)
	for _, x := range mac {
		b = append(b, digits[x>>4], digits[x&15])
	}
	return string(b)
}
