// Command esp32s3-light is a Matter on/off light over Wi-Fi for ESP32-S3
// boards such as the M5Stack Cardputer. It uses the SDK development
// attestation credentials (vendor 0xFFF1, product 0x8000), test passcode
// 20202021 and discriminator 3840, so commission it with a test
// controller such as chip-tool.
//
// Without a Wi-Fi network it advertises over Bluetooth LE, and a
// commissioner provisions the network over BTP:
//
//	chip-tool pairing ble-wifi 1 <ssid> <password> 20202021 3840
//
// Built with a network (-ldflags "-X main.ssid=... -X main.password=..."),
// it joins it at once and is commissioned over IP:
//
//	chip-tool pairing onnetwork-long 1 20202021 3840
//
// It keeps its fabrics and network in flash and restarts already
// commissioned. Hold the G0 button for 5 s to erase them (factory reset).
// The RGB LED shows the light state (red when on); dim cyan means it waits
// for BLE commissioning, dim purple for commissioning over IP, yellow
// means a factory reset.
//
// It speaks IPv6 (link-local) and IPv4 (DHCP), and advertises itself with
// mDNS on both, so controllers that look over either family find it.
//
// The console is USB-Serial-JTAG: when no host reads it, prints block,
// which stalls the firmware. Keep a serial reader attached while it is
// plugged into a computer.
//
//	tinygo flash -target esp32s3-generic ./esp32s3-light
package main

import (
	"crypto/rand"
	"machine"
	"net/netip"
	"runtime"
	"time"

	"firmware/matterble"
	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/dnssd"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/ip4"
	"github.com/shabunin/tiny-matter-go/ip6"
	"github.com/shabunin/tiny-matter-go/mdns"
	"github.com/shabunin/tiny-matter-go/storage"
	"tinygo.org/x/espradio"
)

var (
	ssid, password string // optional compiled-in network, set with -ldflags -X
	stateSlot      string // "1" keeps state in a second flash area (testing)
)

const (
	matterPort    = 5540
	passcode      = 20202021
	discriminator = 3840
	iterations    = 1000

	joinTimeout = 60 * time.Second // give up on a network provisioned over BLE
)

// network sends UDP over IPv6 or IPv4 by destination.
type network struct {
	s6 *ip6.Stack
	s4 *ip4.Stack
}

func (n network) sendUDP(port uint16, to netip.AddrPort, b []byte) error {
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

// transport carries Matter messages over BTP to the BLE peer and over UDP
// to everyone else. BTP is reliable, so MRP is not used over it.
type transport struct {
	ip  *network
	ble *matterble.Server
}

func (t *transport) Send(to exchange.Addr, pkt []byte) error {
	if to == matterble.Peer {
		if t.ble == nil {
			return nil
		}
		return t.ble.Send(pkt)
	}
	if t.ip == nil {
		return nil
	}
	return t.ip.sendUDP(matterPort, to, pkt)
}

func (t *transport) Reliable(to exchange.Addr) bool { return to == matterble.Peer }

// advertiser holds the DNS-SD services until the mDNS responder exists.
type advertiser struct {
	r    *mdns.Responder
	svcs []dnssd.Service
}

func (a *advertiser) Advertise(svcs []dnssd.Service) {
	a.svcs = append(a.svcs[:0], svcs...)
	if a.r != nil {
		a.r.Advertise(a.svcs)
	}
}

func hexMAC(mac [6]byte) string {
	const digits = "0123456789ABCDEF"
	b := make([]byte, 0, 12)
	for _, x := range mac {
		b = append(b, digits[x>>4], digits[x&15])
	}
	return string(b)
}

func fatal(msg string, err error) {
	for {
		println("FATAL:", msg, err.Error())
		time.Sleep(2 * time.Second)
	}
}

// stateStore keeps fabrics, the ACL and the Wi-Fi network in the last
// 32 KB of the flash data area, in two 16 KB slots (or the 32 KB before
// it, for a stateSlot=1 test build).
func stateStore() *storage.Flash {
	const slot = 16 << 10
	off := machine.Flash.Size() - 2*slot
	if stateSlot == "1" {
		off -= 2 * slot
	}
	return &storage.Flash{Dev: machine.Flash, Offset: off, SlotSize: slot}
}

var (
	pressedSince time.Time
	wifiOn       bool
)

// checkButton erases the stored state and restarts when G0 is held 5 s.
func checkButton(now time.Time, store *storage.Flash) {
	if !buttonPressed() {
		pressedSince = time.Time{}
		return
	}
	if pressedSince.IsZero() {
		pressedSince = now
	} else if now.Sub(pressedSince) > 5*time.Second {
		println("factory reset")
		setLED(40, 30, 0) // yellow: erasing
		store.Erase()
		time.Sleep(500 * time.Millisecond)
		restart()
	}
}

func main() {
	initBoard()
	// Long P-256 computations (PASE, CASE) must let the radio tasks run:
	// over BLE, a stall beyond the supervision timeout drops the link.
	p256.SetYield(runtime.Gosched)
	for _, c := range [][3]uint8{{40, 0, 0}, {0, 40, 0}, {0, 0, 40}} { // boot self-test
		setLED(c[0], c[1], c[2])
		time.Sleep(400 * time.Millisecond)
	}
	setLED(0, 0, 8) // dim blue: starting
	time.Sleep(2 * time.Second)
	store := stateStore()
	println("tiny-matter-go light: starting")

	// The Wi-Fi driver is initialised (not started) first, so BLE can
	// coexist with it; its arena must hold both the BT controller and Wi-Fi.
	radioCfg := espradio.Config{Logging: espradio.LogLevelError, ArenaPoolSize: 96 << 10}
	if err := espradio.Enable(radioCfg); err != nil {
		fatal("radio", err)
	}
	mac := factoryMAC()
	println("mac", hexMAC(mac))

	tr := &transport{}
	adv := &advertiser{}
	salt := []byte("SPAKE2P Key Salt")
	v, err := spake2p.NewVerifier(passcode, salt, iterations)
	if err != nil {
		fatal("verifier", err)
	}
	dacKey, err := p256.NewPrivateKey(devcreds.DACPrivateKey)
	if err != nil {
		fatal("dac key", err)
	}
	d, err := device.New(device.Config{
		Transport: tr, Rand: rand.Reader, Port: matterPort,
		Verifier: v, Salt: salt, Iterations: iterations, Discriminator: discriminator,
		Attestation: &clusters.Attestation{
			DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: "Cardputer Light", ProductID: devcreds.ProductID,
			HardwareVersion: 1, HardwareVersionString: "ESP32-S3",
			SoftwareVersion: 1, SoftwareVersionString: "0.2",
			SerialNumber: hexMAC(mac), UniqueID: "tmg-" + hexMAC(mac),
		},
		DeviceType: clusters.DeviceTypeOnOffLight.ID,
		Advertiser: adv,
		Store:      store,
		Clock:      time.Now,
		Log:        func(msg string) { println(msg) },
		WiFi:       true,
	})
	if err != nil {
		fatal("device", err)
	}
	ep := d.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	d.Node.AddCluster(ep, clusters.Descriptor{}, &clusters.OnOff{
		OnChange: func(on bool) {
			if on {
				println("LIGHT ON")
				setLED(80, 0, 0) // red
			} else {
				println("LIGHT OFF")
				setLED(0, 0, 0)
			}
		},
	})
	d.Net.Scan = func(ctx *im.Context, want []byte) ([]clusters.WiFiScanResult, clusters.NetworkingStatus) {
		if !wifiOn {
			return nil, clusters.NetworkOK // the radio is not up during BLE commissioning
		}
		aps, err := espradio.Scan()
		if err != nil {
			return nil, clusters.NetworkUnknownError
		}
		var res []clusters.WiFiScanResult
		for _, ap := range aps {
			if want != nil && ap.SSID != string(want) || len(res) == 8 {
				continue
			}
			res = append(res, clusters.WiFiScanResult{Security: clusters.WiFiWPA2, SSID: []byte(ap.SSID),
				Band: clusters.WiFiBand2G4, RSSI: int8(max(ap.RSSI, -128))})
		}
		return res, clusters.NetworkOK
	}
	if !d.Commissioned() {
		d.OpenCommissioningWindow()
		println("commissionable: passcode", passcode, "discriminator", discriminator)
	}

	// The network: stored, compiled in, or provisioned over BLE.
	var nw clusters.WiFiNetwork
	viaBLE := false
	switch {
	case len(d.Net.Networks) > 0:
		nw = d.Net.Networks[0]
	case ssid != "":
		nw = clusters.WiFiNetwork{SSID: []byte(ssid), Credentials: []byte(password)}
	default:
		nw = commissionOverBLE(d, tr, store)
		viaBLE = true
	}
	if viaBLE {
		// If commissioning does not complete, start over: the fail-safe
		// rolled the network back, so BLE advertising resumes.
		d.FailSafe.OnExpire = append(d.FailSafe.OnExpire, func(now time.Time) {
			if !d.Commissioned() {
				println("commissioning did not complete: restarting")
				time.Sleep(200 * time.Millisecond)
				restart()
			}
		})
	}

	println("connecting to Wi-Fi", string(nw.SSID))
	if err := espradio.Start(); err != nil {
		fatal("wifi start", err)
	}
	wifiOn = true
	if m, err := espradio.StationMAC(); err == nil && m != mac {
		println("station MAC differs from eFuse:", hexMAC(m))
		mac = m
	}
	params := espradio.STAConfig{SSID: string(nw.SSID), Password: string(nw.Credentials)}
	link := espradio.Link{Config: radioCfg}
	reconnected := false
	link.LinkNotify(func(connected bool) (int, espradio.STAConfig) {
		println("wifi link connected:", connected)
		if !connected {
			d.Net.SetConnected(d.Node, nil)
			return 3, params
		}
		d.Net.SetConnected(d.Node, nw.SSID)
		reconnected = true
		return 0, espradio.STAConfig{}
	})
	joinStart := time.Now()
	for {
		err := link.LinkConnect(params)
		if err == nil {
			break
		}
		println("wifi connect:", err.Error())
		if viaBLE && time.Since(joinStart) > joinTimeout {
			println("cannot join the provisioned network: restarting")
			restart()
		}
		time.Sleep(3 * time.Second)
	}
	d.Net.SetConnected(d.Node, nw.SSID)
	d.Net.SetLastConnect(d.Node, nw.SSID, clusters.NetworkOK, 0, false)
	nd := link.NetDev()
	sendFrame := func(f []byte) error {
		nTX++
		err := nd.SendOffsetEthFrame(f)
		if err != nil {
			nTXErr++
			if nTXErr < 10 {
				println("tx error:", err.Error(), "len", len(f))
			}
		}
		return err
	}
	stack := ip6.New(mac, sendFrame)
	stack4 := ip4.New(mac, sendFrame)
	net := &network{stack, stack4}
	println("wifi up, mac", hexMAC(mac), "address", stack.Addr().String())

	resp := mdns.New(hexMAC(mac), []netip.Addr{stack.Addr()}, func(dst netip.AddrPort, b []byte) error {
		return net.sendUDP(mdns.Port, dst, b)
	})
	if err := stack.Join(mdns.Group); err != nil {
		fatal("join mdns", err)
	}
	stack4.Join(mdns.Group4)
	stack4.StartDHCP(hexMAC(mac), func(p netip.Prefix, gw netip.Addr) {
		addrs := []netip.Addr{stack.Addr()}
		if p.IsValid() {
			println("ipv4 address", p.String(), "gateway", gw.String())
			addrs = append(addrs, p.Addr())
		} else {
			println("ipv4 address lost")
		}
		resp.SetAddrs(addrs)
	})
	tr.ip = net
	adv.r = resp
	resp.Advertise(adv.svcs)

	onMatter := func(src netip.AddrPort, dst netip.Addr, b []byte) {
		if err := d.HandlePacket(time.Now(), src, b); err != nil {
			println("drop from", src.String(), err.Error())
		}
	}
	onMDNS := func(src netip.AddrPort, dst netip.Addr, b []byte) {
		nMDNS++
		resp.HandlePacket(time.Now(), src, b)
	}
	stack.Listen(matterPort, onMatter)
	stack.Listen(mdns.Port, onMDNS)
	stack4.Listen(matterPort, onMatter)
	stack4.Listen(mdns.Port, onMDNS)
	if d.Commissioned() {
		println("commissioned; reachable over CASE")
		setLED(0, 0, 0)
	} else {
		setLED(8, 0, 8) // dim purple: waiting to be commissioned
	}

	var frame [espradio.MaxFrameSize]byte
	lastReport := time.Now()
	for {
		for i := 0; i < 8; i++ {
			off, n, err := nd.EthPoll(frame[:])
			if err != nil || n == 0 {
				break
			}
			f := frame[off : off+n]
			countFrame(f)
			stack.HandleFrame(f)
			stack4.HandleFrame(f)
		}
		now := time.Now()
		if reconnected {
			reconnected = false
			stack.ReportGroups()
			stack4.ReportGroups()
			stack4.RenewDHCP()
			resp.Reannounce()
		}
		d.Poll(now)
		resp.Poll(now)
		stack4.Poll(now)
		checkButton(now, store)
		if now.Sub(lastReport) > 30*time.Second {
			lastReport = now
			rx, drops := espradio.NetifRxStats()
			println("alive: rx frames", rx, "ring drops", drops, "ipv6", nIP6, "v6 multicast", nMcast6, "ipv4", nIP4, "tx", nTX, "txerr", nTXErr, "mdns rx", nMDNS)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// commissionOverBLE advertises the Matter BLE service and serves the
// commissioner over BTP until it provisions a network with ConnectNetwork,
// then closes the BLE link and returns the network to join.
func commissionOverBLE(d *device.Device, tr *transport, store *storage.Flash) clusters.WiFiNetwork {
	if err := espradio.BLEInit(); err != nil {
		fatal("ble init", err)
	}
	matterble.Log = func(msg string) { println(msg) }
	b, err := matterble.New(matterble.NewTransport(espradio.VHCITransport{}), discriminator, devcreds.VendorID, devcreds.ProductID)
	if err != nil {
		fatal("ble", err)
	}
	tr.ble = b
	var join *clusters.WiFiNetwork
	d.Net.Connect = func(now time.Time, n clusters.WiFiNetwork) {
		println("ConnectNetwork: closing BLE, joining", string(n.SSID))
		join = &n
		b.Close(now)
	}
	d.HoldSaves = true // a flash erase would stall the link past its timeout
	println("BLE advertising: discriminator", discriminator)
	setLED(0, 8, 8) // dim cyan: waiting for BLE commissioning
	for {
		now := time.Now()
		b.Poll(now, func(msg []byte) {
			if err := d.HandlePacket(now, matterble.Peer, msg); err != nil {
				println("ble drop:", err.Error())
			}
		})
		d.Poll(now)
		if join != nil && !b.Connected() {
			break
		}
		b.Advertise(!b.Connected() && join == nil && d.PASE.WindowOpen())
		checkButton(now, store)
		time.Sleep(2 * time.Millisecond)
	}
	b.Advertise(false)
	d.HoldSaves = false
	tr.ble = nil
	d.Net.Connect = nil
	return *join
}

var nIP6, nMcast6, nIP4, nTX, nTXErr, nMDNS int

func countFrame(f []byte) {
	if len(f) < 14 {
		return
	}
	switch {
	case f[12] == 0x86 && f[13] == 0xDD:
		nIP6++
		if f[0] == 0x33 && f[1] == 0x33 {
			nMcast6++
		}
	case f[12] == 0x08:
		nIP4++
	}
}
