// Command hostdevice runs the stack on a host over UDP for interoperability
// testing against a Matter controller such as chip-tool. It is an on/off
// light (endpoint 1, a member of the groups added to it) and a push button (endpoint 2, Generic Switch) using
// the SDK development attestation credentials (vendor 0xFFF1, product
// 0x8000), test passcode 20202021 and discriminator 3840.
//
// Lines on standard input work the button: "press", "release", "click"
// (a short press) and "long" (held 1.5 s). With -test-key, the General
// Diagnostics TestEventTrigger command does the same: trigger
// 0x003B000000000001 clicks and 0x003B000000000002 long-presses.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
)

type udpTransport struct{ c *net.UDPConn }

func (t udpTransport) Send(to exchange.Addr, pkt []byte) error {
	_, err := t.c.WriteToUDPAddrPort(pkt, to)
	return err
}

func main() {
	addr := flag.String("listen", "[::]:5540", "UDP listen address")
	passcode := flag.Uint("passcode", 20202021, "setup passcode")
	discriminator := flag.Uint("discriminator", 3840, "discriminator")
	mdns := flag.Bool("mdns", true, "advertise with avahi-publish")
	state := flag.String("state", "", "file keeping fabrics and the ACL across restarts")
	testKey := flag.String("test-key", "", "hex enable key (16 bytes) for TestEventTrigger")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	salt := []byte("SPAKE2P Key Salt")
	const iterations = 1000
	v, err := spake2p.NewVerifier(uint32(*passcode), salt, iterations)
	if err != nil {
		log.Fatal(err)
	}
	dacKey, err := p256.NewPrivateKey(devcreds.DACPrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}

	cfg := device.Config{
		Transport: udpTransport{conn}, Rand: rand.Reader, Port: uint16(ua.Port),
		Verifier: v, Salt: salt, Iterations: iterations, Discriminator: uint16(*discriminator),
		Attestation: &clusters.Attestation{
			DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: "Host Light", ProductID: devcreds.ProductID,
			HardwareVersion: 1, HardwareVersionString: "1",
			SoftwareVersion: 1, SoftwareVersionString: "0.1",
			SerialNumber: "TMG-0001", UniqueID: "tmg-host-0001",
		},
		DeviceType: clusters.DeviceTypeOnOffLight.ID,
		Log:        func(msg string) { log.Print(msg) },
		Clock:      time.Now,
	}
	if *mdns {
		cfg.Advertiser = &avahiAdvertiser{}
	}
	if *state != "" {
		cfg.Store = fileStore(*state)
	}
	d, err := device.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	light := d.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	lightID := &clusters.Identify{Type: clusters.IdentifyLightOutput, OnIdentify: func(on bool) { log.Printf("light identify=%v", on) }}
	d.Node.AddCluster(light, clusters.Descriptor{}, lightID,
		&clusters.OnOff{OnChange: func(on bool) { log.Printf("light on=%v", on) }},
		d.NewGroups(lightID))
	groups := &groupMemberships{c: conn, joined: map[netip.Addr]bool{}}
	d.OnMulticast = groups.set
	groups.set(d.MulticastAddrs())
	button := &clusters.Switch{}
	sw := d.Node.AddEndpoint(2, clusters.DeviceTypeGenericSwitch)
	d.Node.AddCluster(sw, clusters.Descriptor{},
		&clusters.Identify{Type: clusters.IdentifyVisibleIndicator, OnIdentify: func(on bool) { log.Printf("button identify=%v", on) }},
		button)
	d.Diagnostics.Interfaces = hostInterfaces

	cmds := make(chan string, 4)
	if *testKey != "" {
		key, err := hex.DecodeString(*testKey)
		if err != nil || len(key) != 16 {
			log.Fatal("-test-key wants 32 hex digits")
		}
		copy(d.Diagnostics.EnableKey[:], key)
		d.Diagnostics.Trigger = func(ctx *im.Context, trigger uint64) im.Status {
			switch trigger {
			case 0x003B000000000001:
				cmds <- "click"
			case 0x003B000000000002:
				cmds <- "long"
			default:
				return im.InvalidCommand
			}
			return im.Success
		}
	}
	if !d.Commissioned() {
		d.OpenCommissioningWindow()
	}
	log.Printf("listening on %v, passcode %d, discriminator %d", conn.LocalAddr(), *passcode, *discriminator)

	type packet struct {
		from netip.AddrPort
		b    []byte
	}
	pkts := make(chan packet, 16)
	go func() {
		for {
			buf := make([]byte, 1280)
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				log.Fatal(err)
			}
			pkts <- packet{from, buf[:n]}
		}
	}()
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			cmds <- strings.TrimSpace(sc.Text())
		}
	}()
	for {
		var timer <-chan time.Time
		if deadline := d.Poll(time.Now()); !deadline.IsZero() {
			timer = time.After(time.Until(deadline))
		}
		select {
		case p := <-pkts:
			if err := d.HandlePacket(time.Now(), p.from, p.b); err != nil {
				log.Printf("drop packet from %v: %v", p.from, err)
			}
		case c := <-cmds:
			now := time.Now()
			switch c {
			case "press":
				button.Press(d.Node, 2, now)
			case "release":
				button.Release(d.Node, 2, now)
			case "click":
				button.Press(d.Node, 2, now)
				time.AfterFunc(150*time.Millisecond, func() { cmds <- "release" })
			case "long":
				button.Press(d.Node, 2, now)
				time.AfterFunc(1500*time.Millisecond, func() { cmds <- "release" })
			default:
				log.Printf("unknown command %q (press, release, click, long)", c)
				continue
			}
			log.Printf("button: %s", c)
		case <-timer:
		}
	}
}

// hostInterfaces lists the host's up, non-loopback interfaces.
func hostInterfaces() []clusters.NetworkInterface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []clusters.NetworkInterface
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) == 0 || len(out) == 4 {
			continue
		}
		ni := clusters.NetworkInterface{Name: ifc.Name, Operational: ifc.Flags&net.FlagRunning != 0,
			HardwareAddress: ifc.HardwareAddr, Type: clusters.InterfaceEthernet}
		if strings.HasPrefix(ifc.Name, "wl") {
			ni.Type = clusters.InterfaceWiFi
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				if p.Addr().Is4() {
					ni.IPv4 = append(ni.IPv4, p.Addr())
				} else {
					ni.IPv6 = append(ni.IPv6, p.Addr().WithZone(""))
				}
			}
		}
		out = append(out, ni)
	}
	return out
}
