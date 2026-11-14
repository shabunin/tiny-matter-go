// Command esp32s3-light is a Matter on/off light over Wi-Fi for ESP32-S3
// boards such as the M5Stack Cardputer. It uses the SDK development
// attestation credentials (vendor 0xFFF1, product 0x8000), test passcode
// 20202021 and discriminator 3840, so commission it with a test
// controller such as chip-tool:
//
//	chip-tool pairing onnetwork-long 1 20202021 3840
//
// It keeps its fabrics in flash and restarts already commissioned. Hold
// the G0 button for 5 s to erase them (factory reset). The RGB LED shows the
// light state (red when on); dim purple means it is waiting to be
// commissioned, yellow means a factory reset.
//
// The console is USB-Serial-JTAG: when no host reads it, prints block,
// which stalls the firmware. Keep a serial reader attached while it is
// plugged into a computer.
//
// Build with the Wi-Fi credentials:
//
//	tinygo flash -target esp32s3-generic -ldflags "-X main.ssid=... -X main.password=..." ./esp32s3-light
package main

import (
	"crypto/rand"
	"machine"
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/ip6"
	"github.com/shabunin/tiny-matter-go/mdns"
	"github.com/shabunin/tiny-matter-go/storage"
	"tinygo.org/x/espradio"
)

var ssid, password string // set with -ldflags -X

const (
	matterPort    = 5540
	passcode      = 20202021
	discriminator = 3840
	iterations    = 1000
)

type transport struct{ s *ip6.Stack }

func (t transport) Send(to exchange.Addr, pkt []byte) error {
	err := t.s.SendUDP(matterPort, to, pkt)
	if err == ip6.ErrNoNeighbor {
		return nil // sent once the neighbor answers
	}
	return err
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

// stateStore keeps fabrics and the ACL in the last 32 KB of the flash data
// area, in two 16 KB slots.
func stateStore() *storage.Flash {
	const slot = 16 << 10
	return &storage.Flash{Dev: machine.Flash, Offset: machine.Flash.Size() - 2*slot, SlotSize: slot}
}

func main() {
	initBoard()
	for _, c := range [][3]uint8{{40, 0, 0}, {0, 40, 0}, {0, 0, 40}} { // boot self-test
		setLED(c[0], c[1], c[2])
		time.Sleep(400 * time.Millisecond)
	}
	setLED(0, 0, 8) // dim blue: starting
	time.Sleep(2 * time.Second)
	store := stateStore()
	println("tiny-matter-go light: connecting to Wi-Fi", ssid)

	params := espradio.STAConfig{SSID: ssid, Password: password}
	link := espradio.Link{Config: espradio.Config{Logging: espradio.LogLevelError}}
	reconnected := false
	link.LinkNotify(func(connected bool) (int, espradio.STAConfig) {
		println("wifi link connected:", connected)
		if !connected {
			return 3, params
		}
		reconnected = true
		return 0, espradio.STAConfig{}
	})
	for {
		err := link.LinkConnect(params)
		if err == nil {
			break
		}
		println("wifi connect:", err.Error())
		time.Sleep(3 * time.Second)
	}
	nd := link.NetDev()
	mac, err := nd.HardwareAddr6()
	if err != nil {
		fatal("mac", err)
	}
	stack := ip6.New(mac, func(f []byte) error {
		nTX++
		err := nd.SendOffsetEthFrame(f)
		if err != nil {
			nTXErr++
			if nTXErr < 10 {
				println("tx error:", err.Error(), "len", len(f))
			}
		}
		return err
	})
	println("wifi up, mac", hexMAC(mac), "address", stack.Addr().String())

	resp := mdns.New(hexMAC(mac), []netip.Addr{stack.Addr()}, func(dst netip.AddrPort, b []byte) error {
		return stack.SendUDP(mdns.Port, dst, b)
	})
	if err := stack.Join(mdns.Group); err != nil {
		fatal("join mdns", err)
	}

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
		Transport: transport{stack}, Rand: rand.Reader, Port: matterPort,
		Verifier: v, Salt: salt, Iterations: iterations, Discriminator: discriminator,
		Attestation: &clusters.Attestation{
			DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: "Cardputer Light", ProductID: devcreds.ProductID,
			HardwareVersion: 1, HardwareVersionString: "ESP32-S3",
			SoftwareVersion: 1, SoftwareVersionString: "0.1",
			SerialNumber: hexMAC(mac), UniqueID: "tmg-" + hexMAC(mac),
		},
		DeviceType: clusters.DeviceTypeOnOffLight.ID,
		Advertiser: resp,
		Store:      store,
		Log:        func(msg string) { println(msg) },
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

	stack.Listen(matterPort, func(src netip.AddrPort, dst netip.Addr, b []byte) {
		if err := d.HandlePacket(time.Now(), src, b); err != nil {
			println("drop from", src.String(), err.Error())
		}
	})
	stack.Listen(mdns.Port, func(src netip.AddrPort, dst netip.Addr, b []byte) {
		nMDNS++
		resp.HandlePacket(time.Now(), src, b)
	})
	if d.Commissioned() {
		println("commissioned; reachable over CASE")
		setLED(0, 0, 0)
	} else {
		d.OpenCommissioningWindow()
		println("commissionable: passcode", passcode, "discriminator", discriminator)
		setLED(8, 0, 8) // dim purple: waiting to be commissioned
	}
	var pressedSince time.Time

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
		}
		now := time.Now()
		if reconnected {
			reconnected = false
			stack.ReportGroups()
			resp.Reannounce()
		}
		d.Poll(now)
		resp.Poll(now)
		// Holding G0 for 5 s erases the stored fabrics and restarts.
		if buttonPressed() {
			if pressedSince.IsZero() {
				pressedSince = now
			} else if now.Sub(pressedSince) > 5*time.Second {
				println("factory reset")
				setLED(40, 30, 0) // yellow: erasing
				store.Erase()
				time.Sleep(500 * time.Millisecond)
				restart()
			}
		} else {
			pressedSince = time.Time{}
		}
		if now.Sub(lastReport) > 30*time.Second {
			lastReport = now
			rx, drops := espradio.NetifRxStats()
			println("alive: rx frames", rx, "ring drops", drops, "ipv6", nIP6, "v6 multicast", nMcast6, "ipv4", nIP4, "tx", nTX, "txerr", nTXErr, "mdns rx", nMDNS)
		}
		time.Sleep(2 * time.Millisecond)
	}
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
