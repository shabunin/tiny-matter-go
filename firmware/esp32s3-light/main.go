// Command esp32s3-light is a Matter on/off light over Wi-Fi for ESP32-S3
// boards such as the M5Stack Cardputer. It uses the SDK development
// attestation credentials (vendor 0xFFF1, product 0x8000), test passcode
// 20202021 and discriminator 3840, so commission it with a test
// controller such as chip-tool:
//
//	chip-tool pairing onnetwork-long 1 20202021 3840
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

func main() {
	time.Sleep(2 * time.Second)
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
		Log:        func(msg string) { println(msg) },
	})
	if err != nil {
		fatal("device", err)
	}
	ep := d.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	d.Node.AddCluster(ep, clusters.Descriptor{}, &clusters.OnOff{
		OnChange: func(on bool) { println("LIGHT", map[bool]string{true: "ON", false: "OFF"}[on]) },
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
	d.OpenCommissioningWindow()
	println("commissionable: passcode", passcode, "discriminator", discriminator)

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
