// Command hostdevice runs the stack on a host over UDP for interoperability
// testing against a Matter controller such as chip-tool. It is an on/off
// light using the SDK development attestation credentials (vendor 0xFFF1,
// product 0x8000), test passcode 20202021 and discriminator 3840.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
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
	d.Node.AddCluster(light, clusters.Descriptor{}, &clusters.OnOff{
		OnChange: func(on bool) { log.Printf("light on=%v", on) },
	})
	if !d.Commissioned() {
		d.OpenCommissioningWindow()
	}
	log.Printf("listening on %v, passcode %d, discriminator %d", conn.LocalAddr(), *passcode, *discriminator)

	buf := make([]byte, 1280)
	for {
		deadline := d.Poll(time.Now())
		if deadline.IsZero() {
			deadline = time.Now().Add(time.Hour)
		}
		conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			log.Fatal(err)
		}
		if err := d.HandlePacket(time.Now(), from, buf[:n]); err != nil {
			log.Printf("drop packet from %v: %v", from, err)
		}
	}
}
