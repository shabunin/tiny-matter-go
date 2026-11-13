// Command devicesize builds a complete device (on/off light) to measure
// flash and RAM use on microcontroller targets. It does not network.
package main

import (
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
)

type nopTransport struct{}

func (nopTransport) Send(exchange.Addr, []byte) error { return nil }

// xorshift is a stand-in entropy source; real firmware uses the hardware RNG.
type xorshift uint64

func (x *xorshift) Read(b []byte) (int, error) {
	for i := range b {
		*x ^= *x << 13
		*x ^= *x >> 7
		*x ^= *x << 17
		b[i] = byte(*x)
	}
	return len(b), nil
}

func main() {
	rng := xorshift(0x9E3779B97F4A7C15)
	salt := []byte("SPAKE2P Key Salt")
	v, err := spake2p.NewVerifier(20202021, salt, 1000)
	if err != nil {
		panic(err)
	}
	dacKey, _ := p256.NewPrivateKey(devcreds.DACPrivateKey)
	d, err := device.New(device.Config{
		Transport: nopTransport{}, Rand: &rng,
		Verifier: v, Salt: salt, Iterations: 1000, Discriminator: 3840,
		Attestation: &clusters.Attestation{DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration},
		Basic: &clusters.BasicInformation{VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: "Light", ProductID: devcreds.ProductID},
	})
	if err != nil {
		panic(err)
	}
	ep := d.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	d.Node.AddCluster(ep, clusters.Descriptor{}, &clusters.OnOff{})
	d.OpenCommissioningWindow()
	var pkt [64]byte
	for {
		d.HandlePacket(time.Now(), exchange.Addr{}, pkt[:])
		d.Poll(time.Now())
		time.Sleep(time.Second)
	}
}
