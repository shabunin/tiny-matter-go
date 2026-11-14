package controller_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/btp"
	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/credentials/attestation"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

// blePeer is the device's address for its BLE peer, as in the firmware.
var blePeer = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)

// blePeripheral is the device's end of a BLE link: a BTP peripheral whose
// C2 indications reach the controller through toCen. Its BTP state belongs
// to the device goroutine.
type blePeripheral struct {
	srv   *btp.Conn
	toCen chan []byte
	gone  chan struct{}
	once  sync.Once
	// leave drops the link once all the device sent has been acknowledged,
	// as a device does that cannot keep BLE up while joining Wi-Fi.
	leave bool
}

func newBLEPeripheral() *blePeripheral {
	return &blePeripheral{srv: btp.NewConn(247), toCen: make(chan []byte, 1024), gone: make(chan struct{})}
}

// poll sends what BTP has for the central (device goroutine).
func (p *blePeripheral) poll(t *testing.T, now time.Time) time.Time {
	for {
		select {
		case <-p.gone:
			return time.Time{}
		default:
		}
		pkt, next, err := p.srv.Poll(now)
		if err != nil {
			p.drop()
			return time.Time{}
		}
		if pkt == nil {
			if p.leave && p.srv.Flushed() && len(p.toCen) == 0 {
				p.drop()
			}
			return next
		}
		p.toCen <- bytes.Clone(pkt)
	}
}

func (p *blePeripheral) drop() { p.once.Do(func() { close(p.gone) }) }

// fakeGATT is the controller's end of the link.
type fakeGATT struct {
	d *testDevice
	p *blePeripheral
}

func (g *fakeGATT) MTU() int { return 247 }

func (g *fakeGATT) Write(ctx context.Context, b []byte) error {
	select {
	case <-g.p.gone:
		return errors.New("disconnected")
	default:
	}
	b = bytes.Clone(b)
	var err error
	g.d.do(func() {
		now := time.Now()
		var msg []byte
		if msg, err = g.p.srv.HandleWrite(now, b); err == nil && msg != nil {
			g.d.dev.HandlePacket(now, blePeer, msg)
		}
	})
	return err
}

func (g *fakeGATT) Subscribe(ctx context.Context) error {
	g.d.do(func() { g.p.srv.Subscribed(time.Now()) })
	return nil
}

func (g *fakeGATT) Values() <-chan []byte { return g.p.toCen }
func (g *fakeGATT) Done() <-chan struct{} { return g.p.gone }
func (g *fakeGATT) Close() error          { g.p.drop(); return nil }

// fakeBluetooth sees one device advertising a discriminator.
type fakeBluetooth struct {
	d             *testDevice
	p             *blePeripheral
	discriminator uint16
	connects      int
}

func (b *fakeBluetooth) Scan(ctx context.Context, found func(controller.BLEDevice) bool) error {
	sd := btp.ServiceData(b.discriminator, devcreds.VendorID, devcreds.ProductID, false)
	found(controller.BLEDevice{ID: "dev0", Address: "02:00:00:00:00:01", ServiceData: sd[:]})
	return nil // the scan ends
}

func (b *fakeBluetooth) Connect(ctx context.Context, dev controller.BLEDevice) (controller.GATT, error) {
	b.connects++
	return &fakeGATT{b.d, b.p}, nil
}

func openBLEController(t *testing.T, bt controller.Bluetooth) *controller.Controller {
	t.Helper()
	c, err := controller.Open(controller.Options{Dir: t.TempDir(), PAAs: attestation.TestPAAs(), NoDiscovery: true,
		Log: func(msg string) { t.Log(msg) }, Bluetooth: bt})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestCommissionOverBLE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, true, p)
	var joined []byte
	d.do(func() {
		d.dev.Net.Connect = func(now time.Time, n clusters.WiFiNetwork) {
			joined = bytes.Clone(n.SSID)
			d.dev.Net.SetConnected(d.dev.Node, n.SSID)
			p.leave = true
		}
	})
	c := openBLEController(t, &fakeBluetooth{d: d, p: p, discriminator: 3840})

	// The device is told to join the network, leaves BLE, and is reached
	// at its address on the IP network.
	start := time.Now()
	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840}, controller.CommissionOptions{
		BLE: true, Addr: d.addr(),
		WiFi: &controller.WiFiNetwork{SSID: []byte("test-net"), Password: []byte("secret123")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("took %v: waited for a ConnectNetwork response that came?", took)
	}
	var nets []clusters.WiFiNetwork
	d.do(func() { nets = d.dev.Net.Committed() })
	if string(joined) != "test-net" || len(nets) != 1 || string(nets[0].SSID) != "test-net" ||
		string(nets[0].Credentials) != "secret123" {
		t.Fatalf("joined %q, committed %+v", joined, nets)
	}
	if got := d.fabrics(); got != 1 {
		t.Fatalf("device has %d fabrics", got)
	}
	if n.Addr != d.addr().String() {
		t.Errorf("node address %q", n.Addr)
	}
	select {
	case <-p.gone:
	default:
		t.Error("BLE still connected")
	}
	// Operational over CASE on the IP network.
	if _, err := c.Invoke(ctx, n.ID, im.CommandPath{Endpoint: 1, Cluster: 0x0006, Command: 0x01}, 0, nil); err != nil {
		t.Fatal(err)
	}
	if !readOnOff(t, ctx, c, n.ID) {
		t.Fatal("light off after On")
	}
}

// TestCommissionOverBLENoNetwork: a device on a network already is
// commissioned over BLE without being given one.
func TestCommissionOverBLENoNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, false, p)
	c := openBLEController(t, &fakeBluetooth{d: d, p: p, discriminator: 3840})
	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{BLE: true, Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.fabrics(); got != 1 || !readOnOffOK(ctx, c, n.ID) {
		t.Fatalf("device has %d fabrics", got)
	}
	// Asking it to join Wi-Fi without the cluster fails before it joins
	// the fabric.
	d2p := newBLEPeripheral()
	d2 := startDeviceWith(t, false, d2p)
	c2 := openBLEController(t, &fakeBluetooth{d: d2, p: d2p, discriminator: 3840})
	_, err = c2.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840}, controller.CommissionOptions{
		BLE: true, Addr: d2.addr(), WiFi: &controller.WiFiNetwork{SSID: []byte("x"), Password: []byte("password1")}})
	if err == nil || !strings.Contains(err.Error(), "no Wi-Fi interface") {
		t.Fatalf("err = %v", err)
	}
	if got := d2.fabrics(); got != 0 {
		t.Errorf("device kept %d fabrics", got)
	}
}

func TestBLEWrongDiscriminator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, true, p)
	bt := &fakeBluetooth{d: d, p: p, discriminator: 1234}
	c := openBLEController(t, bt)
	_, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{BLE: true, Addr: d.addr()})
	if err == nil || !strings.Contains(err.Error(), "no device in BLE commissioning mode with discriminator 3840") {
		t.Fatalf("err = %v", err)
	}
	if bt.connects != 0 {
		t.Error("connected anyway")
	}
	// A short discriminator from a manual code matches the top 4 bits.
	bt.discriminator = 3840 + 0x0AB
	_, err = c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840, ShortOnly: true},
		controller.CommissionOptions{BLE: true, Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}
}

func readOnOffOK(ctx context.Context, c *controller.Controller, node uint64) bool {
	rep, err := c.Read(ctx, node, im.Request{Attributes: []im.AttributePath{onOffPath}})
	return err == nil && len(rep.Attributes) == 1 && rep.Attributes[0].Status == im.Success
}
