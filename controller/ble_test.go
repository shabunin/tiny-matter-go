package controller_test

import (
	"bytes"
	"context"
	"encoding/hex"
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

// blePeripheral is the device's end of a BLE connection: a BTP peripheral
// whose C2 indications reach the controller through toCen. Its fields
// belong to the device goroutine; reset starts a new connection.
type blePeripheral struct {
	srv   *btp.Conn
	toCen chan []byte
	gone  chan struct{}
	once  *sync.Once
	// leave drops the link once all the device sent has been acknowledged,
	// as a device does that cannot keep BLE up while joining its network.
	leave bool
}

func newBLEPeripheral() *blePeripheral {
	p := &blePeripheral{}
	p.reset()
	return p
}

func (p *blePeripheral) reset() {
	p.srv, p.toCen, p.gone, p.once, p.leave = btp.NewConn(247), make(chan []byte, 1024), make(chan struct{}), new(sync.Once), false
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

func (p *blePeripheral) drop() {
	gone := p.gone
	p.once.Do(func() { close(gone) })
}

// fakeGATT is the controller's end of one connection.
type fakeGATT struct {
	d     *testDevice
	srv   *btp.Conn
	toCen chan []byte
	gone  chan struct{}
	drop  func()
}

func (g *fakeGATT) MTU() int { return 247 }

func (g *fakeGATT) Write(ctx context.Context, b []byte) error {
	select {
	case <-g.gone:
		return errors.New("disconnected")
	default:
	}
	b = bytes.Clone(b)
	var err error
	g.d.do(func() {
		now := time.Now()
		var msg []byte
		if msg, err = g.srv.HandleWrite(now, b); err == nil && msg != nil {
			g.d.dev.HandlePacket(now, blePeer, msg)
		}
	})
	return err
}

func (g *fakeGATT) Subscribe(ctx context.Context) error {
	g.d.do(func() { g.srv.Subscribed(time.Now()) })
	return nil
}

func (g *fakeGATT) Values() <-chan []byte { return g.toCen }
func (g *fakeGATT) Done() <-chan struct{} { return g.gone }
func (g *fakeGATT) Close() error          { g.drop(); return nil }

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
	var g *fakeGATT
	b.d.do(func() {
		p := b.p
		if b.connects > 1 {
			p.reset()
		}
		once, gone := p.once, p.gone
		g = &fakeGATT{d: b.d, srv: p.srv, toCen: p.toCen, gone: gone, drop: func() { once.Do(func() { close(gone) }) }}
	})
	return g, nil
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

// joinOnConnect makes the device "join" the network ConnectNetwork names,
// leaving BLE as the firmware does. The function it returns reports the
// network joined.
func joinOnConnect(d *testDevice, p *blePeripheral) func() clusters.WiFiNetwork {
	var joined clusters.WiFiNetwork
	d.do(func() {
		d.dev.Net.Connect = func(now time.Time, n clusters.WiFiNetwork) {
			joined = n
			d.dev.Net.SetConnected(d.dev.Node, n.SSID)
			p.leave = true
		}
	})
	return func() (n clusters.WiFiNetwork) {
		d.do(func() { n = joined })
		return n
	}
}

func TestCommissionOverBLE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, wifiNetwork, p)
	joined := joinOnConnect(d, p)
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
	if string(joined().SSID) != "test-net" || len(nets) != 1 || string(nets[0].SSID) != "test-net" ||
		string(nets[0].Credentials) != "secret123" {
		t.Fatalf("joined %q, committed %+v", joined().SSID, nets)
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

// testDataset is a Thread operational dataset: channel 15, PAN ID 0x1234,
// extended PAN ID DEAD00BEEF00CAFE, network "OpenThread-1234".
var testDataset, _ = hex.DecodeString("0e080000000000010000" + "000300000f" + "0208dead00beef00cafe" +
	"051000112233445566778899aabbccddeeff" + "030f4f70656e5468726561642d31323334" + "01021234")

func TestCommissionOverBLEThread(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, threadNetwork, p)
	joined := joinOnConnect(d, p)
	c := openBLEController(t, &fakeBluetooth{d: d, p: p, discriminator: 3840})
	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{BLE: true, Addr: d.addr(), Thread: testDataset})
	if err != nil {
		t.Fatal(err)
	}
	xpan, _ := hex.DecodeString("dead00beef00cafe")
	var nets []clusters.WiFiNetwork
	d.do(func() { nets = d.dev.Net.Committed() })
	if j := joined(); !bytes.Equal(j.SSID, xpan) || !bytes.Equal(j.Credentials, testDataset) ||
		len(nets) != 1 || !bytes.Equal(nets[0].SSID, xpan) || !bytes.Equal(nets[0].Credentials, testDataset) {
		t.Fatalf("joined %x, committed %+v", j.SSID, nets)
	}
	if !readOnOffOK(ctx, c, n.ID) {
		t.Fatal("not operational")
	}

	// A dataset a device could not join with is refused before anything
	// happens, and a Wi-Fi device is not given a Thread network.
	if _, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{BLE: true, Thread: testDataset[:len(testDataset)-4]}); err == nil ||
		!strings.Contains(err.Error(), "Thread dataset") {
		t.Errorf("incomplete dataset: err = %v", err)
	}
	wp := newBLEPeripheral()
	wd := startDeviceWith(t, wifiNetwork, wp)
	wc := openBLEController(t, &fakeBluetooth{d: wd, p: wp, discriminator: 3840})
	_, err = wc.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{BLE: true, Addr: wd.addr(), Thread: testDataset})
	if err == nil || !strings.Contains(err.Error(), "no Thread interface") {
		t.Fatalf("err = %v", err)
	}
	if got := wd.fabrics(); got != 0 {
		t.Errorf("Wi-Fi device kept %d fabrics", got)
	}
}

// TestCommissionOverBLENoNetwork: a device on a network already is
// commissioned over BLE without being given one.
func TestCommissionOverBLENoNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, noNetwork, p)
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
	d2 := startDeviceWith(t, noNetwork, d2p)
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
	d := startDeviceWith(t, wifiNetwork, p)
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

// TestAutoBLE: without BLE or an address, a device found only over BLE is
// commissioned there only if it is given a network.
func TestAutoBLE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := newBLEPeripheral()
	d := startDeviceWith(t, wifiNetwork, p)
	bt := &fakeBluetooth{d: d, p: p, discriminator: 3840}
	c := openBLEController(t, bt)
	code := &onboarding.Payload{Passcode: passcode, Discriminator: 3840, ShortOnly: true}
	_, err := c.Commission(ctx, code, controller.CommissionOptions{})
	if err == nil || !strings.Contains(err.Error(), "needs a network") {
		t.Fatalf("err = %v", err)
	}
	if bt.connects != 0 {
		t.Error("connected anyway")
	}
	// A QR code that says the device is not on BLE: not looked for there.
	_, err = c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840,
		Discovery: onboarding.DiscoveryOnNetwork}, controller.CommissionOptions{})
	if err == nil || !strings.Contains(err.Error(), "discovery is off") {
		t.Fatalf("on-network QR code: err = %v", err)
	}
	// Given a network, it would be commissioned over BLE, but with
	// discovery off it could not be found on its network afterwards.
	wifi := &controller.WiFiNetwork{SSID: []byte("test-net"), Password: []byte("secret123")}
	_, err = c.Commission(ctx, code, controller.CommissionOptions{WiFi: wifi})
	if err == nil || !strings.Contains(err.Error(), "give the address the device will have") {
		t.Fatalf("err = %v", err)
	}
	_, err = c.Commission(ctx, code, controller.CommissionOptions{BLE: true, WiFi: wifi})
	if err == nil || !strings.Contains(err.Error(), "give the address the device will have") {
		t.Fatalf("explicit BLE: err = %v", err)
	}
	if bt.connects != 0 || d.fabrics() != 0 {
		t.Errorf("%d connections, %d fabrics", bt.connects, d.fabrics())
	}
}

func readOnOffOK(ctx context.Context, c *controller.Controller, node uint64) bool {
	rep, err := c.Read(ctx, node, im.Request{Attributes: []im.AttributePath{onOffPath}})
	return err == nil && len(rep.Attributes) == 1 && rep.Attributes[0].Status == im.Success
}
