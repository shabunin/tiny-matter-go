package controller_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/credentials/attestation"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/onboarding"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const passcode = 20202021

// testDevice is a device.Device on a loopback UDP socket, run by its own
// goroutine.
type testDevice struct {
	t     *testing.T
	dev   *device.Device
	conn  *net.UDPConn
	calls chan func()
	quit  chan struct{}
	done  chan struct{}
}

// udpTransport sends over UDP and, to blePeer, over the device's BTP
// peripheral if it has one.
type udpTransport struct {
	conn *net.UDPConn
	ble  *blePeripheral
}

func (u udpTransport) Send(to exchange.Addr, pkt []byte) error {
	if to == blePeer {
		if u.ble == nil {
			return nil
		}
		return u.ble.srv.Send(pkt)
	}
	_, err := u.conn.WriteToUDPAddrPort(pkt, to)
	return err
}

func (u udpTransport) Reliable(to exchange.Addr) bool { return to == blePeer }

func startDevice(t *testing.T) *testDevice { return startDeviceWith(t, noNetwork, nil) }

// netKind is the network interface a test device has.
type netKind int

const (
	noNetwork netKind = iota
	wifiNetwork
	threadNetwork
)

// startDeviceWith starts a device, with Network Commissioning for a kind
// of network, and reachable over BLE through ble if not nil.
func startDeviceWith(t *testing.T, kind netKind, ble *blePeripheral) *testDevice {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("SPAKE2P Key Salt")
	v, _ := spake2p.NewVerifier(passcode, salt, 1000)
	dacKey, _ := p256.NewPrivateKey(devcreds.DACPrivateKey)
	dev, err := device.New(device.Config{
		Transport: udpTransport{conn, ble}, Rand: rand.Reader,
		Verifier: v, Salt: salt, Iterations: 1000, Discriminator: 3840,
		Attestation: &clusters.Attestation{DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration},
		Basic: &clusters.BasicInformation{VendorName: "T", VendorID: devcreds.VendorID,
			ProductName: "Test Light", ProductID: devcreds.ProductID},
		WiFi: kind == wifiNetwork, Thread: kind == threadNetwork,
	})
	if err != nil {
		t.Fatal(err)
	}
	ep := dev.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	dev.Node.AddCluster(ep, clusters.Descriptor{}, &clusters.OnOff{})
	dev.OpenCommissioningWindow()

	d := &testDevice{t: t, dev: dev, conn: conn,
		calls: make(chan func()), quit: make(chan struct{}), done: make(chan struct{})}
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
				return
			}
			pkts <- packet{from, buf[:n]}
		}
	}()
	go func() {
		defer close(d.done)
		for {
			wait := time.Second
			deadline := dev.Poll(time.Now())
			if ble != nil {
				if next := ble.poll(t, time.Now()); !next.IsZero() && (deadline.IsZero() || next.Before(deadline)) {
					deadline = next
				}
			}
			if !deadline.IsZero() {
				wait = max(time.Until(deadline), time.Millisecond)
			}
			timer := time.NewTimer(wait)
			select {
			case p := <-pkts:
				dev.HandlePacket(time.Now(), p.from, p.b)
			case f := <-d.calls:
				f()
			case <-timer.C:
			case <-d.quit:
				timer.Stop()
				return
			}
			timer.Stop()
		}
	}()
	t.Cleanup(func() {
		close(d.quit)
		<-d.done
		conn.Close()
	})
	return d
}

// do runs f on the device goroutine.
func (d *testDevice) do(f func()) {
	ran := make(chan struct{})
	d.calls <- func() { f(); close(ran) }
	<-ran
}

func (d *testDevice) addr() netip.AddrPort { return d.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (d *testDevice) fabrics() (n int) {
	d.do(func() { n = d.dev.Fabrics.Committed() })
	return n
}

func openController(t *testing.T, dir string) *controller.Controller {
	t.Helper()
	c, err := controller.Open(controller.Options{Dir: dir, PAAs: attestation.TestPAAs(), NoDiscovery: true,
		Log: func(msg string) { t.Log(msg) }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var onOffPath = im.AttributePath{Endpoint: 1, Cluster: 0x0006, Attribute: 0x0000}

func readOnOff(t *testing.T, ctx context.Context, c *controller.Controller, node uint64) bool {
	t.Helper()
	rep, err := c.Read(ctx, node, im.Request{Attributes: []im.AttributePath{onOffPath}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Attributes) != 1 || rep.Attributes[0].Status != im.Success {
		t.Fatalf("OnOff read: %+v", rep.Attributes)
	}
	r := tlv.NewReader(rep.Attributes[0].Data)
	r.Next()
	on, err := r.Bool()
	if err != nil {
		t.Fatal(err)
	}
	return on
}

func TestCommissionAndControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := startDevice(t)
	dir := t.TempDir()
	c := openController(t, dir)

	// A wrong passcode fails PASE, and the device stays uncommissioned.
	_, err := c.Commission(ctx, &onboarding.Payload{Passcode: 20202022, Discriminator: 3840},
		controller.CommissionOptions{Addr: d.addr()})
	if err == nil {
		t.Fatal("commissioned with a wrong passcode")
	}

	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}
	if n.VendorID != devcreds.VendorID || n.ProductID != devcreds.ProductID || n.Label != "Test Light" {
		t.Errorf("node = %+v", n)
	}
	if got := d.fabrics(); got != 1 {
		t.Fatalf("device has %d fabrics", got)
	}

	// Invoke and read.
	if readOnOff(t, ctx, c, n.ID) {
		t.Fatal("light on before On")
	}
	if _, err := c.Invoke(ctx, n.ID, im.CommandPath{Endpoint: 1, Cluster: 0x0006, Command: 0x01}, 0, nil); err != nil {
		t.Fatal(err)
	}
	if !readOnOff(t, ctx, c, n.ID) {
		t.Fatal("light off after On")
	}

	// Write and read back.
	labelPath := im.AttributePath{Cluster: 0x0028, Attribute: 0x0005}
	if err := c.Write(ctx, n.ID, labelPath, 0, func(w *tlv.Writer, tag tlv.Tag) { w.PutString(tag, "kitchen") }); err != nil {
		t.Fatal(err)
	}
	rep, err := c.Read(ctx, n.ID, im.Request{Attributes: []im.AttributePath{labelPath}})
	if err != nil {
		t.Fatal(err)
	}
	r := tlv.NewReader(rep.Attributes[0].Data)
	r.Next()
	if s, _ := r.String(); s != "kitchen" {
		t.Errorf("NodeLabel = %q", s)
	}

	// A subscription reports the change.
	reports := make(chan bool, 8)
	sub, err := c.Subscribe(ctx, n.ID, im.Request{Attributes: []im.AttributePath{onOffPath}},
		controller.SubscribeOptions{MaxInterval: 10, OnReport: func(rd *im.ReportData) {
			for _, a := range rd.Reports {
				r := tlv.NewReader(a.Data)
				r.Next()
				on, _ := r.Bool()
				reports <- on
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	if on := <-reports; !on {
		t.Error("priming report: off")
	}
	if _, err := c.Invoke(ctx, n.ID, im.CommandPath{Endpoint: 1, Cluster: 0x0006, Command: 0x00}, 0, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case on := <-reports:
		if on {
			t.Error("report after Off: on")
		}
	case <-time.After(5 * time.Second):
		t.Error("no report after Off")
	}
	sub.Close()

	// The state survives a restart of the controller.
	c.Close()
	c = openController(t, dir)
	defer c.Close()
	if nodes := c.Nodes(); len(nodes) != 1 || nodes[0].ID != n.ID || nodes[0].Label != "Test Light" {
		t.Fatalf("nodes after reopening: %+v", nodes)
	}
	if readOnOff(t, ctx, c, n.ID) {
		t.Error("light on after Off")
	}

	// Another controller open on the same fabric at the same time is a
	// node of its own, admitted by the administrator CAT.
	c2 := openController(t, dir)
	if c2.NodeID() == c.NodeID() {
		t.Error("two controllers with one node ID")
	}
	if readOnOff(t, ctx, c2, n.ID) {
		t.Error("light on after Off")
	}
	acl, err := c2.Read(ctx, n.ID, im.Request{Attributes: []im.AttributePath{{Cluster: 0x001F, Attribute: 0}},
		FabricFiltered: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(acl.Attributes[0].Data, binary.LittleEndian.AppendUint64(nil, 0xFFFFFFFD_00000000|controller.DefaultAdminCAT)) {
		t.Errorf("ACL does not name the administrator CAT: %x", acl.Attributes[0].Data)
	}
	c2.Close()

	// A commissioning window for another administrator, closed again.
	w, err := c.OpenWindow(ctx, n.ID, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !onboarding.ValidPasscode(w.Payload.Passcode) || w.Payload.VendorID != devcreds.VendorID {
		t.Errorf("window payload %+v", w.Payload)
	}
	if _, err := w.Payload.ManualCode(); err != nil {
		t.Error(err)
	}
	if err := c.CloseWindow(ctx, n.ID); err != nil {
		t.Fatal(err)
	}

	// Removing the node removes the fabric from the device.
	if err := c.RemoveNode(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if got := d.fabrics(); got != 0 {
		t.Errorf("device has %d fabrics after RemoveNode", got)
	}
	if len(c.Nodes()) != 0 {
		t.Errorf("nodes after RemoveNode: %+v", c.Nodes())
	}
}

// A second controller commissions the device through a window the first
// one opened (the enhanced commissioning method).
func TestOpenWindowForSecondAdmin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := startDevice(t)
	c1 := openController(t, t.TempDir())
	defer c1.Close()
	n, err := c1.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}
	w, err := c1.OpenWindow(ctx, n.ID, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c2 := openController(t, t.TempDir())
	defer c2.Close()
	n2, err := c2.Commission(ctx, &w.Payload, controller.CommissionOptions{Addr: d.addr(), Label: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if n2.Label != "second" {
		t.Errorf("label %q", n2.Label)
	}
	if got := d.fabrics(); got != 2 {
		t.Fatalf("device has %d fabrics", got)
	}
	// Both administrators control the device.
	for _, c := range []*controller.Controller{c1, c2} {
		id := c.Nodes()[0].ID
		if _, err := c.Invoke(ctx, id, im.CommandPath{Endpoint: 1, Cluster: 0x0006, Command: 0x02}, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	if readOnOff(t, ctx, c1, n.ID) {
		t.Error("toggled twice: want off")
	}
}
