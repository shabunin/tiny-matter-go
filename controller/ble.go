package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/btp"
	"github.com/shabunin/tiny-matter-go/internal/bluez"
	"github.com/shabunin/tiny-matter-go/internal/dbus"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

// Bluetooth is a BLE central: it finds devices in BLE commissioning mode
// and connects to their Matter GATT service. Without Options.Bluetooth,
// the controller uses BlueZ over D-Bus (Linux).
type Bluetooth interface {
	// Scan reports devices advertising the Matter BLE service until found
	// returns true or ctx ends.
	Scan(ctx context.Context, found func(BLEDevice) bool) error
	// Connect connects to a device Scan reported.
	Connect(ctx context.Context, d BLEDevice) (GATT, error)
}

// BLEDevice is a device advertising the Matter BLE service.
type BLEDevice struct {
	ID      string // identifies the device to Connect (a D-Bus path for BlueZ)
	Address string
	Name    string
	// ServiceData is the service data for UUID 0xFFF6.
	ServiceData []byte
}

// GATT is a connection to a device's Matter GATT service.
type GATT interface {
	// MTU returns the ATT MTU, or 0 if unknown.
	MTU() int
	// Write writes to characteristic C1, with a write response.
	Write(ctx context.Context, b []byte) error
	// Subscribe enables indications on characteristic C2.
	Subscribe(ctx context.Context) error
	// Values delivers the values indicated on C2.
	Values() <-chan []byte
	// Done is closed when the connection ends, once the values received
	// before have been taken.
	Done() <-chan struct{}
	// Close disconnects.
	Close() error
}

const (
	bleScanWait      = 20 * time.Second
	bleConnectWait   = 30 * time.Second
	btpHandshakeWait = 15 * time.Second
	bleWriteTimeout  = 10 * time.Second
	blePASETimeout   = 45 * time.Second
)

var errLinkClosed = errors.New("controller: BLE connection closed")

// blueZ is the BlueZ Bluetooth.
type blueZ struct{ c *bluez.Client }

func (b blueZ) Scan(ctx context.Context, found func(BLEDevice) bool) error {
	return b.c.Scan(ctx, func(d bluez.Device) bool {
		return found(BLEDevice{ID: string(d.Path), Address: d.Address, Name: d.Name, ServiceData: d.ServiceData})
	})
}

func (b blueZ) Connect(ctx context.Context, d BLEDevice) (GATT, error) {
	l, err := b.c.Connect(ctx, dbus.ObjectPath(d.ID))
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (b blueZ) Close() error { return b.c.Close() }

// bluetooth returns the controller's Bluetooth, opening BlueZ the first
// time.
func (c *Controller) bluetooth(ctx context.Context) (Bluetooth, error) {
	c.bleMu.Lock()
	defer c.bleMu.Unlock()
	if c.ble != nil {
		return c.ble, nil
	}
	if c.opts.Bluetooth != nil {
		c.ble = c.opts.Bluetooth
		return c.ble, nil
	}
	cl, err := bluez.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("controller: Bluetooth: %w", err)
	}
	c.ble = blueZ{cl}
	return c.ble, nil
}

// BLECommissionable is a device in BLE commissioning mode.
type BLECommissionable struct {
	BLEDevice
	btp.Advertisement
}

// DiscoverBLE reports the devices in BLE commissioning mode found until ctx
// ends.
func (c *Controller) DiscoverBLE(ctx context.Context, found func(BLECommissionable)) error {
	bt, err := c.bluetooth(ctx)
	if err != nil {
		return err
	}
	err = bt.Scan(ctx, func(d BLEDevice) bool {
		if ad, ok := btp.ParseServiceData(d.ServiceData); ok {
			found(BLECommissionable{d, ad})
		}
		return false
	})
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// findBLE looks for the device with the payload's discriminator in BLE
// advertisements.
func (c *Controller) findBLE(ctx context.Context, bt Bluetooth, p *onboarding.Payload) (BLEDevice, error) {
	var dev BLEDevice
	found := false
	sctx, cancel := context.WithTimeout(ctx, bleScanWait)
	defer cancel()
	err := bt.Scan(sctx, func(d BLEDevice) bool {
		ad, ok := btp.ParseServiceData(d.ServiceData)
		if !ok {
			return false
		}
		match := ad.Discriminator == p.Discriminator
		if p.ShortOnly {
			match = uint8(ad.Discriminator>>8) == p.ShortDiscriminator()
		}
		if !match {
			c.logf("BLE: %s advertises discriminator %d, not ours", d.Address, ad.Discriminator)
			return false
		}
		c.logf("found %s over BLE: discriminator %d, vendor %#04x, product %#04x",
			d.Address, ad.Discriminator, ad.VendorID, ad.ProductID)
		dev, found = d, true
		return true
	})
	if found {
		return dev, nil
	}
	if err == nil || errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return dev, notFound{"controller: no device in BLE commissioning mode with " + discriminatorText(p)}
	}
	return dev, fmt.Errorf("controller: BLE: %w", err)
}

// openBLE finds the device over BLE (unless dev is given), connects, and
// opens a BTP session that the controller's exchanges reach at the link's
// address.
func (c *Controller) openBLE(ctx context.Context, p *onboarding.Payload, dev *BLEDevice) (*bleLink, error) {
	bt, err := c.bluetooth(ctx)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		d, err := c.findBLE(ctx, bt, p)
		if err != nil {
			return nil, err
		}
		dev = &d
	}
	cctx, cancel := context.WithTimeout(ctx, bleConnectWait)
	gatt, err := bt.Connect(cctx, *dev)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: connecting over BLE: %w", err)
	}
	l := &bleLink{c: c, gatt: gatt, out: make(chan []byte, 64),
		quit: make(chan struct{}), done: make(chan struct{})}
	hctx, cancel := context.WithTimeout(ctx, btpHandshakeWait)
	err = l.handshake(hctx)
	cancel()
	if err != nil {
		gatt.Close()
		return nil, fmt.Errorf("controller: BTP handshake: %w", err)
	}
	c.logf("BLE connected to %s: BTP segments of %d bytes, window %d", dev.Address, l.conn.FragmentSize(), l.conn.Window())
	if err := c.do(func(time.Time) {
		c.nextLink++
		l.addr = netip.AddrPortFrom(netip.IPv6Unspecified(), c.nextLink)
		c.links[l.addr] = l
	}); err != nil {
		gatt.Close()
		return nil, err
	}
	go l.run()
	return l, nil
}

// isBLE reports whether an exchange address stands for a BLE link: no UDP
// datagram comes from the unspecified address.
func isBLE(a netip.AddrPort) bool { return a.Addr() == netip.IPv6Unspecified() && a.Port() != 0 }

// Reliable reports whether a peer is reached over a reliable transport
// (exchange.ReliableTransport): BTP is, so MRP is not used over it.
func (c *Controller) Reliable(to netip.AddrPort) bool { return isBLE(to) }

// bleLink carries Matter messages over BTP on a GATT connection. Its
// goroutine owns the BTP state.
type bleLink struct {
	c    *Controller
	addr netip.AddrPort
	gatt GATT
	conn *btp.Conn
	out  chan []byte // messages from the controller loop
	quit chan struct{}
	done chan struct{}
	err  error
}

func (l *bleLink) handshake(ctx context.Context) error {
	l.conn = btp.NewCentral(l.gatt.MTU())
	if err := l.gatt.Write(ctx, l.conn.HandshakeRequest()); err != nil {
		return err
	}
	if err := l.gatt.Subscribe(ctx); err != nil {
		return err
	}
	select {
	case v := <-l.gatt.Values():
		_, err := l.conn.HandleIndication(time.Now(), v)
		return err
	case <-l.gatt.Done():
		return errLinkClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// send queues a message for the device (controller loop goroutine).
func (l *bleLink) send(pkt []byte) error {
	select {
	case <-l.done:
		return errLinkClosed
	default:
	}
	select {
	case l.out <- bytes.Clone(pkt):
		return nil
	default:
		return errors.New("controller: BLE send queue full")
	}
}

func (l *bleLink) run() {
	defer func() {
		l.gatt.Close()
		close(l.done)
		l.c.do(func(time.Time) { delete(l.c.links, l.addr) })
	}()
	var pending [][]byte
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := time.Now()
		for len(pending) > 0 && l.conn.Send(pending[0]) == nil {
			pending = pending[1:]
		}
		pkt, next, err := l.conn.Poll(now)
		if err != nil {
			l.fail(err)
			return
		}
		if pkt != nil {
			ctx, cancel := context.WithTimeout(context.Background(), bleWriteTimeout)
			err := l.gatt.Write(ctx, bytes.Clone(pkt))
			cancel()
			if err != nil {
				l.fail(err)
				return
			}
			continue
		}
		wait := time.Hour
		if !next.IsZero() {
			wait = max(time.Until(next), time.Millisecond)
		}
		timer.Reset(wait)
		select {
		case v := <-l.gatt.Values():
			msg, err := l.conn.HandleIndication(time.Now(), v)
			if err != nil {
				l.fail(err)
				return
			}
			if msg != nil {
				select {
				case l.c.packets <- packet{l.addr, bytes.Clone(msg)}:
				case <-l.quit:
					return
				}
			}
		case m := <-l.out:
			pending = append(pending, m)
		case <-timer.C:
		case <-l.gatt.Done():
			l.fail(errLinkClosed)
			return
		case <-l.quit:
			return
		}
	}
}

func (l *bleLink) fail(err error) {
	if l.err == nil {
		l.err = err
		l.c.logf("BLE link: %v", err)
	}
}

// gone reports whether the link is down.
func (l *bleLink) gone() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// close disconnects and waits for the link's goroutine.
func (l *bleLink) close() {
	select {
	case <-l.quit:
	default:
		close(l.quit)
	}
	<-l.done
}

func closeBluetooth(b Bluetooth) {
	if cl, ok := b.(io.Closer); ok {
		cl.Close()
	}
}
