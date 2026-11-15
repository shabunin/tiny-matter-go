package controller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

// bleGrace is how long a device seen over BLE first waits for the IP
// network to answer too: a device on the network is commissioned there.
const bleGrace = 2 * time.Second

// notFound is the error when no device in commissioning mode answers.
type notFound struct{ msg string }

func (e notFound) Error() string { return e.msg }

func isNotFound(err error) bool {
	var nf notFound
	return errors.As(err, &nf)
}

func discriminatorText(p *onboarding.Payload) string {
	if p.ShortOnly {
		return fmt.Sprint("short discriminator ", p.ShortDiscriminator())
	}
	return fmt.Sprint("discriminator ", p.Discriminator)
}

// findIP looks for the device in commissioning mode with mDNS.
func (c *Controller) findIP(ctx context.Context, p *onboarding.Payload) ([]netip.AddrPort, error) {
	dctx, cancel := context.WithTimeout(ctx, commissionableWait)
	found, err := c.disc.commissionable(dctx, p)
	cancel()
	if len(found) == 0 {
		if err == nil || errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			err = notFound{"controller: no device in commissioning mode with " + discriminatorText(p) + " answered on the network"}
		}
		return nil, err
	}
	var addrs []netip.AddrPort
	for _, f := range found {
		c.logf("found %s: discriminator %d, vendor %#04x, product %#04x, at %v",
			f.Name, f.Discriminator, f.VendorID, f.ProductID, f.Addrs)
		addrs = append(addrs, instanceAddrs(f.Instance)...)
	}
	if len(addrs) == 0 {
		return nil, notFound{"controller: the device in commissioning mode has no address"}
	}
	return addrs, nil
}

// located is where a device in commissioning mode was found: at addrs on
// the IP network, or over BLE.
type located struct {
	addrs []netip.AddrPort
	ble   *BLEDevice
}

// finders search for a device; a nil one is not used.
type finders struct {
	ip  func(ctx context.Context) ([]netip.AddrPort, error)
	ble func(ctx context.Context) (BLEDevice, error)
}

// race runs the finders at once. A device on the network is preferred: one
// seen over BLE first is taken once the network search fails or grace has
// passed without an answer. Errors other than not finding the device win
// over not finding it.
func race(ctx context.Context, f finders, grace time.Duration) (located, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		l   located
		err error
	}
	var ipc, blec chan result
	if f.ip != nil {
		ipc = make(chan result, 1)
		go func() {
			addrs, err := f.ip(ctx)
			ipc <- result{located{addrs: addrs}, err}
		}()
	}
	if f.ble != nil {
		blec = make(chan result, 1)
		go func() {
			d, err := f.ble(ctx)
			blec <- result{located{ble: &d}, err}
		}()
	}
	var (
		onBLE   *located
		timer   <-chan time.Time
		lastErr error
	)
	for ipc != nil || blec != nil {
		select {
		case r := <-ipc:
			ipc = nil
			if r.err == nil {
				return r.l, nil
			}
			lastErr = pickErr(lastErr, r.err)
		case r := <-blec:
			blec = nil
			if r.err != nil {
				lastErr = pickErr(lastErr, r.err)
				continue
			}
			onBLE = &r.l
			if ipc == nil {
				return *onBLE, nil
			}
			timer = time.After(grace)
		case <-timer:
			return *onBLE, nil
		}
	}
	if onBLE != nil {
		return *onBLE, nil
	}
	if lastErr == nil {
		lastErr = errors.New("controller: nowhere to look for the device")
	}
	return located{}, lastErr
}

// pickErr keeps the more telling of two errors: a failure over not
// finding the device.
func pickErr(old, err error) error {
	if old == nil || isNotFound(old) && !isNotFound(err) {
		return err
	}
	return old
}

// locate looks for a device in commissioning mode with mDNS and, unless
// its QR code says it does not advertise over BLE, over BLE at once.
func (c *Controller) locate(ctx context.Context, p *onboarding.Payload) (located, error) {
	var f finders
	if c.disc != nil {
		f.ip = func(ctx context.Context) ([]netip.AddrPort, error) { return c.findIP(ctx, p) }
	}
	if p.Discovery == 0 || p.Discovery&onboarding.DiscoveryBLE != 0 {
		if bt, err := c.bluetooth(ctx); err != nil {
			c.logf("not looking over BLE: %v", err)
		} else {
			f.ble = func(ctx context.Context) (BLEDevice, error) { return c.findBLE(ctx, bt, p) }
		}
	}
	if f.ip == nil && f.ble == nil {
		return located{}, errors.New("controller: discovery is off and there is no Bluetooth: give the device's address")
	}
	l, err := race(ctx, f, bleGrace)
	if err != nil && isNotFound(err) && f.ip != nil && f.ble != nil {
		err = notFound{"controller: no device in commissioning mode with " + discriminatorText(p) +
			" answered on the network or over BLE"}
	}
	return l, err
}

// errNeedsNetwork refuses to commission a device found only over BLE
// without giving it a network.
var errNeedsNetwork = errors.New("controller: the device is in BLE commissioning mode and needs a network: " +
	"give it Wi-Fi or Thread credentials, or commission over BLE explicitly if it is on a network already")

// errUnfindable refuses to commission over BLE a device that could not be
// found on the IP network afterwards.
var errUnfindable = errors.New("controller: discovery is off: give the address the device will have on its network")

// reach finds the device and opens a PASE session with it: over BLE with
// opts.BLE, at opts.Addr, or else where locate finds it, in which case
// useBLE (if not nil) may refuse a device found only over BLE. The link is
// nil over the IP network.
func (c *Controller) reach(ctx context.Context, p *onboarding.Payload, opts CommissionOptions, useBLE func() error) (*exchange.Session, *bleLink, error) {
	var (
		addrs  []netip.AddrPort
		dev    *BLEDevice
		viaBLE = opts.BLE
	)
	switch {
	case opts.BLE:
	case opts.Addr.IsValid():
		addrs = []netip.AddrPort{opts.Addr}
	default:
		l, err := c.locate(ctx, p)
		if err != nil {
			return nil, nil, err
		}
		if l.ble == nil {
			addrs = l.addrs
			break
		}
		if useBLE != nil {
			if err := useBLE(); err != nil {
				return nil, nil, err
			}
		}
		viaBLE, dev = true, l.ble
	}

	if viaBLE {
		link, err := c.openBLE(ctx, p, dev)
		if err != nil {
			return nil, nil, err
		}
		c.logf("PASE over BLE")
		pctx, cancel := context.WithTimeout(ctx, blePASETimeout)
		ps, err := c.pase(pctx, link.addr, p.Passcode)
		cancel()
		if err != nil {
			link.close()
			return nil, nil, fmt.Errorf("controller: PASE: %w", err)
		}
		return ps, link, nil
	}

	var err error
	for _, a := range addrs {
		c.logf("PASE with %v", a)
		actx, cancel := context.WithTimeout(ctx, paseAttemptTimeout)
		var ps *exchange.Session
		ps, err = c.pase(actx, a, p.Passcode)
		cancel()
		if err == nil {
			return ps, nil, nil
		}
		if ctx.Err() != nil {
			break
		}
		c.logf("PASE with %v: %v", a, err)
	}
	return nil, nil, fmt.Errorf("controller: PASE: %w", err)
}
