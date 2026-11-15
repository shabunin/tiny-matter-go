package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/onboarding"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// WiFiScanResult is a Wi-Fi network a device sees.
type WiFiScanResult struct {
	SSID  []byte
	BSSID [6]byte
	// Security is a WiFiSecurityBitmap: 0x01 open, 0x02 WEP, 0x04 WPA,
	// 0x08 WPA2, 0x10 WPA3.
	Security uint8
	Channel  uint16
	// Band is a WiFiBandEnum: 0 2.4 GHz, 1 3.65 GHz, 2 5 GHz, 3 6 GHz,
	// 4 60 GHz, 5 1 GHz.
	Band uint8
	RSSI int8
}

// ThreadScanResult is a Thread network a device sees.
type ThreadScanResult struct {
	PANID           uint16
	ExtendedPANID   uint64
	NetworkName     string
	Channel         uint16
	Version         uint8
	ExtendedAddress [8]byte
	RSSI            int8
	LQI             uint8
}

// NetworkScan is what a device saw when asked to scan for networks.
type NetworkScan struct {
	Interface string // "Wi-Fi" or "Thread"
	WiFi      []WiFiScanResult
	Thread    []ThreadScanResult
}

const scanFailSafe = 60 // seconds, beyond the scan itself

// ScanNetworks asks a device in commissioning mode which networks it sees
// (Network Commissioning ScanNetworks), reaching it as Commission would
// (see CommissionOptions.BLE and Addr). The device is left uncommissioned.
func (c *Controller) ScanNetworks(ctx context.Context, p *onboarding.Payload, opts CommissionOptions) (*NetworkScan, error) {
	ps, link, err := c.reach(ctx, p, opts, nil)
	if err != nil {
		return nil, err
	}
	if link != nil {
		defer link.close()
	}
	defer c.do(func(now time.Time) { securechannel.CloseSession(now, c.m, ps) })

	sctx, cancel := context.WithTimeout(ctx, stepTimeout)
	rep, err := c.readOn(sctx, ps, im.Request{Attributes: []im.AttributePath{
		{AnyEndpoint: true, Cluster: clNetworkCommissioning, Attribute: attrFeatureMap},
		{AnyEndpoint: true, Cluster: clNetworkCommissioning, Attribute: attrScanMaxTime},
	}})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: reading Network Commissioning: %w", err)
	}
	scan := &NetworkScan{Interface: "Wi-Fi"}
	ep, _, ok := networkEndpoint(rep, featureWiFi)
	if !ok {
		if ep, _, ok = networkEndpoint(rep, featureThread); !ok {
			return nil, errors.New("controller: the device has no Wi-Fi or Thread interface to scan with")
		}
		scan.Interface = "Thread"
	}
	scanMax := uint64(30)
	for _, a := range rep.Attributes {
		if a.Status == im.Success && a.Path.Endpoint == ep && a.Path.Attribute == attrScanMaxTime {
			r := tlv.NewReader(a.Data)
			if r.Next() == nil {
				if v, err := r.Uint(); err == nil && v > 0 {
					scanMax = v
				}
			}
		}
	}

	// The spec has ScanNetworks need the fail-safe armed; not every device
	// insists, but none minds.
	sctx, cancel = context.WithTimeout(ctx, stepTimeout)
	res, err := c.invokeOn(sctx, ps, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), scanMax+scanFailSafe)
		w.PutUint(tlv.ContextTag(1), 0)
	})
	cancel()
	if err := commissioningError("ArmFailSafe", res, err); err != nil {
		return nil, err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c.invokeOn(sctx, ps, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), 0)
			w.PutUint(tlv.ContextTag(1), 0)
		})
		cancel()
	}()

	c.logf("asking the device to scan for %s networks (up to %d s)", scan.Interface, scanMax)
	sctx, cancel = context.WithTimeout(ctx, time.Duration(scanMax)*time.Second+15*time.Second)
	res, err = c.invokeOn(sctx, ps, im.CommandPath{Endpoint: ep, Cluster: clNetworkCommissioning, Command: cmdScanNetworks}, 0, nil)
	cancel()
	if err := networkError("ScanNetworks", res, err); err != nil {
		return nil, err
	}
	if err := parseScan(res.Fields, scan); err != nil {
		return nil, fmt.Errorf("controller: ScanNetworks response: %w", err)
	}
	return scan, nil
}

// parseScan decodes the result lists of a ScanNetworksResponse.
func parseScan(fields []byte, scan *NetworkScan) error {
	r := tlv.NewReader(fields)
	if err := r.Next(); err != nil || r.Type() != tlv.TypeStruct || r.EnterContainer() != nil {
		return errors.New("no response fields")
	}
	for r.Next() == nil {
		switch {
		case r.Tag().IsContext(2) && r.Type() == tlv.TypeArray:
			if err := eachStruct(r, func() func(*tlv.Reader, uint8) error {
				scan.WiFi = append(scan.WiFi, WiFiScanResult{})
				s := &scan.WiFi[len(scan.WiFi)-1]
				return func(r *tlv.Reader, tag uint8) error { return wifiField(s, r, tag) }
			}); err != nil {
				return err
			}
		case r.Tag().IsContext(3) && r.Type() == tlv.TypeArray:
			if err := eachStruct(r, func() func(*tlv.Reader, uint8) error {
				scan.Thread = append(scan.Thread, ThreadScanResult{})
				s := &scan.Thread[len(scan.Thread)-1]
				return func(r *tlv.Reader, tag uint8) error { return threadField(s, r, tag) }
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// eachStruct decodes the structures of the list at r: item is called for
// each, and the function it returns for each of its fields.
func eachStruct(r *tlv.Reader, item func() func(r *tlv.Reader, tag uint8) error) error {
	if err := r.EnterContainer(); err != nil {
		return err
	}
	for r.Next() == nil {
		if r.Type() != tlv.TypeStruct {
			return errors.New("list item is not a structure")
		}
		if err := im.ForEachField(r, item()); err != nil {
			return err
		}
	}
	return r.ExitContainer()
}

func wifiField(s *WiFiScanResult, r *tlv.Reader, tag uint8) (err error) {
	switch tag {
	case 0:
		s.Security, err = r.Uint8()
	case 1:
		var b []byte
		b, err = r.Bytes()
		s.SSID = append([]byte(nil), b...)
	case 2:
		var b []byte
		if b, err = r.Bytes(); err == nil && len(b) == 6 {
			copy(s.BSSID[:], b)
		}
	case 3:
		s.Channel, err = r.Uint16()
	case 4:
		s.Band, err = r.Uint8()
	case 5:
		s.RSSI, err = r.Int8()
	}
	return err
}

func threadField(s *ThreadScanResult, r *tlv.Reader, tag uint8) (err error) {
	switch tag {
	case 0:
		s.PANID, err = r.Uint16()
	case 1:
		s.ExtendedPANID, err = r.Uint()
	case 2:
		s.NetworkName, err = r.String()
	case 3:
		s.Channel, err = r.Uint16()
	case 4:
		s.Version, err = r.Uint8()
	case 5:
		var b []byte
		if b, err = r.Bytes(); err == nil && len(b) == 8 {
			copy(s.ExtendedAddress[:], b)
		}
	case 6:
		s.RSSI, err = r.Int8()
	case 7:
		s.LQI, err = r.Uint8()
	}
	return err
}
