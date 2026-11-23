// Package cyw43wifi is the Wi-Fi radio of the Raspberry Pi Pico W and
// Pico 2 W, a CYW43439 driven by soypat/cyw43439, as a wifinode.Radio.
package cyw43wifi

import (
	"errors"
	"strconv"

	"firmware/wifinode"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/soypat/cyw43439"
)

// maxMulticast is how many multicast addresses the chip's filter holds.
const maxMulticast = 10

// Radio is the CYW43439 station. It does not rejoin by itself: the Node
// calls Connect again after the link drops.
type Radio struct {
	// Dev is the chip, also for its GPIOs (the Pico W's LED is GPIO 0).
	Dev *cyw43439.Device

	rx       []byte
	rxLen    int
	attempts int
	nRx      int
}

var _ wifinode.Radio = (*Radio)(nil)

// New powers the chip up and loads its Wi-Fi firmware (about 1.5 s), and
// with bluetooth its Bluetooth controller's too, for HCI.
func New(bluetooth bool) (*Radio, error) {
	r := &Radio{Dev: cyw43439.NewPicoWDevice(), rx: make([]byte, cyw43439.MaxFrameSize)}
	cfg := cyw43439.DefaultWifiConfig()
	if bluetooth {
		cfg = cyw43439.DefaultWifiBluetoothConfig()
	}
	if err := r.Dev.Init(cfg); err != nil {
		return nil, err
	}
	// The driver calls the handler while it holds its lock, so a reply
	// sent from inside it would deadlock: Recv copies the frame out and
	// returns it after the poll.
	r.Dev.RecvEthHandle(func(f []byte) { r.rxLen = copy(r.rx, f) })
	return r, nil
}

// HCIMaxPacket is the longest HCI packet (type byte included) the driver
// writes to the Bluetooth controller: its buffer is 256 bytes, with a
// 4-byte header.
const HCIMaxPacket = 252

// BDAddr is the Bluetooth address to give the controller, the Wi-Fi
// address plus one, as the Pico SDK does: the controller's firmware starts
// with the same address on every board.
func BDAddr(mac [6]byte) [6]byte {
	for i := 5; i >= 0; i-- {
		mac[i]++
		if mac[i] != 0 {
			break
		}
	}
	return mac
}

// Start does nothing: New started the chip.
func (r *Radio) Start() error { return nil }

func (r *Radio) MAC() ([6]byte, bool) {
	m, err := r.Dev.HardwareAddr6()
	return m, err == nil
}

// Connect joins a WPA2 network (or an open one, with no password). From
// the second attempt on, it leaves first: after a reset that did not
// leave (a crash, a power cut, a reflash), the access point may still hold
// the station's old association, and then lets a new join associate but
// never completes the WPA handshake. A failed attempt also leaves the chip
// half-joined, refusing the next join's settings. Leaving clears both.
func (r *Radio) Connect(ssid, password []byte) error {
	if r.attempts > 0 {
		r.Dev.Leave()
	}
	r.attempts++
	opts := cyw43439.JoinOptions{Auth: cyw43439.JoinAuthWPA2, Passphrase: string(password)}
	if len(password) == 0 {
		opts.Auth = cyw43439.JoinAuthOpen
	}
	return r.Dev.Join(string(ssid), opts)
}

func (r *Radio) LinkUp() bool     { return r.Dev.IsLinkUp() }
func (r *Radio) Reconnects() bool { return false }

// Recv polls the chip for one frame.
func (r *Radio) Recv() ([]byte, error) {
	r.rxLen = 0
	if _, err := r.Dev.PollOne(); err != nil {
		return nil, err
	}
	if r.rxLen == 0 {
		return nil, nil
	}
	r.nRx++
	return r.rx[:r.rxLen], nil
}

func (r *Radio) Send(frame []byte) error { return r.Dev.SendEth(frame) }

// SetMulticast programs the chip's multicast filter. It holds 10
// addresses; beyond that, the rest are not received.
func (r *Radio) SetMulticast(macs [][6]byte) error {
	if len(macs) > maxMulticast {
		r.Dev.SetMulticastList(macs[:maxMulticast])
		return errors.New("cyw43wifi: " + strconv.Itoa(len(macs)) + " multicast addresses, the chip holds 10")
	}
	return r.Dev.SetMulticastList(macs)
}

// maxScan bounds the networks a scan keeps.
const maxScan = 24

// Scan scans all 2.4 GHz channels (about 3 s), joined or not. Frames that
// arrive meanwhile are dropped: the radio is off the channel for most of
// it, and MRP retransmits.
func (r *Radio) Scan() ([]wifinode.AccessPoint, error) {
	var aps []wifinode.AccessPoint
	err := r.Dev.Scan(func(res cyw43439.ScanResult) {
		name := res.Name()
		if len(name) == 0 || name[0] == 0 {
			return // hidden
		}
		for i := range aps {
			if aps[i].BSSID == res.BSSID {
				aps[i].RSSI = max(aps[i].RSSI, int(res.RSSI))
				return
			}
		}
		sec := security(res.Security)
		if sec != 0 && len(aps) < maxScan {
			aps = append(aps, wifinode.AccessPoint{SSID: string(name), RSSI: int(res.RSSI),
				Security: sec, BSSID: res.BSSID, Channel: uint16(res.Channel)})
		}
	})
	return aps, err
}

// security maps the driver's flags to a Matter WiFiSecurityBitmap, zero
// for an enterprise-only network, which Matter cannot provision.
func security(s cyw43439.ScanSecurity) uint8 {
	if s == 0 {
		return clusters.WiFiUnencrypted
	}
	var m uint8
	if s&cyw43439.ScanWEP != 0 {
		m |= clusters.WiFiWEP
	}
	if s&cyw43439.ScanWPA != 0 {
		m |= clusters.WiFiWPAPersonal
	}
	if s&cyw43439.ScanWPA2 != 0 {
		m |= clusters.WiFiWPA2
	}
	if s&cyw43439.ScanWPA3 != 0 {
		m |= clusters.WiFiWPA3
	}
	return m
}

func (r *Radio) RSSI() (int, error) { return r.Dev.RSSI() }

func (r *Radio) Stats() string { return "rx frames " + strconv.Itoa(r.nRx) }
