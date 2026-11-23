// Package cyw43wifi is the Wi-Fi radio of the Raspberry Pi Pico W and
// Pico 2 W, a CYW43439 driven by soypat/cyw43439, as a wifinode.Radio.
package cyw43wifi

import (
	"errors"
	"strconv"

	"firmware/wifinode"

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

// New powers the chip up and loads its firmware (about 1.5 s).
func New() (*Radio, error) {
	r := &Radio{Dev: cyw43439.NewPicoWDevice(), rx: make([]byte, cyw43439.MaxFrameSize)}
	if err := r.Dev.Init(cyw43439.DefaultWifiConfig()); err != nil {
		return nil, err
	}
	// The driver calls the handler while it holds its lock, so a reply
	// sent from inside it would deadlock: Recv copies the frame out and
	// returns it after the poll.
	r.Dev.RecvEthHandle(func(f []byte) { r.rxLen = copy(r.rx, f) })
	return r, nil
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

// Scan reports no networks: the driver cannot scan yet.
func (r *Radio) Scan() ([]wifinode.AccessPoint, error) { return nil, nil }

func (r *Radio) RSSI() (int, error) { return r.Dev.RSSI() }

func (r *Radio) Stats() string { return "rx frames " + strconv.Itoa(r.nRx) }
