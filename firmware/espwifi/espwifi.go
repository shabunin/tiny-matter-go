// Package espwifi is the ESP32 and ESP32-S3 Wi-Fi radio (espradio) as a
// wifinode.Radio.
package espwifi

import (
	"strconv"
	"sync/atomic"

	"firmware/wifinode"

	"tinygo.org/x/espradio"
)

// Radio is the espradio station. Set Config (as passed to espradio.Enable)
// before Start. espradio reconnects by itself after losing the link.
type Radio struct {
	Config espradio.Config

	link   espradio.Link
	nd     *espradio.NetDev
	params espradio.STAConfig
	linked bool // link set up
	frame  []byte
	up     atomic.Bool // set from espradio's link callback
}

var _ wifinode.Radio = (*Radio)(nil)

// Start starts Wi-Fi (espradio.Enable must have been called).
func (r *Radio) Start() error { return espradio.Start() }

// MAC returns the station address.
func (r *Radio) MAC() ([6]byte, bool) {
	m, err := espradio.StationMAC()
	return m, err == nil
}

// Connect joins the network. Once it is up, espradio rejoins it every 3 s
// after the link drops.
func (r *Radio) Connect(ssid, password []byte) error {
	r.params = espradio.STAConfig{SSID: string(ssid), Password: string(password)}
	if !r.linked {
		r.linked = true
		r.link = espradio.Link{Config: r.Config}
		r.link.LinkNotify(func(connected bool) (int, espradio.STAConfig) {
			r.up.Store(connected)
			if !connected {
				return 3, r.params
			}
			return 0, espradio.STAConfig{}
		})
	}
	if err := r.link.LinkConnect(r.params); err != nil {
		return err
	}
	r.nd = r.link.NetDev()
	r.up.Store(true)
	return nil
}

func (r *Radio) LinkUp() bool     { return r.up.Load() }
func (r *Radio) Reconnects() bool { return true }

// Recv polls for a frame. The buffer is on the heap, allocated once: not
// on main's stack, which packet handling (CASE, certificate checks) takes
// close to its end, and not a package-level var (on the classic ESP32,
// growing .bss by that much breaks the Wi-Fi handshake, "auth expired").
func (r *Radio) Recv() ([]byte, error) {
	if r.nd == nil {
		return nil, nil
	}
	if r.frame == nil {
		r.frame = make([]byte, espradio.MaxFrameSize)
	}
	off, size, err := r.nd.EthPoll(r.frame)
	if err != nil || size == 0 {
		return nil, err
	}
	return r.frame[off : off+size], nil
}

func (r *Radio) Send(frame []byte) error {
	if r.nd == nil {
		return nil
	}
	return r.nd.SendOffsetEthFrame(frame)
}

// SetMulticast does nothing: espradio passes all multicast frames.
func (r *Radio) SetMulticast([][6]byte) error { return nil }

func (r *Radio) Scan() ([]wifinode.AccessPoint, error) { return Scan() }

func (r *Radio) RSSI() (int, error) {
	v, err := espradio.RSSI()
	return int(v), err
}

func (r *Radio) Stats() string {
	rx, drops := espradio.NetifRxStats()
	return "rx frames " + strconv.Itoa(int(rx)) + " ring drops " + strconv.Itoa(int(drops))
}

// Scan scans with espradio (Wi-Fi must be started).
func Scan() ([]wifinode.AccessPoint, error) {
	aps, err := espradio.Scan()
	if err != nil {
		return nil, err
	}
	out := make([]wifinode.AccessPoint, len(aps))
	for i, ap := range aps {
		out[i] = wifinode.AccessPoint{SSID: ap.SSID, RSSI: int(ap.RSSI)}
	}
	return out, nil
}
