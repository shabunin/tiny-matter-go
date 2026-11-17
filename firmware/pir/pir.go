// Package pir makes a PIR motion sensor (such as the M5Stack PIR unit, an
// AS312 whose output is high while it sees motion) a Matter Occupancy
// Sensor endpoint.
package pir

import (
	"machine"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
)

const debounce = 100 * time.Millisecond

// Sensor is a PIR on Pin, reported as occupancy on Endpoint. The PIR's
// own output drops a few seconds after the last motion; the area stays
// occupied for Hold after that, so presence does not flicker.
type Sensor struct {
	Pin      machine.Pin
	Endpoint uint16
	Hold     time.Duration

	d   *device.Device
	occ *clusters.OccupancySensing

	sample    bool
	sampledAt time.Time
	lastSeen  time.Time // motion last seen
}

// DefaultHold is how long the area stays occupied after the last motion.
const DefaultHold = 30 * time.Second

// Add configures pin (mode: an input mode, with a pull-down where the
// pin has one) and adds the Occupancy Sensor endpoint ep to d's node.
func Add(d *device.Device, pin machine.Pin, mode machine.PinMode, ep uint16) *Sensor {
	pin.Configure(machine.PinConfig{Mode: mode})
	s := &Sensor{Pin: pin, Endpoint: ep, Hold: DefaultHold, d: d,
		occ: &clusters.OccupancySensing{Sensors: clusters.OccupancyPassiveInfrared}}
	id := &clusters.Identify{Type: clusters.IdentifyVisibleIndicator,
		OnIdentify: func(on bool) { println("occupancy sensor identify:", on) }}
	e := d.Node.AddEndpoint(ep, clusters.DeviceTypeOccupancySensor)
	e.Clients = []uint32{clusters.IDOnOff}
	d.Node.AddCluster(e, clusters.Descriptor{}, id, s.occ, d.NewBinding())
	return s
}

// Poll follows the PIR output.
func (s *Sensor) Poll(now time.Time) {
	if s == nil {
		return
	}
	if v := s.Pin.Get(); v != s.sample {
		s.sample, s.sampledAt = v, now
	}
	motion := s.sample && now.Sub(s.sampledAt) >= debounce
	if motion {
		s.lastSeen = now
	}
	occupied := motion || s.occ.Occupied() && now.Sub(s.lastSeen) < s.Hold
	if occupied != s.occ.Occupied() {
		println("occupied:", occupied)
		s.occ.Set(s.d.Node, s.Endpoint, now, occupied)
		// Switch the bound lights (tmctl bind) with the occupancy.
		cmd := uint32(clusters.CmdOff)
		if occupied {
			cmd = clusters.CmdOn
		}
		if n := s.d.SendBound(now, s.Endpoint, clusters.IDOnOff, cmd, nil); n > 0 {
			println("occupancy: On/Off to", n, "bound target(s)")
		}
	}
}
