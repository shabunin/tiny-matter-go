// Package climate makes the sensors of an M5Stack ENV unit (II or III: an
// SHT3x for temperature and humidity, and on the ENV II a BMP280 for
// pressure) Matter Temperature, Humidity and Pressure Sensor endpoints.
package climate

import (
	"time"

	"firmware/envsensor"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/im"
)

const (
	interval = 10 * time.Second
	failures = 3 // failed readings in a row before the values read null
)

// Endpoints are where the quantities go.
type Endpoints struct {
	Temperature, Humidity, Pressure uint16
}

// Sensors are the unit's sensors and their endpoints.
type Sensors struct {
	d   *device.Device
	ep  Endpoints
	sht *envsensor.SHT3x
	bmp *envsensor.BMP280

	temperature, humidity, pressure *clusters.Measurement

	next     time.Time
	started  bool // an SHT3x measurement is under way
	failures int
}

// Add looks for the sensors on bus and adds an endpoint for each quantity
// they measure. It returns nil if there are none.
func Add(d *device.Device, bus envsensor.Bus, ep Endpoints) *Sensors {
	s := &Sensors{d: d, ep: ep}
	if sht := (&envsensor.SHT3x{Bus: bus, Addr: 0x44}); sht.Start() == nil {
		s.sht, s.started = sht, true
	}
	for _, addr := range []uint16{0x76, 0x77} {
		if bmp := (&envsensor.BMP280{Bus: bus, Addr: addr}); bmp.Init() == nil {
			s.bmp = bmp
			break
		}
	}
	if s.sht == nil && s.bmp == nil {
		println("climate: no sensor found")
		return nil
	}
	if s.sht != nil {
		s.temperature = clusters.NewTemperatureMeasurement(clusters.Value(-4000), clusters.Value(12500))
		s.temperature.Tolerance = 20 // SHT30: ±0.2 °C
		s.humidity = clusters.NewHumidityMeasurement(clusters.Value(0), clusters.Value(10000))
		s.humidity.Tolerance = 200 // ±2 %RH
		s.add(ep.Temperature, clusters.DeviceTypeTemperatureSensor, s.temperature)
		s.add(ep.Humidity, clusters.DeviceTypeHumiditySensor, s.humidity)
		println("climate: SHT3x temperature and humidity on endpoints", ep.Temperature, ep.Humidity)
	} else {
		s.temperature = clusters.NewTemperatureMeasurement(clusters.Value(-4000), clusters.Value(8500))
		s.temperature.Tolerance = 100 // BMP280: ±1 °C
		s.add(ep.Temperature, clusters.DeviceTypeTemperatureSensor, s.temperature)
		println("climate: BMP280 temperature on endpoint", ep.Temperature)
	}
	if s.bmp != nil {
		s.pressure = clusters.NewPressureMeasurement(clusters.Value(300), clusters.Value(1100)) // hPa
		s.pressure.Tolerance = 1                                                                // ±1 hPa
		s.add(ep.Pressure, clusters.DeviceTypePressureSensor, s.pressure)
		println("climate: BMP280 pressure on endpoint", ep.Pressure)
	}
	s.next = time.Now().Add(50 * time.Millisecond) // the first SHT3x reading
	return s
}

func (s *Sensors) add(ep uint16, dt im.DeviceType, m *clusters.Measurement) {
	id := &clusters.Identify{Type: clusters.IdentifyVisibleIndicator,
		OnIdentify: func(on bool) { println("sensor", ep, "identify:", on) }}
	s.d.Node.AddCluster(s.d.Node.AddEndpoint(ep, dt), clusters.Descriptor{}, id, m)
}

// Identifying reports whether a controller is identifying one of the
// sensors' endpoints.
func (s *Sensors) Identifying() bool {
	if s == nil {
		return false
	}
	for _, ep := range []uint16{s.ep.Temperature, s.ep.Humidity, s.ep.Pressure} {
		if e := s.d.Node.Endpoint(ep); e != nil {
			if id, ok := e.Cluster(clusters.IDIdentify).(*clusters.Identify); ok && id.Identifying() {
				return true
			}
		}
	}
	return false
}

// Poll takes a reading every 10 s.
func (s *Sensors) Poll(now time.Time) {
	if s == nil || now.Before(s.next) {
		return
	}
	s.next = now.Add(interval)
	n := s.d.Node
	ok := true
	if s.sht != nil {
		if s.started {
			if t, h, err := s.sht.Read(); err == nil {
				s.temperature.Set(n, s.ep.Temperature, clusters.Value(t))
				s.humidity.Set(n, s.ep.Humidity, clusters.Value(h))
			} else {
				ok = s.failed("SHT3x", err)
			}
		}
		// Start the next one; it is read next time round.
		s.started = s.sht.Start() == nil
	}
	if s.bmp != nil {
		if t, p, err := s.bmp.Read(); err == nil {
			if s.sht == nil {
				s.temperature.Set(n, s.ep.Temperature, clusters.Value(t))
			}
			s.pressure.Set(n, s.ep.Pressure, clusters.Value((p+50)/100)) // Pa to 0.1 kPa
		} else {
			ok = s.failed("BMP280", err)
		}
	}
	if ok {
		s.failures = 0
	}
}

// failed counts a failed reading, making the values null once they are
// stale. It returns false.
func (s *Sensors) failed(chip string, err error) bool {
	s.failures++
	if s.failures == 1 {
		println("climate:", chip, "reading failed:", err.Error())
	}
	if s.failures == failures {
		println("climate: readings failing; values now null")
		for _, m := range []struct {
			m  *clusters.Measurement
			ep uint16
		}{{s.temperature, s.ep.Temperature}, {s.humidity, s.ep.Humidity}, {s.pressure, s.ep.Pressure}} {
			if m.m != nil {
				m.m.Set(s.d.Node, m.ep, clusters.Null)
			}
		}
	}
	return false
}
