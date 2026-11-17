//go:build m5stick_c

package main

import (
	"machine"
	"time"

	"firmware/climate"
	"firmware/softi2c"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
)

// M5StickC (or StickC Plus) with an ENV HAT on its header, or an ENV unit
// on its Grove port: temperature, humidity and pressure sensors.
const (
	boardName   = "m5stickc-climate"
	productName = "M5StickC Climate"

	resetPin = machine.GPIO37 // the M5 button: held 5 s, a factory reset
	ledPin   = machine.GPIO10 // red LED, lit when low
)

// The buses an ENV can be on, tried in turn. Both are bit-banged: TinyGo's
// I2C controller gets no answer from these pins on the classic ESP32.
var envBuses = []struct {
	name     string
	sda, scl machine.Pin
}{
	{"hat", machine.GPIO0, machine.GPIO26},
	{"grove", machine.GPIO32, machine.GPIO33},
}

var deviceType = clusters.DeviceTypeTemperatureSensor

func newApp(d *device.Device) func(now time.Time) {
	ledPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	ledPin.High()
	var s *climate.Sensors
	for _, b := range envBuses {
		bus := &softi2c.Bus{SDA: b.sda, SCL: b.scl}
		bus.Configure()
		if s = climate.Add(d, bus, climate.Endpoints{Temperature: 1, Humidity: 2, Pressure: 3}); s != nil {
			println("env on the", b.name, "bus")
			break
		}
	}
	return func(now time.Time) {
		s.Poll(now)
		// Blink the LED while a controller identifies a sensor.
		ledPin.Set(!(s.Identifying() && now.UnixMilli()/250%2 == 0))
	}
}
