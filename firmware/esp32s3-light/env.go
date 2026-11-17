package main

import (
	"machine"
	"time"

	"firmware/climate"

	"github.com/shabunin/tiny-matter-go/device"
)

// An M5Stack ENV unit (II or III) on the Grove port makes the node a
// temperature, humidity and pressure sensor too. Any other unit there is
// taken for a PIR (see main), an occupancy sensor.
const (
	temperatureEndpoint = 3
	humidityEndpoint    = 4
	pressureEndpoint    = 5
	occupancyEndpoint   = 6
)

// groveI2C reports whether an I2C unit is on the Grove port: it has
// pull-ups on both lines, which a PIR's output and an empty port do not.
func groveI2C() bool {
	groveSDA.Configure(machine.PinConfig{Mode: machine.PinInputPulldown})
	groveSCL.Configure(machine.PinConfig{Mode: machine.PinInputPulldown})
	time.Sleep(time.Millisecond)
	return groveSDA.Get() && groveSCL.Get()
}

// newEnv looks for an ENV unit on the Grove port and adds its sensors. It
// returns nil if there is none.
func newEnv(d *device.Device) *climate.Sensors {
	if !groveI2C() {
		return nil
	}
	i2c := machine.I2C0
	if err := i2c.Configure(machine.I2CConfig{Frequency: 100_000, SDA: groveSDA, SCL: groveSCL}); err != nil {
		println("env: i2c:", err.Error())
		return nil
	}
	return climate.Add(d, i2c, climate.Endpoints{
		Temperature: temperatureEndpoint, Humidity: humidityEndpoint, Pressure: pressureEndpoint})
}
