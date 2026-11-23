package main

import (
	"time"

	"firmware/cyw43wifi"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
)

// light is the On/Off Light on endpoint 1, shown on the LED.
type light struct {
	d     *device.Device
	radio *cyw43wifi.Radio
	id    *clusters.Identify
	onOff *clusters.OnOff
	led   bool
	set   bool // led has been written once
}

func newLight(d *device.Device, radio *cyw43wifi.Radio) *light {
	l := &light{d: d, radio: radio}
	l.id = &clusters.Identify{Type: clusters.IdentifyLightOutput, Effects: true,
		OnIdentify: func(on bool) { println("identify:", on) }}
	l.onOff = &clusters.OnOff{Lighting: true, OnChange: func(on bool) { println("light on:", on) }}
	scenes := d.NewScenes()
	l.onOff.Scenes = scenes
	groups := d.NewGroups(l.id)
	groups.Scenes = scenes
	ep := d.Node.AddEndpoint(lightEndpoint, clusters.DeviceTypeOnOffLight)
	d.Node.AddCluster(ep, clusters.Descriptor{}, l.id, groups, scenes, l.onOff)
	return l
}

// poll shows the light, or what the device is doing, on the LED. The LED
// is on the Wi-Fi chip, so it is written only when it changes.
func (l *light) poll(now time.Time) {
	ms := now.UnixMilli()
	var on bool
	switch {
	case l.id.Identifying():
		on = ms/250%2 == 0
	case !l.d.Commissioned():
		on = ms%1000 < 80
	default:
		on = l.onOff.On
	}
	if on == l.led && l.set {
		return
	}
	if err := l.radio.Dev.GPIOSet(0, on); err == nil {
		l.led, l.set = on, true
	}
}
