package main

import (
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/storage"
)

const (
	lightEndpoint  = 1
	switchEndpoint = 2

	debounce  = 20 * time.Millisecond
	resetHold = 5 * time.Second // holding G0 this long erases the state
)

// Test event triggers (General Diagnostics TestEventTrigger) that work
// the button, with the Switch cluster ID in the upper bits as in the
// SDK's trigger values.
const (
	triggerClick = 0x003B000000000001 // press the button for 150 ms
	triggerLong  = 0x003B000000000002 // hold it for 1.5 s

	// The SDK's OTA requestor trigger: query the default providers now.
	triggerOTAQuery = 0x002A000000000100
)

// ui is the board's user interface. The G0 button is a Generic Switch on
// endpoint 2 and, held for 5 s, a factory reset. The RGB LED is the light
// (its colour and brightness) or, while the node is not commissioned, shows
// the commissioning mode (dim cyan: over BLE, dim purple: over IP); it
// blinks while an endpoint identifies itself, white for the light and
// green for the button.
type ui struct {
	d     *device.Device
	store *storage.Flash
	// alive, if set, runs first in every poll: it feeds the watchdog.
	alive func(now time.Time)

	button   clusters.Switch
	lightID  clusters.Identify
	buttonID clusters.Identify
	onOff    *clusters.OnOff
	level    *clusters.LevelControl
	color    *clusters.ColorControl
	rgb      [3]uint8 // the light's colour, while on
	changed  bool     // the light changed: recompute rgb
	ble      bool     // waiting for BLE commissioning

	sample    bool      // the last button sample (true: pressed)
	sampledAt time.Time // when the sample last changed
	pressed   bool      // the debounced button state
	pressedAt time.Time
	releaseAt time.Time // when a triggered press ends (zero: none)

	shown [3]uint8 // the colour on the LED
	drawn bool
}

// newUI adds the light (endpoint 1, an Extended Color Light) and the
// button (endpoint 2) to the node.
func newUI(d *device.Device, store *storage.Flash) *ui {
	u := &ui{d: d, store: store, changed: true}
	u.lightID = clusters.Identify{Type: clusters.IdentifyLightOutput, Effects: true,
		OnIdentify: func(on bool) { println("light identify:", on, "effect", u.lightID.Effect()) }}
	u.buttonID = clusters.Identify{Type: clusters.IdentifyVisibleIndicator,
		OnIdentify: func(on bool) { println("button identify:", on) }}
	u.onOff = &clusters.OnOff{Lighting: true,
		OnChange: func(on bool) {
			if on {
				println("LIGHT ON")
			} else {
				println("LIGHT OFF")
			}
			u.changed = true
		},
	}
	u.level = clusters.NewLevelControl(u.onOff, true)
	u.level.OnChange = func(uint8) { u.changed = true }
	u.color = clusters.NewColorControl(clusters.ColorAllFeatures, u.onOff, u.level)
	u.color.OnChange = func() { u.changed = true }
	scenes := d.NewScenes()
	u.onOff.Scenes = scenes
	groups := d.NewGroups(&u.lightID)
	groups.Scenes = scenes
	light := d.Node.AddEndpoint(lightEndpoint, clusters.DeviceTypeExtendedColorLight)
	d.Node.AddCluster(light, clusters.Descriptor{}, &u.lightID, groups, scenes, u.onOff, u.level, u.color)
	sw := d.Node.AddEndpoint(switchEndpoint, clusters.DeviceTypeGenericSwitch)
	d.Node.AddCluster(sw, clusters.Descriptor{}, &u.buttonID, &u.button)
	return u
}

// poll debounces the button, ends triggered presses and updates the LED.
func (u *ui) poll(now time.Time) {
	if u.alive != nil {
		u.alive(now)
	}
	n := u.d.Node
	if s := buttonPressed(); s != u.sample {
		u.sample, u.sampledAt = s, now
	}
	if u.sample != u.pressed && now.Sub(u.sampledAt) >= debounce {
		u.pressed = u.sample
		if u.pressed {
			println("button pressed")
			u.pressedAt = now
			u.button.Press(n, switchEndpoint, now)
		} else {
			println("button released")
			u.button.Release(n, switchEndpoint, now)
		}
	}
	if u.pressed && now.Sub(u.pressedAt) >= resetHold {
		println("factory reset")
		setLED(40, 30, 0) // yellow: erasing
		u.store.Erase()
		time.Sleep(500 * time.Millisecond)
		restart()
	}
	if !u.releaseAt.IsZero() && !now.Before(u.releaseAt) {
		u.releaseAt = time.Time{}
		u.button.Release(n, switchEndpoint, now)
	}
	u.updateLED(now)
}

// trigger serves the test event triggers that work the button.
func (u *ui) trigger(ctx *im.Context, trigger uint64) im.Status {
	var hold time.Duration
	switch trigger {
	case triggerClick:
		hold = 150 * time.Millisecond
	case triggerLong:
		hold = 1500 * time.Millisecond
	case triggerOTAQuery:
		if !u.d.CheckForUpdate(ctx.Now) {
			return im.InvalidInState
		}
		println("test event trigger: querying the default OTA providers")
		return im.Success
	default:
		return im.InvalidCommand
	}
	println("test event trigger: button held", hold.String())
	u.button.Press(ctx.Node, switchEndpoint, ctx.Now)
	u.releaseAt = ctx.Now.Add(hold)
	return im.Success
}

// updateLED shows the colour the state calls for, writing the LED only
// when it changes.
func (u *ui) updateLED(now time.Time) {
	var c [3]uint8
	switch {
	case u.lightID.Identifying() || u.buttonID.Identifying():
		if now.UnixMilli()/250%2 == 0 {
			c = [3]uint8{40, 40, 40} // white: the light
			if !u.lightID.Identifying() {
				c = [3]uint8{0, 40, 0} // green: the button
			}
		}
	case u.onOff.On || u.level.Brightness() > 0: // on, or fading off
		if u.changed {
			u.changed = false
			r, g, b := u.color.RGB(u.level.Brightness())
			// The LED is bright: full scale is 3/8 of its range.
			u.rgb = [3]uint8{uint8(uint16(r) * 3 / 8), uint8(uint16(g) * 3 / 8), uint8(uint16(b) * 3 / 8)}
		}
		c = u.rgb
	case u.d.Commissioned():
	case u.ble:
		c = [3]uint8{0, 8, 8} // dim cyan
	default:
		c = [3]uint8{8, 0, 8} // dim purple
	}
	if !u.drawn || c != u.shown {
		setLED(c[0], c[1], c[2])
		u.shown, u.drawn = c, true
	}
}

// bootReason maps the reason the CPU last reset to a General Diagnostics
// boot reason.
func bootReason(cause uint32) uint8 {
	switch cause {
	case 0x01: // power on, or the EN pin
		return clusters.BootPowerOn
	case 0x0F:
		return clusters.BootBrownOut
	case 0x07, 0x08, 0x0B, 0x11: // timer group (MWDT) watchdogs
		return clusters.BootSoftwareWatchdog
	case 0x09, 0x0D, 0x10, 0x12: // RTC and super watchdogs
		return clusters.BootHardwareWatchdog
	case 0x03, 0x0C: // software system or CPU reset
		return clusters.BootSoftwareReset
	}
	return clusters.BootUnspecified // e.g. 0x15: reset over USB
}
