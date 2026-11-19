//go:build m5stack

package main

import (
	tinydev "device"
	"device/esp"
	"machine"
	"runtime/interrupt"
	"runtime/volatile"
	"time"
	"unsafe"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// M5Stack Core with the M5GO base: an Extended Color Light on the base's
// RGB LEDs, its brightness set by an angle unit on Port B, switched by
// button B, its hue turned by buttons A (back) and C (forward): a twelfth
// of the colour circle per click, smoothly while held. The knob and the
// buttons are also a Color Dimmer Switch (endpoint 2): they do the same to
// the lights that endpoint is bound to.
const (
	boardName   = "m5go-light"
	productName = "M5GO Light"

	buttonA  = machine.BUTTON_A // G39: hue back
	buttonB  = machine.BUTTON_B // G38: on and off
	buttonC  = machine.BUTTON_C // G37: hue forward
	resetPin = buttonB          // held 5 s: a factory reset
	ledPin   = machine.GPIO15   // the base's two bars of five SK6812s
	numLEDs  = 10
	knobPin  = machine.GPIO36 // Port B: the angle unit's wiper (ADC1)

	lightEndpoint  = 1
	switchEndpoint = 2

	knobEvery = 50 * time.Millisecond
	knobStep  = 3 // levels the knob must move before it acts

	holdAfter  = 400 * time.Millisecond // a press longer than this is a hold
	debounce   = 30 * time.Millisecond
	hueStep    = 21                     // per click: a twelfth of the circle (0 to 254)
	sweepEvery = 100 * time.Millisecond // while a hue button is held
	sweepRate  = 42                     // hue per second: round in 6 s
	hueResync  = 2 * time.Second        // idle buttons follow the light's hue again
)

var deviceType = clusters.DeviceTypeExtendedColorLight

type light struct {
	d     *device.Device
	id    *clusters.Identify
	onOff *clusters.OnOff
	level *clusters.LevelControl
	color *clusters.ColorControl

	changed bool
	rgb     [3]uint8
	shown   [3]uint8
	drawn   bool

	knob      machine.ADC
	knobAvg   int32 // smoothed reading, 0 to 65535
	knobLevel int   // the level the knob last set (-1: none yet)
	knobNext  time.Time

	back, toggle, forward button
	hue                   int32     // tenths of a hue step, 0 to 2549
	hueAt                 time.Time // last hue change by the buttons
	sweepNext             time.Time
	nudge                 bool // the last level nudge was a step lower
}

// button is a debounced push button, low when pressed.
type button struct {
	pin     machine.Pin
	down    bool
	at      time.Time // pressed at
	changed time.Time
}

// poll reports a click (released before holdAfter) and whether the
// button is being held.
func (b *button) poll(now time.Time) (click, held bool) {
	if down := !b.pin.Get(); down != b.down && now.Sub(b.changed) >= debounce {
		b.down, b.changed = down, now
		if down {
			b.at = now
		} else {
			click = now.Sub(b.at) < holdAfter
		}
	}
	return click, b.down && now.Sub(b.at) >= holdAfter
}

func newApp(d *device.Device) func(now time.Time) {
	l := &light{d: d, knobLevel: -1, changed: true,
		back: button{pin: buttonA}, toggle: button{pin: buttonB}, forward: button{pin: buttonC}}
	for _, p := range []machine.Pin{buttonA, buttonB, buttonC} {
		p.Configure(machine.PinConfig{Mode: machine.PinInput}) // pulled up on the board
	}
	l.id = &clusters.Identify{Type: clusters.IdentifyLightOutput, Effects: true,
		OnIdentify: func(on bool) { println("identify:", on) }}
	l.onOff = &clusters.OnOff{Lighting: true, OnChange: func(on bool) {
		println("light on:", on)
		l.changed = true
	}}
	l.level = clusters.NewLevelControl(l.onOff, true)
	l.level.OnChange = func(uint8) { l.changed = true }
	l.color = clusters.NewColorControl(clusters.ColorAllFeatures, l.onOff, l.level)
	l.color.OnChange = func() { l.changed = true }
	scenes := d.NewScenes()
	l.onOff.Scenes = scenes
	groups := d.NewGroups(l.id)
	groups.Scenes = scenes
	ep := d.Node.AddEndpoint(lightEndpoint, clusters.DeviceTypeExtendedColorLight)
	d.Node.AddCluster(ep, clusters.Descriptor{}, l.id, groups, scenes, l.onOff, l.level, l.color)
	sw := d.Node.AddEndpoint(switchEndpoint, clusters.DeviceTypeColorDimmerSwitch)
	sw.Clients = []uint32{clusters.IDOnOff, clusters.IDLevelControl, clusters.IDColorControl}
	d.Node.AddCluster(sw, clusters.Descriptor{},
		&clusters.Identify{Type: clusters.IdentifyNone}, d.NewBinding())

	ledPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	ledPin.Low()
	busyWait(tReset)
	l.show([3]uint8{0, 0, 8}) // dim blue: starting
	machine.InitADC()
	l.knob = machine.ADC{Pin: knobPin}
	l.knob.Configure(machine.ADCConfig{})
	muteSpeaker()
	return l.poll
}

func (l *light) poll(now time.Time) {
	l.buttons(now)
	if !now.Before(l.knobNext) {
		l.knobNext = now.Add(knobEvery)
		l.readKnob(now)
	}
	l.render(now)
}

// buttons handles B (on and off) and A and C (hue back and forward).
func (l *light) buttons(now time.Time) {
	if click, _ := l.toggle.poll(now); click {
		l.switchTo(now, !l.onOff.On)
	}
	backClick, backHeld := l.back.poll(now)
	fwdClick, fwdHeld := l.forward.poll(now)
	switch {
	case backClick:
		l.turnHue(now, -hueStep*10, 300*time.Millisecond)
	case fwdClick:
		l.turnHue(now, hueStep*10, 300*time.Millisecond)
	case backHeld != fwdHeld && !now.Before(l.sweepNext):
		l.sweepNext = now.Add(sweepEvery)
		step := int32(sweepRate * sweepEvery / (100 * time.Millisecond)) // tenths of a step
		if backHeld {
			step = -step
		}
		l.turnHue(now, step, sweepEvery)
	}
}

// switchTo switches the light, and the bound ones to the same state (not a
// Toggle, so lights that disagreed agree again).
func (l *light) switchTo(now time.Time, on bool) {
	l.onOff.Set(l.d.Node, lightEndpoint, on)
	cmd := uint32(clusters.CmdOff)
	if on {
		cmd = clusters.CmdOn
	}
	l.d.SendBound(now, switchEndpoint, clusters.IDOnOff, cmd, nil)
}

// turnHue moves the hue by delta tenths of a step, at full saturation,
// here and on the bound lights, switching them on if this one is off.
func (l *light) turnHue(now time.Time, delta int32, dur time.Duration) {
	if !l.onOff.On {
		l.switchTo(now, true)
	}
	if now.Sub(l.hueAt) > hueResync { // start from the light's hue
		h, _ := l.color.HueSaturation()
		l.hue = int32(h) * 10
	}
	l.hueAt = now
	l.hue = ((l.hue+delta)%2550 + 2550) % 2550
	hue := uint8(l.hue / 10)
	l.color.MoveToHueSaturation(l.d.Node, lightEndpoint, now, hue, 254, dur)
	tenths := uint64(dur / (100 * time.Millisecond))
	l.d.SendBound(now, switchEndpoint, clusters.IDColorControl, clusters.CmdMoveToHueAndSaturation,
		func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), uint64(hue))
			w.PutUint(tlv.ContextTag(1), 254)    // Saturation
			w.PutUint(tlv.ContextTag(2), tenths) // TransitionTime
			w.PutUint(tlv.ContextTag(3), 0)      // OptionsMask
			w.PutUint(tlv.ContextTag(4), 0)      // OptionsOverride
		})
	// Nanoleaf's string lights take a new colour but show it only when
	// their level (or on/off) next changes: follow it with this light's
	// level, one step lower every other time, so that it is a change.
	level := max(l.level.Level(), 2)
	if l.nudge = !l.nudge; l.nudge {
		level--
	}
	l.d.SendBound(now, switchEndpoint, clusters.IDLevelControl, clusters.CmdMoveToLevelWithOnOff, moveToLevel(level))
}

// readKnob follows the angle unit: its position sets the level, the
// bottom few percent switching the light off. It acts only when the knob
// moves, so a controller's changes stand until someone turns it.
func (l *light) readKnob(now time.Time) {
	keepSpeakerQuiet()
	raw := int32(l.knob.Get())
	if l.knobLevel < 0 {
		l.knobAvg = raw
	}
	l.knobAvg += (raw - l.knobAvg) / 4
	const dead = 65535 * 3 / 100
	lvl := 0
	if l.knobAvg > dead {
		lvl = 1 + int(l.knobAvg-dead)*253/(65535-dead)
	}
	if l.knobLevel < 0 { // the position at start: leave the light as it was
		l.knobLevel = lvl
		return
	}
	if d := lvl - l.knobLevel; d < knobStep && d > -knobStep && (lvl == 0) == (l.knobLevel == 0) {
		return
	}
	l.knobLevel = lvl
	println("knob: level", lvl)
	if lvl == 0 {
		l.level.MoveToLevel(l.d.Node, lightEndpoint, now, 0, 0) // to the minimum: off
		l.onOff.Set(l.d.Node, lightEndpoint, false)
		l.d.SendBound(now, switchEndpoint, clusters.IDOnOff, clusters.CmdOff, nil)
	} else {
		l.level.MoveToLevel(l.d.Node, lightEndpoint, now, uint8(lvl), 0)
		l.d.SendBound(now, switchEndpoint, clusters.IDLevelControl, clusters.CmdMoveToLevelWithOnOff,
			moveToLevel(uint8(lvl)))
	}
}

// moveToLevel encodes MoveToLevel(WithOnOff)'s fields: the level, reached
// in a tenth of a second.
func moveToLevel(level uint8) func(w *tlv.Writer) {
	return func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), uint64(level))
		w.PutUint(tlv.ContextTag(1), 1) // TransitionTime, tenths of a second
		w.PutUint(tlv.ContextTag(2), 0) // OptionsMask
		w.PutUint(tlv.ContextTag(3), 0) // OptionsOverride
	}
}

// render shows the light's colour (white blinking while identifying),
// writing the LEDs only when it changes.
func (l *light) render(now time.Time) {
	var c [3]uint8
	switch {
	case l.id.Identifying():
		if now.UnixMilli()/250%2 == 0 {
			c = [3]uint8{40, 40, 40}
		}
	case l.onOff.On || l.level.Brightness() > 0: // on, or fading off
		if l.changed {
			l.changed = false
			r, g, b := l.color.RGB(l.level.Brightness())
			// Ten LEDs: full scale is half their range.
			l.rgb = [3]uint8{r / 2, g / 2, b / 2}
		}
		c = l.rgb
	case !l.d.Commissioned():
		c = [3]uint8{8, 0, 8} // dim purple: waiting to be commissioned
	}
	if !l.drawn || c != l.shown {
		l.show(c)
	}
}

func ccount() uint32 { return uint32(tinydev.AsmFull("rsr {}, CCOUNT", nil)) }

// SK6812 timing in CPU cycles at 160 MHz (6.25 ns per cycle).
const (
	t0High = 52        // 0.325 us (SK6812: 0.30 ± 0.15 us)
	t1High = 112       // 0.70 us  (SK6812: 0.60 ± 0.15 us)
	tBit   = 200       // 1.25 us
	tReset = 300 * 240 // >= 300 us latch (450 us at 160 MHz)
)

func busyWait(cycles uint32) {
	start := ccount()
	for ccount()-start < cycles {
	}
}

// writeStrip sends the same GRB colour to all numLEDs SK6812 pixels, timing
// bits with the CPU cycle counter. Marked noinline so show's two passes run
// the exact same flash addresses and the second pass hits warm ICache.
//
//go:noinline
func writeStrip(c [3]uint8) {
	set, setMask := ledPin.PortMaskSet()
	clr, clrMask := ledPin.PortMaskClear()
	setReg := (*volatile.Register32)(unsafe.Pointer(set))
	clrReg := (*volatile.Register32)(unsafe.Pointer(clr))
	data := uint32(c[1])<<16 | uint32(c[0])<<8 | uint32(c[2]) // GRB
	state := interrupt.Disable()
	for p := 0; p < numLEDs; p++ {
		for i := 23; i >= 0; i-- {
			high := uint32(t0High)
			if data>>uint(i)&1 != 0 {
				high = t1High
			}
			start := ccount()
			setReg.Set(setMask)
			for ccount()-start < high {
			}
			clrReg.Set(clrMask)
			for ccount()-start < tBit {
			}
		}
	}
	interrupt.Restore(state)
}

func (l *light) show(c [3]uint8) {
	// Code runs from flash XIP: the first pass may stall on ICache misses
	// and stretch a pulse (lighting LED 0 green); the second runs hot from
	// ICache after a > 300 us latch pause and overwrites any glitch.
	writeStrip(c)
	busyWait(tReset)
	writeStrip(c)
	l.shown, l.drawn = c, true
}

// muteSpeaker silences the Core's speaker (G25, DAC1). At reset the ESP32
// leaves DAC1 driven by the ADC1 state machine and its tone generator, so
// every ADC1 reading (the knob) pulses the speaker: a buzz. Detach it, and
// hold the pin with a gentle pull-down rather than driving it, which
// clicks. (From the M5Core gallery's hardware.go.)
func muteSpeaker() {
	esp.SENS.SetSAR_MEAS_CTRL2_SAR1_DAC_XPD_FSM(0)
	esp.SENS.SetSAR_DAC_CTRL2_DAC_CW_EN1(0)
	esp.SENS.SetSAR_DAC_CTRL2_DAC_CW_EN2(0)
	esp.RTC_IO.SetPAD_DAC1_PDAC1_XPD_DAC(0)
	esp.RTC_IO.SetPAD_DAC1_PDAC1_DAC_XPD_FORCE(1)
	esp.RTC_IO.SetPAD_DAC1_PDAC1_MUX_SEL(0)
	esp.RTC_IO.SetPAD_DAC1_PDAC1_FUN_IE(0)
	machine.SPEAKER_PIN.Configure(machine.PinConfig{Mode: machine.PinInputPulldown})
	esp.IO_MUX.SetGPIO25_FUN_IE(0)
	esp.IO_MUX.SetGPIO25_MCU_IE(0)
}

// keepSpeakerQuiet runs before each ADC1 reading: the radio's calibration
// can hand SAR1 back to its state machine, which drives DAC1 again.
func keepSpeakerQuiet() {
	if esp.SENS.GetSAR_MEAS_WAIT2_FORCE_XPD_SAR() != 3 {
		esp.SENS.SetSAR_MEAS_WAIT2_FORCE_XPD_SAR(3)
	}
	if esp.SENS.GetSAR_READ_CTRL_SAR1_DIG_FORCE() != 0 {
		esp.SENS.SetSAR_READ_CTRL_SAR1_DIG_FORCE(0)
	}
	if esp.SENS.GetSAR_MEAS_CTRL2_SAR1_DAC_XPD_FSM() != 0 {
		esp.SENS.SetSAR_MEAS_CTRL2_SAR1_DAC_XPD_FSM(0)
	}
	if esp.RTC_IO.GetPAD_DAC1_PDAC1_DAC_XPD_FORCE() != 1 || esp.RTC_IO.GetPAD_DAC1_PDAC1_XPD_DAC() != 0 || esp.RTC_IO.GetPAD_DAC1_PDAC1_MUX_SEL() != 0 {
		muteSpeaker()
	}
}
