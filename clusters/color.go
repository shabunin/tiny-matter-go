package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// IDColorControl is the Color Control cluster ID.
const IDColorControl = 0x0300

// Color Control features.
const (
	ColorHueSaturation    = 0x01
	ColorEnhancedHue      = 0x02
	ColorLoop             = 0x04
	ColorXY               = 0x08
	ColorTemperature      = 0x10
	ColorAllFeatures      = 0x1F
	colorFeatureHSFamily  = ColorHueSaturation | ColorEnhancedHue | ColorLoop
	colorModeHS           = 0
	colorModeXY           = 1
	colorModeCT           = 2
	colorModeEnhancedHS   = 3
	colorMaxXY            = 0xFEFF
	colorMaxHue           = 0xFE
	colorMaxSat           = 0xFE
	colorMaxMireds        = 0xFEFF
	colorMaxTransition    = 0xFFFE
	colorTick             = 50 * time.Millisecond
	colorForeverRemaining = 0xFFFE
)

// ColorControl is the Color Control cluster (spec 3.2): hue and
// saturation (8-bit and enhanced 16-bit hue), a colour loop, CIE xy and
// colour temperature, each changed over time. As in the SDK, the values
// of each mode are kept apart; ColorMode and EnhancedColorMode say which
// one the light shows (RGB converts it).
type ColorControl struct {
	im.ClusterBase
	// OnOff is the endpoint's On/Off cluster, for ExecuteIfOff.
	OnOff *OnOff
	// OnChange, if set, is called whenever a colour value or the mode
	// changes, including each step of a transition.
	OnChange func()

	features   uint32
	physMin    uint16 // ColorTempPhysicalMinMireds
	physMax    uint16
	coupleMin  uint16
	hue, sat   uint8
	ehue       uint16
	x, y       uint16
	mireds     uint16
	mode       uint8 // EnhancedColorMode (ColorMode derives from it)
	options    uint8
	startUp    nullU16
	loopActive bool
	loopUp     bool // ColorLoopDirection: increment
	loopTime   uint16
	loopStart  uint16
	loopStored uint16
	axes       [colorAxes]colorAxis
	lastReport time.Time
	lastCouple time.Time
}

// colorAxis is one value moving over time: linearly to a target, or at a
// rate for ever (MoveHue, the colour loop).
type colorAxis struct {
	active  bool
	start   time.Time // zero: from the next Poll
	from    int64
	delta   int64 // finite: total change over dur
	dur     time.Duration
	forever bool
	num     int64 // forever: num/den units per second
	den     int64
	mod     int64 // non-zero: the value wraps
	lo, hi  int64
}

const (
	axHue = iota // CurrentHue or EnhancedCurrentHue (enhanced modes)
	axSat
	axX
	axY
	axCT
	colorAxes
)

// Attribute IDs.
const (
	colorCurrentHue       = 0x0000
	colorCurrentSat       = 0x0001
	colorRemainingTime    = 0x0002
	colorCurrentX         = 0x0003
	colorCurrentY         = 0x0004
	colorTempMireds       = 0x0007
	colorMode             = 0x0008
	colorOptions          = 0x000F
	colorNumPrimaries     = 0x0010
	colorEnhancedHue      = 0x4000
	colorEnhancedMode     = 0x4001
	colorLoopActive       = 0x4002
	colorLoopDirection    = 0x4003
	colorLoopTime         = 0x4004
	colorLoopStartHue     = 0x4005
	colorLoopStoredHue    = 0x4006
	colorCapabilities     = 0x400A
	colorTempPhysMin      = 0x400B
	colorTempPhysMax      = 0x400C
	colorCoupleMin        = 0x400D
	colorStartUpMireds    = 0x4010
	colorExecuteIfOff     = 0x01
	colorDefaultX         = 0x616B
	colorDefaultY         = 0x607D
	colorDefaultMireds    = 250
	colorDefaultPhysMin   = 154
	colorDefaultPhysMax   = 454
	colorDefaultLoopTime  = 25
	colorDefaultLoopStart = 0x2300
)

// Commands.
const (
	colorMoveToHue          = 0x00
	colorMoveHue            = 0x01
	colorStepHue            = 0x02
	colorMoveToSat          = 0x03
	colorMoveSat            = 0x04
	colorStepSat            = 0x05
	colorMoveToHueSat       = 0x06
	colorMoveToColor        = 0x07
	colorMoveColor          = 0x08
	colorStepColor          = 0x09
	colorMoveToTemp         = 0x0A
	colorEnhMoveToHue       = 0x40
	colorEnhMoveHue         = 0x41
	colorEnhStepHue         = 0x42
	colorEnhMoveToHueSat    = 0x43
	colorLoopSet            = 0x44
	colorStopMoveStep       = 0x47
	colorMoveTemp           = 0x4B
	colorStepTemp           = 0x4C
	dirShortest, dirLongest = 0, 1
	dirUp, dirDown          = 2, 3
	moveStop, moveUp        = 0, 1
	moveDown                = 3
)

// NewColorControl returns Color Control with the given features (Color*
// constants; EnhancedHue needs HueSaturation and ColorLoop needs
// EnhancedHue), coupled to the endpoint's On/Off and, for
// CoupleColorTempToLevel, Level Control (either may be nil). It starts at
// 250 mireds (4000 K) if it has ColorTemperature, else at xy
// (0.381, 0.377), else at hue 0.
func NewColorControl(features uint32, onOff *OnOff, level *LevelControl) *ColorControl {
	c := &ColorControl{OnOff: onOff, features: features & ColorAllFeatures,
		physMin: colorDefaultPhysMin, physMax: colorDefaultPhysMax, coupleMin: colorDefaultPhysMin,
		x: colorDefaultX, y: colorDefaultY, mireds: colorDefaultMireds,
		loopTime: colorDefaultLoopTime, loopStart: colorDefaultLoopStart, loopUp: true}
	switch {
	case c.has(ColorTemperature):
		c.mode = colorModeCT
	case c.has(ColorXY):
		c.mode = colorModeXY
	case c.has(ColorEnhancedHue):
		c.mode = colorModeEnhancedHS
	}
	if level != nil {
		level.Color = c
	}
	return c
}

// SetTemperatureRange sets the physical colour temperature range in
// mireds (by default 154-454, 6500 K to 2200 K).
func (c *ColorControl) SetTemperatureRange(minMireds, maxMireds uint16) {
	c.physMin, c.physMax, c.coupleMin = max(minMireds, 1), maxMireds, max(minMireds, 1)
	c.mireds = min(max(c.mireds, c.physMin), c.physMax)
}

func (c *ColorControl) has(f uint32) bool { return c.features&f != 0 }

// Mode returns EnhancedColorMode: 0 hue and saturation, 1 xy, 2 colour
// temperature, 3 enhanced hue and saturation.
func (c *ColorControl) Mode() uint8 { return c.mode }

// HueSaturation returns the 8-bit hue and the saturation.
func (c *ColorControl) HueSaturation() (hue, sat uint8) { return c.hue, c.sat }

// EnhancedHue returns the 16-bit hue.
func (c *ColorControl) EnhancedHue() uint16 { return c.ehue }

// XY returns the CIE 1931 xy colour (units of 1/65536).
func (c *ColorControl) XY() (x, y uint16) { return c.x, c.y }

// Mireds returns the colour temperature in mireds.
func (c *ColorControl) Mireds() uint16 { return c.mireds }

// RGB returns the colour the light should show at a level (0-254) as
// 8-bit RGB, from the attributes of the current mode.
func (c *ColorControl) RGB(level uint8) (r, g, b uint8) {
	switch c.mode {
	case colorModeHS:
		return HSVToRGB(c.hue, c.sat, level)
	case colorModeEnhancedHS:
		return HSVToRGB(uint8(uint32(c.ehue)*254/65535), c.sat, level)
	case colorModeXY:
		return XYToRGB(c.x, c.y, level)
	}
	return MiredsToRGB(c.mireds, level)
}

func (*ColorControl) ID() uint32       { return IDColorControl }
func (*ColorControl) Revision() uint16 { return 7 }

func (c *ColorControl) FeatureMap() uint32 { return c.features }

func (c *ColorControl) Attributes() []uint32 {
	a := []uint32{colorRemainingTime, colorMode, colorOptions, colorNumPrimaries, colorEnhancedMode, colorCapabilities}
	if c.has(ColorHueSaturation) {
		a = append(a, colorCurrentHue, colorCurrentSat)
	}
	if c.has(ColorXY) {
		a = append(a, colorCurrentX, colorCurrentY)
	}
	if c.has(ColorTemperature) {
		a = append(a, colorTempMireds, colorTempPhysMin, colorTempPhysMax, colorCoupleMin, colorStartUpMireds)
	}
	if c.has(ColorEnhancedHue) {
		a = append(a, colorEnhancedHue)
	}
	if c.has(ColorLoop) {
		a = append(a, colorLoopActive, colorLoopDirection, colorLoopTime, colorLoopStartHue, colorLoopStoredHue)
	}
	return a
}

func (c *ColorControl) AcceptedCommands() []uint32 {
	var a []uint32
	if c.has(ColorHueSaturation) {
		a = append(a, colorMoveToHue, colorMoveHue, colorStepHue, colorMoveToSat, colorMoveSat, colorStepSat, colorMoveToHueSat)
	}
	if c.has(ColorXY) {
		a = append(a, colorMoveToColor, colorMoveColor, colorStepColor)
	}
	if c.has(ColorTemperature) {
		a = append(a, colorMoveToTemp)
	}
	if c.has(ColorEnhancedHue) {
		a = append(a, colorEnhMoveToHue, colorEnhMoveHue, colorEnhStepHue, colorEnhMoveToHueSat)
	}
	if c.has(ColorLoop) {
		a = append(a, colorLoopSet)
	}
	if c.has(ColorHueSaturation | ColorXY | ColorTemperature) {
		a = append(a, colorStopMoveStep)
	}
	if c.has(ColorTemperature) {
		a = append(a, colorMoveTemp, colorStepTemp)
	}
	return a
}

func (*ColorControl) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*ColorControl) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (*ColorControl) WritePrivilege(attr uint32) im.Privilege {
	if attr == colorStartUpMireds {
		return im.Manage
	}
	return im.Operate
}

func (c *ColorControl) colorMode() uint8 {
	if c.mode == colorModeEnhancedHS {
		return colorModeHS
	}
	return c.mode
}

func (c *ColorControl) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if !hasID(c.Attributes(), attr) {
		return im.UnsupportedAttribute
	}
	var v uint64
	switch attr {
	case colorCurrentHue:
		v = uint64(c.hue)
	case colorCurrentSat:
		v = uint64(c.sat)
	case colorRemainingTime:
		v = c.remaining(ctx.Now)
	case colorCurrentX:
		v = uint64(c.x)
	case colorCurrentY:
		v = uint64(c.y)
	case colorTempMireds:
		v = uint64(c.mireds)
	case colorMode:
		v = uint64(c.colorMode())
	case colorOptions:
		v = uint64(c.options)
	case colorNumPrimaries:
		w.PutNull(tag)
		return im.Success
	case colorEnhancedHue:
		v = uint64(c.ehue)
	case colorEnhancedMode:
		v = uint64(c.mode)
	case colorLoopActive:
		if c.loopActive {
			v = 1
		}
	case colorLoopDirection:
		if c.loopUp {
			v = 1
		}
	case colorLoopTime:
		v = uint64(c.loopTime)
	case colorLoopStartHue:
		v = uint64(c.loopStart)
	case colorLoopStoredHue:
		v = uint64(c.loopStored)
	case colorCapabilities:
		v = uint64(c.features)
	case colorTempPhysMin:
		v = uint64(c.physMin)
	case colorTempPhysMax:
		v = uint64(c.physMax)
	case colorCoupleMin:
		v = uint64(c.coupleMin)
	case colorStartUpMireds:
		c.startUp.put(w, tag)
		return im.Success
	}
	w.PutUint(tag, v)
	return im.Success
}

func (c *ColorControl) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	var st im.Status
	switch {
	case attr == colorOptions:
		var v uint16
		if v, st = readU16(r, colorExecuteIfOff); st == im.Success {
			c.options = uint8(v)
		}
	case attr == colorStartUpMireds && c.has(ColorTemperature):
		var v nullU16
		if v, st = readNullU16(r, colorMaxMireds); st == im.Success {
			if v.valid && v.v == 0 {
				return im.ConstraintError
			}
			c.startUp = v
		}
	default:
		return im.UnsupportedWrite
	}
	if st == im.Success {
		ctx.Node.Changed(ctx.Endpoint, IDColorControl, attr)
	}
	return st
}

// ---- Transitions ----

func (c *ColorControl) axisAttr(i int) uint32 {
	switch i {
	case axHue:
		if c.mode == colorModeEnhancedHS {
			return colorEnhancedHue
		}
		return colorCurrentHue
	case axSat:
		return colorCurrentSat
	case axX:
		return colorCurrentX
	case axY:
		return colorCurrentY
	}
	return colorTempMireds
}

// setAxis stores an axis value, reporting whether it changed.
func (c *ColorControl) setAxis(i int, v int64) bool {
	old := c.axisValue(i)
	switch i {
	case axHue:
		if c.mode == colorModeEnhancedHS {
			c.ehue = uint16(v)
			c.hue = uint8(min(c.ehue>>8, colorMaxHue))
		} else {
			c.hue = uint8(v)
		}
	case axSat:
		c.sat = uint8(v)
	case axX:
		c.x = uint16(v)
	case axY:
		c.y = uint16(v)
	case axCT:
		c.mireds = uint16(v)
	}
	return c.axisValue(i) != old
}

func (c *ColorControl) axisValue(i int) int64 {
	switch i {
	case axHue:
		if c.mode == colorModeEnhancedHS {
			return int64(c.ehue)
		}
		return int64(c.hue)
	case axSat:
		return int64(c.sat)
	case axX:
		return int64(c.x)
	case axY:
		return int64(c.y)
	}
	return int64(c.mireds)
}

func (a *colorAxis) value(now time.Time) (v int64, done bool) {
	el := time.Duration(0)
	if !a.start.IsZero() {
		el = now.Sub(a.start)
	}
	switch {
	case a.forever:
		v = a.from + a.num*int64(el/time.Millisecond)/(a.den*1000)
	case el >= a.dur:
		v, done = a.from+a.delta, true
	default:
		v = a.from + a.delta*int64(el)/int64(a.dur)
	}
	if a.mod != 0 {
		v = (v%a.mod + a.mod) % a.mod
	} else if !a.forever {
		v = min(max(v, a.lo), a.hi)
	}
	return v, done
}

// moveAxis moves axis i by delta over dur (at once if dur is zero),
// wrapping at mod or clamping to lo..hi.
func (c *ColorControl) moveAxis(n *im.Node, ep uint16, now time.Time, i int, delta int64, dur time.Duration, mod, lo, hi int64) {
	a := colorAxis{active: true, start: now, from: c.axisValue(i), delta: delta, dur: dur, mod: mod, lo: lo, hi: hi}
	if dur <= 0 {
		v, _ := a.value(now.Add(time.Nanosecond))
		c.axes[i] = colorAxis{}
		if c.setAxis(i, v) {
			c.changed()
		}
		n.Changed(ep, IDColorControl, c.axisAttr(i))
		return
	}
	c.axes[i] = a
}

// rateAxis moves axis i at num/den units per second for ever.
func (c *ColorControl) rateAxis(now time.Time, i int, num, den, mod int64) {
	c.axes[i] = colorAxis{active: true, start: now, from: c.axisValue(i), forever: true, num: num, den: den, mod: mod}
}

func (c *ColorControl) changed() {
	if c.OnChange != nil {
		c.OnChange()
	}
}

// stopAll ends every transition where it is, and the colour loop.
func (c *ColorControl) stopAll(n *im.Node, ep uint16) {
	for i := range c.axes {
		if c.axes[i].active {
			c.axes[i] = colorAxis{}
			n.Changed(ep, IDColorControl, c.axisAttr(i))
		}
	}
	if c.loopActive {
		c.loopActive = false
		n.Changed(ep, IDColorControl, colorLoopActive)
	}
	n.Changed(ep, IDColorControl, colorRemainingTime)
}

// remaining returns RemainingTime: the longest transition left, in
// tenths of a second.
func (c *ColorControl) remaining(now time.Time) uint64 {
	var r uint64
	for i := range c.axes {
		a := &c.axes[i]
		switch {
		case !a.active:
		case a.forever:
			return colorForeverRemaining
		case a.start.IsZero():
			r = max(r, uint64(min(a.dur/(100*time.Millisecond), colorMaxTransition)))
		default:
			r = max(r, remainingDS(now, a.start.Add(a.dur)))
		}
	}
	return r
}

// Poll advances the transitions (im.Poller).
func (c *ColorControl) Poll(n *im.Node, ep uint16, now time.Time) time.Time {
	active, changed := false, false
	var next time.Time
	report := false
	for i := range c.axes {
		a := &c.axes[i]
		if !a.active {
			continue
		}
		if a.start.IsZero() {
			a.start = now
		}
		v, done := a.value(now)
		if c.setAxis(i, v) {
			changed = true
		}
		if done {
			*a = colorAxis{}
			n.Changed(ep, IDColorControl, c.axisAttr(i))
			if c.remaining(now) == 0 {
				n.Changed(ep, IDColorControl, colorRemainingTime)
			}
			continue
		}
		active = true
		total := a.dur
		if a.forever {
			total = 40 * time.Second // reported every 10 s
		} else {
			next = earliest(next, a.start.Add(a.dur))
		}
		if quietReport(now, c.lastReport, total) {
			report = true
		}
	}
	if report {
		c.lastReport = now
		for i := range c.axes {
			if c.axes[i].active {
				n.Changed(ep, IDColorControl, c.axisAttr(i))
			}
		}
	}
	if changed {
		c.changed()
	}
	if !active {
		return time.Time{}
	}
	return earliest(next, now.Add(colorTick))
}

// setMode switches the colour mode for a command.
func (c *ColorControl) setMode(n *im.Node, ep uint16, mode uint8) {
	if mode == c.mode {
		return
	}
	oldColorMode := c.colorMode()
	if mode == colorModeEnhancedHS {
		c.ehue = uint16(c.hue) << 8
	}
	c.mode = mode
	n.Changed(ep, IDColorControl, colorEnhancedMode)
	if c.colorMode() != oldColorMode {
		n.Changed(ep, IDColorControl, colorMode)
	}
	c.changed()
}

// startCommand ends the running transitions (and loop) and changes mode.
func (c *ColorControl) startCommand(n *im.Node, ep uint16, mode uint8) {
	c.stopAll(n, ep)
	c.setMode(n, ep, mode)
}

// hueDelta returns the change from cur to target along a direction, in a
// hue space of size mod.
func hueDelta(cur, target, mod int64, dir uint64) int64 {
	up := ((target-cur)%mod + mod) % mod
	down := up - mod
	if up == 0 {
		return 0
	}
	switch dir {
	case dirShortest:
		if up <= mod/2 {
			return up
		}
		return down
	case dirLongest:
		if up > mod/2 {
			return up
		}
		return down
	case dirUp:
		return up
	}
	return down
}

// tempRange returns the colour temperature bounds of Move and Step
// ColorTemperature.
func (c *ColorControl) tempRange(minField, maxField uint64) (lo, hi int64) {
	lo = int64(max(uint64(c.physMin), minField, 1))
	hi = int64(c.physMax)
	if maxField != 0 {
		hi = min(int64(maxField), hi)
	}
	return lo, hi
}

func (c *ColorControl) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	if !hasID(c.AcceptedCommands(), cmd) {
		return im.UnsupportedCommand
	}
	f, ok := decodeNumFields(r)
	if !ok {
		return im.InvalidCommand
	}
	n, ep, now := ctx.Node, ctx.Endpoint, ctx.Now
	// Each command's mandatory fields and where its options fields are.
	var (
		need    []uint8
		maskTag uint8
	)
	switch cmd {
	case colorMoveToHue, colorEnhMoveToHue, colorStepHue, colorEnhStepHue, colorStepSat,
		colorMoveToHueSat, colorEnhMoveToHueSat, colorMoveToColor, colorStepColor:
		need, maskTag = []uint8{0, 1, 2}, 3
	case colorMoveHue, colorEnhMoveHue, colorMoveToSat, colorMoveSat, colorMoveColor, colorMoveToTemp:
		need, maskTag = []uint8{0, 1}, 2
	case colorLoopSet:
		need, maskTag = []uint8{0, 1, 2, 3, 4}, 5
	case colorStopMoveStep:
		maskTag = 0
	case colorMoveTemp:
		need, maskTag = []uint8{0, 1, 2, 3}, 4
	case colorStepTemp:
		need, maskTag = []uint8{0, 1, 2, 3, 4}, 5
	}
	if !f.present(need...) {
		return im.InvalidCommand
	}
	run, st := c.validate(cmd, &f)
	if st != im.Success {
		return st
	}
	if !executeIfOff(c.OnOff, c.options, &f, maskTag) {
		return im.Success
	}
	run(n, ep, now)
	return im.Success
}

// ttField reads a transition time field.
func ttField(f *numFields, tag uint8, max int64) (time.Duration, im.Status) {
	v, ok := f.u(tag, max)
	if !ok {
		return 0, im.ConstraintError
	}
	return deciseconds(uint16(v)), im.Success
}

// validate checks a command's fields and returns what it does.
func (c *ColorControl) validate(cmd uint32, f *numFields) (func(n *im.Node, ep uint16, now time.Time), im.Status) {
	noop := func(*im.Node, uint16, time.Time) {}
	switch cmd {
	case colorMoveToHue, colorEnhMoveToHue:
		enhanced := cmd == colorEnhMoveToHue
		hmax, mod, mode := int64(colorMaxHue), int64(255), uint8(colorModeHS)
		if enhanced {
			hmax, mod, mode = 0xFFFF, 65536, colorModeEnhancedHS
		}
		hue, ok := f.u(0, hmax)
		dir, okDir := f.u(1, dirDown)
		dur, st := ttField(f, 2, colorMaxTransition)
		switch {
		case !ok:
			return nil, im.ConstraintError
		case !okDir:
			return nil, im.InvalidCommand
		case st != im.Success:
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, mode)
			c.moveAxis(n, ep, now, axHue, hueDelta(c.axisValue(axHue), int64(hue), mod, dir), dur, mod, 0, 0)
		}, im.Success

	case colorMoveHue, colorEnhMoveHue:
		enhanced := cmd == colorEnhMoveHue
		rmax, mod, mode := int64(0xFF), int64(255), uint8(colorModeHS)
		if enhanced {
			rmax, mod, mode = 0xFFFF, 65536, colorModeEnhancedHS
		}
		mv, ok := f.u(0, moveDown)
		rate, okR := f.u(1, rmax)
		if !ok || mv == 2 || !okR || (rate == 0 && mv != moveStop) {
			return nil, im.InvalidCommand
		}
		if mv == moveStop {
			return func(n *im.Node, ep uint16, now time.Time) { c.stopAll(n, ep) }, im.Success
		}
		sign := int64(1)
		if mv == moveDown {
			sign = -1
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, mode)
			c.rateAxis(now, axHue, sign*int64(rate), 1, mod)
			n.Changed(ep, IDColorControl, colorRemainingTime)
		}, im.Success

	case colorStepHue, colorEnhStepHue:
		enhanced := cmd == colorEnhStepHue
		smax, ttmax, mod, mode := int64(0xFF), int64(0xFF), int64(255), uint8(colorModeHS)
		if enhanced {
			smax, ttmax, mod, mode = 0xFFFF, colorMaxTransition, 65536, colorModeEnhancedHS
		}
		mv, ok := f.u(0, moveDown)
		size, okS := f.u(1, smax)
		dur, st := ttField(f, 2, ttmax)
		if !ok || (mv != moveUp && mv != moveDown) || !okS || size == 0 {
			return nil, im.InvalidCommand
		}
		if st != im.Success {
			return nil, st
		}
		delta := int64(size)
		if mv == moveDown {
			delta = -delta
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, mode)
			c.moveAxis(n, ep, now, axHue, delta, dur, mod, 0, 0)
		}, im.Success

	case colorMoveToSat:
		sat, ok := f.u(0, colorMaxSat)
		dur, st := ttField(f, 1, colorMaxTransition)
		if !ok {
			return nil, im.ConstraintError
		}
		if st != im.Success {
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, c.hsMode())
			c.moveAxis(n, ep, now, axSat, int64(sat)-int64(c.sat), dur, 0, 0, colorMaxSat)
		}, im.Success

	case colorMoveSat:
		mv, ok := f.u(0, moveDown)
		rate, okR := f.u(1, 0xFF)
		if !ok || mv == 2 || !okR || (rate == 0 && mv != moveStop) {
			return nil, im.InvalidCommand
		}
		if mv == moveStop {
			return func(n *im.Node, ep uint16, now time.Time) { c.stopAll(n, ep) }, im.Success
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			target := int64(colorMaxSat)
			if mv == moveDown {
				target = 0
			}
			c.startCommand(n, ep, c.hsMode())
			delta := target - int64(c.sat)
			c.moveAxis(n, ep, now, axSat, delta, rateDuration(delta, int64(rate)), 0, 0, colorMaxSat)
		}, im.Success

	case colorStepSat:
		mv, ok := f.u(0, moveDown)
		size, okS := f.u(1, 0xFF)
		dur, st := ttField(f, 2, 0xFF)
		if !ok || (mv != moveUp && mv != moveDown) || !okS || size == 0 {
			return nil, im.InvalidCommand
		}
		if st != im.Success {
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			target := int64(c.sat) + int64(size)
			if mv == moveDown {
				target = int64(c.sat) - int64(size)
			}
			target = min(max(target, 0), colorMaxSat)
			c.startCommand(n, ep, c.hsMode())
			c.moveAxis(n, ep, now, axSat, target-int64(c.sat), dur, 0, 0, colorMaxSat)
		}, im.Success

	case colorMoveToHueSat, colorEnhMoveToHueSat:
		enhanced := cmd == colorEnhMoveToHueSat
		hmax, mod, mode := int64(colorMaxHue), int64(255), uint8(colorModeHS)
		if enhanced {
			hmax, mod, mode = 0xFFFF, 65536, colorModeEnhancedHS
		}
		hue, ok := f.u(0, hmax)
		sat, okS := f.u(1, colorMaxSat)
		dur, st := ttField(f, 2, colorMaxTransition)
		if !ok || !okS {
			return nil, im.ConstraintError
		}
		if st != im.Success {
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, mode)
			c.moveAxis(n, ep, now, axHue, hueDelta(c.axisValue(axHue), int64(hue), mod, dirShortest), dur, mod, 0, 0)
			c.moveAxis(n, ep, now, axSat, int64(sat)-int64(c.sat), dur, 0, 0, colorMaxSat)
		}, im.Success

	case colorMoveToColor:
		x, okX := f.u(0, colorMaxXY)
		y, okY := f.u(1, colorMaxXY)
		dur, st := ttField(f, 2, colorMaxTransition)
		if !okX || !okY {
			return nil, im.ConstraintError
		}
		if st != im.Success {
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, colorModeXY)
			c.moveAxis(n, ep, now, axX, int64(x)-int64(c.x), dur, 0, 0, colorMaxXY)
			c.moveAxis(n, ep, now, axY, int64(y)-int64(c.y), dur, 0, 0, colorMaxXY)
		}, im.Success

	case colorMoveColor:
		rx, ry := f.v[0], f.v[1]
		if rx < -0x8000 || rx > 0x7FFF || ry < -0x8000 || ry > 0x7FFF {
			return nil, im.ConstraintError
		}
		if rx == 0 && ry == 0 {
			return func(n *im.Node, ep uint16, now time.Time) { c.stopAll(n, ep) }, im.Success
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, colorModeXY)
			for i, rate := range [colorAxes]int64{axX: rx, axY: ry} {
				if rate == 0 || (i != axX && i != axY) {
					continue
				}
				target := int64(colorMaxXY)
				if rate < 0 {
					target, rate = 0, -rate
				}
				delta := target - c.axisValue(i)
				c.moveAxis(n, ep, now, i, delta, rateDuration(delta, rate), 0, 0, colorMaxXY)
			}
		}, im.Success

	case colorStepColor:
		sx, sy := f.v[0], f.v[1]
		dur, st := ttField(f, 2, colorMaxTransition)
		if sx < -0x8000 || sx > 0x7FFF || sy < -0x8000 || sy > 0x7FFF {
			return nil, im.ConstraintError
		}
		if sx == 0 && sy == 0 {
			return nil, im.InvalidCommand
		}
		if st != im.Success {
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.startCommand(n, ep, colorModeXY)
			tx := min(max(int64(c.x)+sx, 0), colorMaxXY)
			ty := min(max(int64(c.y)+sy, 0), colorMaxXY)
			c.moveAxis(n, ep, now, axX, tx-int64(c.x), dur, 0, 0, colorMaxXY)
			c.moveAxis(n, ep, now, axY, ty-int64(c.y), dur, 0, 0, colorMaxXY)
		}, im.Success

	case colorMoveToTemp:
		m, ok := f.u(0, colorMaxMireds)
		dur, st := ttField(f, 1, colorMaxTransition)
		if !ok {
			return nil, im.ConstraintError
		}
		if st != im.Success {
			return nil, st
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.moveToMireds(n, ep, now, uint16(m), dur)
		}, im.Success

	case colorMoveTemp:
		mv, ok := f.u(0, moveDown)
		rate, okR := f.u(1, 0xFFFF)
		lo, okLo := f.u(2, colorMaxMireds)
		hi, okHi := f.u(3, colorMaxMireds)
		if !ok || mv == 2 || !okR || (rate == 0 && mv != moveStop) {
			return nil, im.InvalidCommand
		}
		if !okLo || !okHi || (lo != 0 && hi != 0 && lo > hi) {
			return nil, im.ConstraintError
		}
		if mv == moveStop {
			return func(n *im.Node, ep uint16, now time.Time) { c.stopAll(n, ep) }, im.Success
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			low, high := c.tempRange(lo, hi)
			target := high
			if mv == moveDown {
				target = low
			}
			c.startCommand(n, ep, colorModeCT)
			delta := target - int64(c.mireds)
			c.moveAxis(n, ep, now, axCT, delta, rateDuration(delta, int64(rate)), 0, low, high)
		}, im.Success

	case colorStepTemp:
		mv, ok := f.u(0, moveDown)
		size, okS := f.u(1, 0xFFFF)
		dur, st := ttField(f, 2, colorMaxTransition)
		lo, okLo := f.u(3, colorMaxMireds)
		hi, okHi := f.u(4, colorMaxMireds)
		if !ok || (mv != moveUp && mv != moveDown) || !okS || size == 0 {
			return nil, im.InvalidCommand
		}
		if st != im.Success || !okLo || !okHi || (lo != 0 && hi != 0 && lo > hi) {
			return nil, im.ConstraintError
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			low, high := c.tempRange(lo, hi)
			target := int64(c.mireds) + int64(size)
			if mv == moveDown {
				target = int64(c.mireds) - int64(size)
			}
			target = min(max(target, low), high)
			c.startCommand(n, ep, colorModeCT)
			c.moveAxis(n, ep, now, axCT, target-int64(c.mireds), dur, 0, low, high)
		}, im.Success

	case colorLoopSet:
		flags, ok := f.u(0, 0xFF)
		action, okA := f.u(1, 2)
		dir, okD := f.u(2, 1)
		secs, okT := f.u(3, 0xFFFF)
		start, okS := f.u(4, 0xFFFF)
		if !ok || !okA || !okD || !okT || !okS {
			return nil, im.InvalidCommand
		}
		return func(n *im.Node, ep uint16, now time.Time) {
			c.loopSet(n, ep, now, uint8(flags), uint8(action), dir == 1, uint16(secs), uint16(start))
		}, im.Success

	case colorStopMoveStep:
		return func(n *im.Node, ep uint16, now time.Time) {
			if c.loopActive {
				return // the colour loop is stopped with ColorLoopSet
			}
			c.stopAll(n, ep)
		}, im.Success
	}
	return noop, im.UnsupportedCommand
}

// hsMode returns the mode a saturation command switches to: enhanced if
// it already is.
func (c *ColorControl) hsMode() uint8 {
	if c.mode == colorModeEnhancedHS {
		return colorModeEnhancedHS
	}
	return colorModeHS
}

// rateDuration returns how long a change of delta takes at rate units per
// second.
func rateDuration(delta, rate int64) time.Duration {
	if delta < 0 {
		delta = -delta
	}
	return time.Duration(delta) * time.Second / time.Duration(rate)
}

// moveToMireds moves the colour temperature within the physical range.
func (c *ColorControl) moveToMireds(n *im.Node, ep uint16, now time.Time, m uint16, dur time.Duration) {
	lo, hi := int64(max(c.physMin, 1)), int64(c.physMax)
	target := min(max(int64(m), lo), hi)
	c.startCommand(n, ep, colorModeCT)
	c.moveAxis(n, ep, now, axCT, target-int64(c.mireds), dur, 0, lo, hi)
}

// loopSet runs ColorLoopSet: direction, time and start hue updates, then
// the action.
func (c *ColorControl) loopSet(n *im.Node, ep uint16, now time.Time, flags, action uint8, up bool, secs, start uint16) {
	if flags&0x02 != 0 && c.loopUp != up {
		c.loopUp = up
		n.Changed(ep, IDColorControl, colorLoopDirection)
	}
	if flags&0x04 != 0 && c.loopTime != secs {
		c.loopTime = secs
		n.Changed(ep, IDColorControl, colorLoopTime)
	}
	if flags&0x08 != 0 && c.loopStart != start {
		c.loopStart = start
		n.Changed(ep, IDColorControl, colorLoopStartHue)
	}
	if flags&0x01 != 0 {
		switch action {
		case 0:
			if c.loopActive {
				c.stopAll(n, ep)
				c.ehue = c.loopStored
				c.hue = uint8(min(c.ehue>>8, colorMaxHue))
				n.Changed(ep, IDColorControl, colorEnhancedHue)
				c.changed()
			}
			return
		case 1, 2:
			from := c.loopStart
			if action == 2 {
				from = c.ehue
			}
			c.startLoop(n, ep, now, from)
			return
		}
	}
	if c.loopActive && flags&0x06 != 0 { // re-anchor at the new speed
		c.startLoop(n, ep, now, c.ehue)
	}
}

// startLoop runs the colour loop from a hue: a full turn of the enhanced
// hue every ColorLoopTime seconds.
func (c *ColorControl) startLoop(n *im.Node, ep uint16, now time.Time, from uint16) {
	wasActive := c.loopActive
	c.startCommand(n, ep, colorModeEnhancedHS)
	if !wasActive && c.loopStored != c.ehue {
		c.loopStored = c.ehue
		n.Changed(ep, IDColorControl, colorLoopStoredHue)
	}
	c.setAxis(axHue, int64(from))
	sign := int64(-1)
	if c.loopUp {
		sign = 1
	}
	c.rateAxis(now, axHue, sign*65536, int64(max(c.loopTime, 1)), 65536)
	c.loopActive = true
	n.Changed(ep, IDColorControl, colorLoopActive)
	n.Changed(ep, IDColorControl, colorRemainingTime)
	c.changed()
}

// coupleToLevel follows Level Control with the colour temperature
// (CoupleColorTempToLevel): warmest at the minimum level, coolest
// (CoupleColorTempToLevelMinMireds) at the maximum.
func (c *ColorControl) coupleToLevel(n *im.Node, ep uint16, now time.Time, level uint8, report bool) {
	if !c.has(ColorTemperature) || c.mode != colorModeCT {
		return
	}
	var m int64
	switch {
	case level <= 1:
		m = int64(c.physMax)
	case level >= colorMaxHue:
		m = int64(c.coupleMin)
	default:
		m = int64(c.physMax) - (int64(c.physMax)-int64(c.coupleMin))*int64(level)/254
	}
	c.axes[axCT] = colorAxis{}
	if c.setAxis(axCT, m) {
		c.changed()
		report = report || quietReport(now, c.lastCouple, 0)
	}
	if report {
		c.lastCouple = now
		n.Changed(ep, IDColorControl, colorTempMireds)
	}
}

// ---- Scenes ----

func (c *ColorControl) sceneSave(dst []scenePair) []scenePair {
	if c.has(ColorXY) {
		dst = append(dst, scenePair{colorCurrentX, sceneU16, int64(c.x)}, scenePair{colorCurrentY, sceneU16, int64(c.y)})
	}
	if c.has(ColorEnhancedHue) {
		dst = append(dst, scenePair{colorEnhancedHue, sceneU16, int64(c.ehue)})
	}
	if c.has(ColorHueSaturation) {
		dst = append(dst, scenePair{colorCurrentSat, sceneU8, int64(c.sat)}, scenePair{colorCurrentHue, sceneU8, int64(c.hue)})
	}
	if c.has(ColorLoop) {
		active, up := int64(0), int64(0)
		if c.loopActive {
			active = 1
		}
		if c.loopUp {
			up = 1
		}
		dst = append(dst, scenePair{colorLoopActive, sceneU8, active}, scenePair{colorLoopDirection, sceneU8, up},
			scenePair{colorLoopTime, sceneU16, int64(c.loopTime)})
	}
	if c.has(ColorTemperature) {
		dst = append(dst, scenePair{colorTempMireds, sceneU16, int64(c.mireds)})
	}
	return append(dst, scenePair{colorEnhancedMode, sceneU8, int64(c.mode)})
}

func (c *ColorControl) sceneKind(attr uint32) uint8 {
	switch attr {
	case colorCurrentX, colorCurrentY:
		if c.has(ColorXY) {
			return sceneU16
		}
	case colorEnhancedHue:
		if c.has(ColorEnhancedHue) {
			return sceneU16
		}
	case colorCurrentSat, colorCurrentHue:
		if c.has(ColorHueSaturation) {
			return sceneU8
		}
	case colorLoopActive, colorLoopDirection:
		if c.has(ColorLoop) {
			return sceneU8
		}
	case colorLoopTime:
		if c.has(ColorLoop) {
			return sceneU16
		}
	case colorTempMireds:
		if c.has(ColorTemperature) {
			return sceneU16
		}
	case colorEnhancedMode:
		return sceneU8
	}
	return 0
}

func (c *ColorControl) sceneClamp(p *scenePair) {
	switch p.attr {
	case colorCurrentX, colorCurrentY:
		clampPair(p, 0, colorMaxXY)
	case colorCurrentSat, colorCurrentHue:
		clampPair(p, 0, colorMaxHue)
	case colorLoopActive, colorLoopDirection:
		clampPair(p, 0, 1)
	case colorTempMireds:
		clampPair(p, int64(c.physMin), int64(c.physMax))
	case colorEnhancedMode:
		clampPair(p, 0, colorModeEnhancedHS)
	default:
		clampPair(p, 0, 0xFFFF)
	}
}

func (c *ColorControl) sceneApply(n *im.Node, ep uint16, now time.Time, pairs []scenePair, dur time.Duration) im.Status {
	mode := int64(colorModeHS)
	if v, ok := sceneValue(pairs, colorEnhancedMode); ok {
		mode = v
	}
	get := func(attr uint32, def int64) int64 {
		if v, ok := sceneValue(pairs, attr); ok {
			return v
		}
		return def
	}
	switch mode {
	case colorModeHS, colorModeEnhancedHS:
		if !c.has(ColorHueSaturation) || (mode == colorModeEnhancedHS && !c.has(ColorEnhancedHue)) {
			return im.Failure
		}
	case colorModeXY:
		if !c.has(ColorXY) {
			return im.Failure
		}
	case colorModeCT:
		if !c.has(ColorTemperature) {
			return im.Failure
		}
	default:
		return im.Failure
	}
	if c.has(ColorLoop) && get(colorLoopActive, 0) == 1 {
		c.loopUp = get(colorLoopDirection, 0) == 1
		c.loopTime = uint16(get(colorLoopTime, int64(c.loopTime)))
		c.startLoop(n, ep, now, c.loopStart)
		return im.Success
	}
	c.startCommand(n, ep, uint8(mode))
	switch mode {
	case colorModeHS:
		hue := get(colorCurrentHue, int64(c.hue))
		c.moveAxis(n, ep, now, axHue, hueDelta(int64(c.hue), hue, 255, dirShortest), dur, 255, 0, 0)
		c.moveAxis(n, ep, now, axSat, get(colorCurrentSat, int64(c.sat))-int64(c.sat), dur, 0, 0, colorMaxSat)
	case colorModeEnhancedHS:
		hue := get(colorEnhancedHue, int64(c.ehue))
		c.moveAxis(n, ep, now, axHue, hueDelta(int64(c.ehue), hue, 65536, dirShortest), dur, 65536, 0, 0)
		c.moveAxis(n, ep, now, axSat, get(colorCurrentSat, int64(c.sat))-int64(c.sat), dur, 0, 0, colorMaxSat)
	case colorModeXY:
		c.moveAxis(n, ep, now, axX, get(colorCurrentX, int64(c.x))-int64(c.x), dur, 0, 0, colorMaxXY)
		c.moveAxis(n, ep, now, axY, get(colorCurrentY, int64(c.y))-int64(c.y), dur, 0, 0, colorMaxXY)
	case colorModeCT:
		c.moveToMireds(n, ep, now, uint16(get(colorTempMireds, int64(c.mireds))), dur)
	}
	return im.Success
}

// ---- Persistence ----

// EncodeState saves the colour, the mode, the options, the loop settings
// and StartUpColorTemperatureMireds (im.Persister).
func (c *ColorControl) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(0), uint64(c.hue))
	w.PutUint(tlv.ContextTag(1), uint64(c.sat))
	w.PutUint(tlv.ContextTag(2), uint64(c.ehue))
	w.PutUint(tlv.ContextTag(3), uint64(c.x))
	w.PutUint(tlv.ContextTag(4), uint64(c.y))
	w.PutUint(tlv.ContextTag(5), uint64(c.mireds))
	w.PutUint(tlv.ContextTag(6), uint64(c.mode))
	w.PutUint(tlv.ContextTag(7), uint64(c.options))
	up := uint64(0)
	if c.loopUp {
		up = 1
	}
	w.PutUint(tlv.ContextTag(8), up)
	w.PutUint(tlv.ContextTag(9), uint64(c.loopTime))
	w.PutUint(tlv.ContextTag(10), uint64(c.loopStart))
	if c.startUp.valid {
		w.PutUint(tlv.ContextTag(11), uint64(c.startUp.v))
	}
	w.EndContainer()
}

// DecodeState restores the state and applies StartUpColorTemperatureMireds
// (im.Persister).
func (c *ColorControl) DecodeState(r *tlv.Reader) error {
	c.startUp = nullU16{}
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		v, err := r.Uint()
		if err != nil {
			return err
		}
		switch tag {
		case 0:
			c.hue = uint8(min(v, colorMaxHue))
		case 1:
			c.sat = uint8(min(v, colorMaxSat))
		case 2:
			c.ehue = uint16(v)
		case 3:
			c.x = uint16(min(v, colorMaxXY))
		case 4:
			c.y = uint16(min(v, colorMaxXY))
		case 5:
			c.mireds = uint16(v)
		case 6:
			c.mode = uint8(v)
		case 7:
			c.options = uint8(v) & colorExecuteIfOff
		case 8:
			c.loopUp = v == 1
		case 9:
			c.loopTime = uint16(v)
		case 10:
			c.loopStart = uint16(v)
		case 11:
			c.startUp = nullU16{uint16(v), true}
		}
		return nil
	})
	if !c.supportsMode(c.mode) {
		c.mode = NewColorControl(c.features, nil, nil).mode
	}
	c.mireds = min(max(c.mireds, c.physMin), c.physMax)
	if c.has(ColorTemperature) && c.startUp.valid && c.startUp.v >= max(c.physMin, 1) && c.startUp.v <= c.physMax {
		c.mireds = c.startUp.v
		c.mode = colorModeCT
	}
	return err
}

func (c *ColorControl) supportsMode(mode uint8) bool {
	switch mode {
	case colorModeHS:
		return c.has(ColorHueSaturation)
	case colorModeXY:
		return c.has(ColorXY)
	case colorModeCT:
		return c.has(ColorTemperature)
	case colorModeEnhancedHS:
		return c.has(ColorEnhancedHue)
	}
	return false
}
