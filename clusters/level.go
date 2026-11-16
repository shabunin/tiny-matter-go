package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// IDLevelControl is the Level Control cluster ID.
const IDLevelControl = 0x0008

// LevelControl is the Level Control cluster (spec 1.6) with the OnOff
// feature and, for lights, the Lighting feature: a level that moves over
// time, coupled to the endpoint's On/Off cluster.
//
// Transitions run in Poll: CurrentLevel moves linearly, and is reported
// when a transition ends and at most once a second (or a quarter of the
// transition) along the way; OnChange sees every step.
type LevelControl struct {
	im.ClusterBase
	// OnOff is the endpoint's On/Off cluster (set by NewLevelControl).
	OnOff *OnOff
	// Color, if set, is the endpoint's Color Control, whose colour
	// temperature follows the level when the CoupleColorTempToLevel
	// option is set.
	Color *ColorControl
	// OnChange, if set, is called when CurrentLevel changes, including
	// each step of a transition.
	OnChange func(level uint8)

	lighting                 bool
	min, max                 uint8
	current                  uint8
	options                  uint8
	onOffTransition          uint16
	onLevel                  nullU8
	onTransition, offTransit nullU16
	defaultMoveRate          nullU8
	startUp                  nullU8

	mv         levelMove
	fadingOff  bool  // fading to the minimum after an Off
	beforeOff  uint8 // the level to return to after the fade
	lastReport time.Time
}

// levelMove is a transition of CurrentLevel.
type levelMove struct {
	active    bool
	from, to  uint8
	start     time.Time // zero: from the next Poll
	dur       time.Duration
	withOnOff bool // a WithOnOff command: OnOff follows the level at the end
	offFade   bool // the fade of an Off
}

const (
	levelCurrent          = 0x0000
	levelRemainingTime    = 0x0001
	levelMin              = 0x0002
	levelMax              = 0x0003
	levelOptions          = 0x000F
	levelOnOffTransition  = 0x0010
	levelOnLevel          = 0x0011
	levelOnTransition     = 0x0012
	levelOffTransition    = 0x0013
	levelDefaultMoveRate  = 0x0014
	levelStartUp          = 0x4000
	levelFeatureOnOff     = 0x1
	levelFeatureLighting  = 0x2
	levelExecuteIfOff     = 0x1
	levelCoupleColorTemp  = 0x2
	levelCmdMoveToLevel   = 0x00
	levelCmdMove          = 0x01
	levelCmdStep          = 0x02
	levelCmdStop          = 0x03
	levelWithOnOff        = 0x04 // added to a command ID
	levelModeUp           = 0
	levelModeDown         = 1
	levelMinStep          = 10 * time.Millisecond
	defaultLevelMoveRate  = 50 // units per second
	levelOptionsMax       = 0x03
	levelMaxTransitionDS  = 0xFFFE
	levelNullU8, levelTop = 0xFF, 0xFE
)

var (
	levelAttrs = []uint32{levelCurrent, levelRemainingTime, levelMin, levelMax, levelOptions,
		levelOnOffTransition, levelOnLevel, levelOnTransition, levelOffTransition, levelDefaultMoveRate}
	levelLightingAttrs = append(levelAttrs[:len(levelAttrs):len(levelAttrs)], levelStartUp)
	levelCmds          = []uint32{0, 1, 2, 3, 4, 5, 6, 7}
)

// NewLevelControl returns Level Control coupled to onOff (which it sets
// up to drive it). lighting selects the Lighting feature: levels 1-254
// and StartUpCurrentLevel. The level starts at the maximum.
func NewLevelControl(onOff *OnOff, lighting bool) *LevelControl {
	l := &LevelControl{OnOff: onOff, lighting: lighting, min: 0, max: levelTop,
		defaultMoveRate: nullU8{defaultLevelMoveRate, true}}
	if lighting {
		l.min = 1
	}
	l.current = l.max
	if onOff != nil {
		onOff.Level = l
	}
	return l
}

// Level returns CurrentLevel.
func (l *LevelControl) Level() uint8 { return l.current }

// Brightness returns the level the light should show: CurrentLevel while
// on or fading off, zero while off.
func (l *LevelControl) Brightness() uint8 {
	if l.OnOff == nil || l.OnOff.On || l.fadingOff {
		return l.current
	}
	return 0
}

func (*LevelControl) ID() uint32       { return IDLevelControl }
func (*LevelControl) Revision() uint16 { return 6 }

func (l *LevelControl) FeatureMap() uint32 {
	if l.lighting {
		return levelFeatureOnOff | levelFeatureLighting
	}
	return levelFeatureOnOff
}

func (l *LevelControl) Attributes() []uint32 {
	if l.lighting {
		return levelLightingAttrs
	}
	return levelAttrs
}

func (*LevelControl) AcceptedCommands() []uint32 { return levelCmds }

func (*LevelControl) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*LevelControl) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (*LevelControl) WritePrivilege(attr uint32) im.Privilege {
	if attr == levelStartUp {
		return im.Manage
	}
	return im.Operate
}

func (l *LevelControl) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case levelCurrent:
		w.PutUint(tag, uint64(l.current))
	case levelRemainingTime:
		w.PutUint(tag, l.remaining(ctx.Now))
	case levelMin:
		w.PutUint(tag, uint64(l.min))
	case levelMax:
		w.PutUint(tag, uint64(l.max))
	case levelOptions:
		w.PutUint(tag, uint64(l.options))
	case levelOnOffTransition:
		w.PutUint(tag, uint64(l.onOffTransition))
	case levelOnLevel:
		l.onLevel.put(w, tag)
	case levelOnTransition:
		l.onTransition.put(w, tag)
	case levelOffTransition:
		l.offTransit.put(w, tag)
	case levelDefaultMoveRate:
		l.defaultMoveRate.put(w, tag)
	case levelStartUp:
		if !l.lighting {
			return im.UnsupportedAttribute
		}
		l.startUp.put(w, tag)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (l *LevelControl) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	var st im.Status
	switch attr {
	case levelOptions:
		var v uint16
		if v, st = readU16(r, levelOptionsMax); st == im.Success {
			l.options = uint8(v)
		}
	case levelOnOffTransition:
		l.onOffTransition, st = readU16(r, 0xFFFF)
	case levelOnLevel:
		var v nullU8
		if v, st = readNullU8(r, levelTop); st == im.Success {
			if v.valid && (v.v < l.min || v.v > l.max) {
				return im.ConstraintError
			}
			l.onLevel = v
		}
	case levelOnTransition, levelOffTransition:
		var v nullU16
		if v, st = readNullU16(r, levelMaxTransitionDS); st == im.Success {
			if attr == levelOnTransition {
				l.onTransition = v
			} else {
				l.offTransit = v
			}
		}
	case levelDefaultMoveRate:
		var v nullU8
		if v, st = readNullU8(r, levelTop); st == im.Success {
			if v.valid && v.v == 0 {
				return im.ConstraintError
			}
			l.defaultMoveRate = v
		}
	case levelStartUp:
		if !l.lighting {
			return im.UnsupportedWrite
		}
		l.startUp, st = readNullU8(r, levelTop)
	default:
		return im.UnsupportedWrite
	}
	if st == im.Success {
		ctx.Node.Changed(ctx.Endpoint, IDLevelControl, attr)
	}
	return st
}

func (l *LevelControl) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	if cmd > 7 {
		return im.UnsupportedCommand
	}
	f, ok := decodeNumFields(r)
	if !ok {
		return im.InvalidCommand
	}
	n, ep, now := ctx.Node, ctx.Endpoint, ctx.Now
	withOnOff := cmd >= levelWithOnOff
	var (
		to      uint8
		dur     time.Duration
		maskTag uint8
	)
	switch cmd &^ levelWithOnOff {
	case levelCmdMoveToLevel:
		if !f.present(0, 1) {
			return im.InvalidCommand
		}
		v, ok := f.u(0, levelTop)
		if !ok {
			return im.ConstraintError
		}
		to = l.clamp(uint8(v))
		dur = deciseconds(l.onOffTransition)
		if !f.isNull(1) {
			ds, ok := f.u(1, 0xFFFF)
			if !ok {
				return im.ConstraintError
			}
			dur = deciseconds(uint16(ds))
		}
		maskTag = 2
	case levelCmdMove:
		if !f.present(0, 1) {
			return im.InvalidCommand
		}
		mode, ok := f.u(0, levelModeDown)
		if !ok {
			return im.InvalidCommand
		}
		rate := l.defaultMoveRate
		if !f.isNull(1) {
			v, ok := f.u(1, levelTop)
			if !ok || v == 0 {
				return im.InvalidCommand
			}
			rate = nullU8{uint8(v), true}
		}
		to = l.max
		if mode == levelModeDown {
			to = l.min
		}
		if rate.valid { // otherwise as fast as possible
			dur = time.Duration(absDiff(to, l.current)) * time.Second / time.Duration(rate.v)
		}
		maskTag = 2
	case levelCmdStep:
		if !f.present(0, 1, 2) {
			return im.InvalidCommand
		}
		mode, ok1 := f.u(0, levelModeDown)
		size, ok2 := f.u(1, 0xFF)
		if !ok1 || !ok2 || size == 0 {
			return im.InvalidCommand
		}
		target := int(l.current) + int(size)
		if mode == levelModeDown {
			target = int(l.current) - int(size)
		}
		to = uint8(min(max(target, int(l.min)), int(l.max)))
		if !f.isNull(2) {
			ds, ok := f.u(2, 0xFFFF)
			if !ok {
				return im.ConstraintError
			}
			// A step cut short at a bound takes proportionally less time.
			dur = deciseconds(uint16(ds)) * time.Duration(absDiff(to, l.current)) / time.Duration(size)
		}
		maskTag = 3
	case levelCmdStop:
		if !withOnOff && !executeIfOff(l.OnOff, l.options, &f, 0) {
			return im.Success
		}
		l.stop(n, ep, now)
		return im.Success
	}
	if !withOnOff && !executeIfOff(l.OnOff, l.options, &f, maskTag) {
		return im.Success
	}
	l.moveTo(n, ep, now, to, dur, withOnOff)
	return im.Success
}

func absDiff(a, b uint8) uint8 {
	if a > b {
		return a - b
	}
	return b - a
}

func (l *LevelControl) clamp(v uint8) uint8 { return min(max(v, l.min), l.max) }

// moveTo starts a transition to level over dur, cancelling any other. A
// WithOnOff move upwards turns the light on first, and one that ends at
// the minimum turns it off.
func (l *LevelControl) moveTo(n *im.Node, ep uint16, now time.Time, to uint8, dur time.Duration, withOnOff bool) {
	l.fadingOff = false
	if withOnOff && to >= l.current && l.OnOff != nil {
		l.OnOff.set(n, ep, now, to != l.min, true)
	}
	l.start(n, ep, now, levelMove{from: l.current, to: to, start: now, dur: dur, withOnOff: withOnOff})
}

func (l *LevelControl) start(n *im.Node, ep uint16, now time.Time, mv levelMove) {
	wasRemaining := l.remaining(now)
	mv.active = true
	l.mv = mv
	if mv.dur <= 0 || mv.from == mv.to {
		l.finish(n, ep, now)
		return
	}
	if rem := l.remaining(now); rem > 10 && absDiff16(rem, wasRemaining) > 10 {
		n.Changed(ep, IDLevelControl, levelRemainingTime)
	}
	l.lastReport = now
}

func absDiff16(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// remaining returns RemainingTime in tenths of a second.
func (l *LevelControl) remaining(now time.Time) uint64 {
	if !l.mv.active {
		return 0
	}
	if l.mv.start.IsZero() {
		return uint64(min(l.mv.dur/(100*time.Millisecond), levelMaxTransitionDS))
	}
	return remainingDS(now, l.mv.start.Add(l.mv.dur))
}

// stop ends a transition where it is (Stop).
func (l *LevelControl) stop(n *im.Node, ep uint16, now time.Time) {
	if !l.mv.active {
		return
	}
	l.mv.active = false
	l.fadingOff = false
	n.Changed(ep, IDLevelControl, levelCurrent)
	n.Changed(ep, IDLevelControl, levelRemainingTime)
}

// setLevel changes CurrentLevel, reporting it if report is set.
func (l *LevelControl) setLevel(n *im.Node, ep uint16, now time.Time, v uint8, report bool) {
	changed := v != l.current
	l.current = v
	if report {
		n.Changed(ep, IDLevelControl, levelCurrent)
		l.lastReport = now
	}
	if changed && l.OnChange != nil {
		l.OnChange(v)
	}
	if (changed || report) && l.options&levelCoupleColorTemp != 0 && l.Color != nil {
		l.Color.coupleToLevel(n, ep, now, v, report)
	}
}

// finish ends the transition at its target.
func (l *LevelControl) finish(n *im.Node, ep uint16, now time.Time) {
	mv := l.mv
	l.mv.active = false
	l.setLevel(n, ep, now, mv.to, true)
	n.Changed(ep, IDLevelControl, levelRemainingTime)
	if mv.withOnOff && l.OnOff != nil {
		l.OnOff.set(n, ep, now, l.current != l.min, true)
	}
	if mv.offFade {
		l.fadingOff = false
		if !l.onLevel.valid {
			l.setLevel(n, ep, now, l.beforeOff, true)
		}
	}
}

// onOffChanged moves the level when the light turns on or off (spec
// 1.6.4.1.1): off fades to the minimum and, without OnLevel, returns to
// the previous level afterwards (while off); on starts from the minimum
// and rises to OnLevel or the previous level.
func (l *LevelControl) onOffChanged(n *im.Node, ep uint16, now time.Time, on bool) {
	if on {
		target := l.current
		if l.fadingOff {
			target = l.beforeOff
		}
		if l.onLevel.valid {
			target = l.onLevel.v
		}
		l.fadingOff = false
		l.mv.active = false
		l.setLevel(n, ep, now, l.min, false)
		dur := deciseconds(l.onOffTransition)
		if l.onTransition.valid {
			dur = deciseconds(l.onTransition.v)
		}
		l.start(n, ep, now, levelMove{from: l.min, to: l.clamp(target), start: now, dur: dur})
		return
	}
	if !l.fadingOff {
		l.beforeOff = l.current
		if l.mv.active { // a move in progress counts as done (a scene)
			l.beforeOff = l.mv.to
		}
	}
	l.fadingOff = true
	dur := deciseconds(l.onOffTransition)
	if l.offTransit.valid {
		dur = deciseconds(l.offTransit.v)
	}
	l.start(n, ep, now, levelMove{from: l.current, to: l.min, start: now, dur: dur, offFade: true})
}

// Poll advances a transition (im.Poller).
func (l *LevelControl) Poll(n *im.Node, ep uint16, now time.Time) time.Time {
	if !l.mv.active {
		return time.Time{}
	}
	mv := &l.mv
	if mv.start.IsZero() {
		mv.start = now
	}
	elapsed := now.Sub(mv.start)
	if elapsed >= mv.dur {
		l.finish(n, ep, now)
		return time.Time{}
	}
	delta := int(mv.to) - int(mv.from)
	v := int(mv.from) + int(int64(delta)*int64(elapsed)/int64(mv.dur))
	l.setLevel(n, ep, now, uint8(v), quietReport(now, l.lastReport, mv.dur))
	step := max(mv.dur/time.Duration(max(absDiff(mv.to, mv.from), 1)), levelMinStep)
	return earliest(now.Add(step), mv.start.Add(mv.dur))
}

// EncodeState saves CurrentLevel and the writable attributes
// (im.Persister).
func (l *LevelControl) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	level := l.current
	if l.fadingOff {
		level = l.beforeOff
	}
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(0), uint64(level))
	w.PutUint(tlv.ContextTag(1), uint64(l.options))
	w.PutUint(tlv.ContextTag(2), uint64(l.onOffTransition))
	putIf8 := func(t uint8, v nullU8) {
		if v.valid {
			w.PutUint(tlv.ContextTag(t), uint64(v.v))
		}
	}
	putIf16 := func(t uint8, v nullU16) {
		if v.valid {
			w.PutUint(tlv.ContextTag(t), uint64(v.v))
		}
	}
	putIf8(3, l.onLevel)
	putIf16(4, l.onTransition)
	putIf16(5, l.offTransit)
	if l.defaultMoveRate.valid {
		putIf8(6, l.defaultMoveRate)
	} else {
		w.PutNull(tlv.ContextTag(6))
	}
	putIf8(7, l.startUp)
	w.EndContainer()
}

// DecodeState restores the state and applies StartUpCurrentLevel
// (im.Persister).
func (l *LevelControl) DecodeState(r *tlv.Reader) error {
	l.onLevel, l.onTransition, l.offTransit, l.startUp = nullU8{}, nullU16{}, nullU16{}, nullU8{}
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		if r.IsNull() {
			if tag == 6 {
				l.defaultMoveRate = nullU8{}
			}
			return nil
		}
		v, err := r.Uint()
		if err != nil {
			return err
		}
		switch tag {
		case 0:
			l.current = uint8(v)
		case 1:
			l.options = uint8(v) & levelOptionsMax
		case 2:
			l.onOffTransition = uint16(v)
		case 3:
			l.onLevel = nullU8{uint8(v), true}
		case 4:
			l.onTransition = nullU16{uint16(v), true}
		case 5:
			l.offTransit = nullU16{uint16(v), true}
		case 6:
			l.defaultMoveRate = nullU8{uint8(v), v > 0}
		case 7:
			l.startUp = nullU8{uint8(v), true}
		}
		return nil
	})
	if l.lighting && l.startUp.valid {
		if l.startUp.v == 0 {
			l.current = l.min
		} else {
			l.current = l.startUp.v
		}
	}
	l.current = l.clamp(l.current)
	return err
}

// Scenes hold CurrentLevel; a recall moves to it even while off, without
// changing OnOff.

func (l *LevelControl) sceneSave(dst []scenePair) []scenePair {
	level := l.current
	if l.fadingOff {
		level = l.beforeOff
	}
	return append(dst, scenePair{levelCurrent, sceneU8, int64(level)})
}

func (l *LevelControl) sceneKind(attr uint32) uint8 {
	if attr == levelCurrent {
		return sceneU8
	}
	return 0
}

func (l *LevelControl) sceneClamp(p *scenePair) { clampPair(p, int64(l.min), int64(l.max)) }

func (l *LevelControl) sceneApply(n *im.Node, ep uint16, now time.Time, pairs []scenePair, dur time.Duration) im.Status {
	v, ok := sceneValue(pairs, levelCurrent)
	if ok && v >= int64(l.min) && v <= int64(l.max) {
		l.moveTo(n, ep, now, uint8(v), dur, false)
	}
	return im.Success
}
