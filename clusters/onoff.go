package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// OnOff is the On/Off cluster. With Lighting it has the Lighting feature
// (global scene, timed on and off, start-up state), which lights need;
// with Level it fades the endpoint's Level Control on and off.
type OnOff struct {
	im.ClusterBase
	On bool
	// OnChange, if set, is called when the state changes.
	OnChange func(on bool)
	// Lighting enables the Lighting feature.
	Lighting bool
	// Level, if set, is the endpoint's Level Control: turning on and off
	// moves its level (spec 1.6.4.1.1).
	Level *LevelControl
	// Scenes, if set, keeps the global scene for OffWithEffect and
	// OnWithRecallGlobalScene.
	Scenes GlobalScene

	// Lighting attributes.
	noGlobalScene bool // GlobalSceneControl is FALSE
	onTime        uint16
	offWaitTime   uint16
	startUp       nullU8 // StartUpOnOff
	tick          time.Time

	// A recalled scene's state, applied when its transition ends.
	sceneOn bool
	sceneAt time.Time // zero: none pending
}

// GlobalScene stores and recalls an endpoint's global scene (Scenes
// Management, group 0 scene 0).
type GlobalScene interface {
	StoreGlobalScene(ctx *im.Context)
	RecallGlobalScene(ctx *im.Context)
}

const (
	onOffAttr              = 0x0000
	onOffGlobalSceneCtrl   = 0x4000
	onOffOnTime            = 0x4001
	onOffOffWaitTime       = 0x4002
	onOffStartUpOnOff      = 0x4003
	onOffCmdOff            = 0x00
	onOffCmdOn             = 0x01
	onOffCmdToggle         = 0x02
	onOffCmdOffWithEffect  = 0x40
	onOffCmdOnWithRecall   = 0x41
	onOffCmdOnWithTimedOff = 0x42
	onOffFeatureLighting   = 0x1
	onOffTick              = 100 * time.Millisecond
	startUpOff, startUpOn  = 0, 1
	startUpToggle          = 2
)

var (
	onOffAttrs         = []uint32{onOffAttr}
	onOffCmds          = []uint32{onOffCmdOff, onOffCmdOn, onOffCmdToggle}
	onOffLightingAttrs = []uint32{onOffAttr, onOffGlobalSceneCtrl, onOffOnTime, onOffOffWaitTime, onOffStartUpOnOff}
	onOffLightingCmds  = []uint32{onOffCmdOff, onOffCmdOn, onOffCmdToggle,
		onOffCmdOffWithEffect, onOffCmdOnWithRecall, onOffCmdOnWithTimedOff}
)

func (*OnOff) ID() uint32       { return IDOnOff }
func (*OnOff) Revision() uint16 { return 6 }

func (o *OnOff) FeatureMap() uint32 {
	if o.Lighting {
		return onOffFeatureLighting
	}
	return 0
}

func (o *OnOff) Attributes() []uint32 {
	if o.Lighting {
		return onOffLightingAttrs
	}
	return onOffAttrs
}

func (o *OnOff) AcceptedCommands() []uint32 {
	if o.Lighting {
		return onOffLightingCmds
	}
	return onOffCmds
}

func (*OnOff) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*OnOff) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (*OnOff) WritePrivilege(attr uint32) im.Privilege {
	if attr == onOffStartUpOnOff {
		return im.Manage
	}
	return im.Operate
}

func (o *OnOff) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch {
	case attr == onOffAttr:
		w.PutBool(tag, o.On)
	case !o.Lighting:
		return im.UnsupportedAttribute
	case attr == onOffGlobalSceneCtrl:
		w.PutBool(tag, !o.noGlobalScene)
	case attr == onOffOnTime:
		w.PutUint(tag, uint64(o.onTime))
	case attr == onOffOffWaitTime:
		w.PutUint(tag, uint64(o.offWaitTime))
	case attr == onOffStartUpOnOff:
		o.startUp.put(w, tag)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (o *OnOff) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if !o.Lighting {
		return im.UnsupportedWrite
	}
	var st im.Status
	switch attr {
	case onOffOnTime, onOffOffWaitTime:
		var v uint16
		if v, st = readU16(r, 0xFFFF); st != im.Success {
			return st
		}
		if attr == onOffOnTime {
			o.onTime = v
		} else {
			o.offWaitTime = v
		}
	case onOffStartUpOnOff:
		var v nullU8
		if v, st = readNullU8(r, startUpToggle); st != im.Success {
			return st
		}
		o.startUp = v
	default:
		return im.UnsupportedWrite
	}
	ctx.Node.Changed(ctx.Endpoint, IDOnOff, attr)
	return im.Success
}

func (o *OnOff) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	n, ep, now := ctx.Node, ctx.Endpoint, ctx.Now
	switch cmd {
	case onOffCmdOff:
		o.command(n, ep, now, false)
	case onOffCmdOn:
		o.command(n, ep, now, true)
	case onOffCmdToggle:
		o.command(n, ep, now, !o.On)
	default:
		if !o.Lighting {
			return im.UnsupportedCommand
		}
		return o.invokeLighting(ctx, cmd, r)
	}
	return im.Success
}

func (o *OnOff) invokeLighting(ctx *im.Context, cmd uint32, r *tlv.Reader) im.Status {
	n, ep, now := ctx.Node, ctx.Endpoint, ctx.Now
	f, ok := decodeNumFields(r)
	if !ok {
		return im.InvalidCommand
	}
	switch cmd {
	case onOffCmdOffWithEffect:
		if !f.present(0, 1) {
			return im.InvalidCommand
		}
		if _, ok := f.u(0, 1); !ok { // DelayedAllOff or DyingLight
			return im.ConstraintError
		}
		// The effect itself is the application's (the variant is not
		// checked: an unknown one means the default).
		if !o.noGlobalScene {
			if o.Scenes != nil {
				o.Scenes.StoreGlobalScene(ctx)
			}
			o.setGlobalScene(n, ep, false)
		}
		o.command(n, ep, now, false)
	case onOffCmdOnWithRecall:
		if !o.noGlobalScene {
			return im.Success
		}
		if o.Scenes != nil {
			o.Scenes.RecallGlobalScene(ctx)
		}
		o.setGlobalScene(n, ep, true)
		o.command(n, ep, now, true)
	case onOffCmdOnWithTimedOff:
		if !f.present(0, 1, 2) {
			return im.InvalidCommand
		}
		ctl, ok1 := f.u(0, 0xFF)
		onTime, ok2 := f.u(1, 0xFFFE)
		offWait, ok3 := f.u(2, 0xFFFE)
		if !ok1 || !ok2 || !ok3 {
			return im.ConstraintError
		}
		if ctl&1 != 0 && !o.On { // AcceptOnlyWhenOn
			return im.Success
		}
		if !o.On && o.offWaitTime > 0 {
			o.setTimes(n, ep, o.onTime, min(o.offWaitTime, uint16(offWait)))
			return im.Success
		}
		o.setTimes(n, ep, max(o.onTime, uint16(onTime)), uint16(offWait))
		o.command(n, ep, now, true)
		o.tick = time.Time{} // restart the 1/10 s count
	default:
		return im.UnsupportedCommand
	}
	return im.Success
}

// command applies an On or Off command, with the Lighting feature's
// effects on the timed on/off attributes and the global scene.
func (o *OnOff) command(n *im.Node, ep uint16, now time.Time, on bool) {
	o.sceneAt = time.Time{} // a command overrides a recalled scene
	if on == o.On {
		return
	}
	if on && o.Lighting {
		o.setGlobalScene(n, ep, true)
	}
	o.set(n, ep, now, on, false)
}

// Set turns the endpoint on or off, as a command would but without
// Lighting side effects: for applications (a button).
func (o *OnOff) Set(n *im.Node, endpoint uint16, on bool) {
	o.set(n, endpoint, time.Time{}, on, false)
}

// set changes the state. A change not made by Level Control moves its
// level; with Lighting, turning off ends OnTime and turning on (without
// OnTime) ends OffWaitTime.
func (o *OnOff) set(n *im.Node, ep uint16, now time.Time, on, byLevel bool) {
	if on == o.On {
		return
	}
	o.On = on
	n.Changed(ep, IDOnOff, onOffAttr)
	if o.Lighting {
		if on && o.onTime == 0 {
			o.setTimes(n, ep, 0, 0)
		} else if !on {
			o.setTimes(n, ep, 0, o.offWaitTime)
		}
	}
	if o.OnChange != nil {
		o.OnChange(on)
	}
	if !byLevel && o.Level != nil {
		o.Level.onOffChanged(n, ep, now, on)
	}
}

func (o *OnOff) setGlobalScene(n *im.Node, ep uint16, v bool) {
	if o.noGlobalScene == !v {
		return
	}
	o.noGlobalScene = !v
	n.Changed(ep, IDOnOff, onOffGlobalSceneCtrl)
}

// setTimes sets OnTime and OffWaitTime, reporting them as changed.
func (o *OnOff) setTimes(n *im.Node, ep uint16, onTime, offWait uint16) {
	if onTime != o.onTime {
		o.onTime = onTime
		n.Changed(ep, IDOnOff, onOffOnTime)
	}
	if offWait != o.offWaitTime {
		o.offWaitTime = offWait
		n.Changed(ep, IDOnOff, onOffOffWaitTime)
	}
}

// Poll counts OnTime down while on and OffWaitTime while off, in tenths
// of a second, turning off when OnTime runs out (im.Poller). The
// countdown is reported when it ends, not every tick.
func (o *OnOff) Poll(n *im.Node, ep uint16, now time.Time) time.Time {
	if !o.sceneAt.IsZero() && !now.Before(o.sceneAt) {
		o.sceneAt = time.Time{}
		o.set(n, ep, now, o.sceneOn, false)
	}
	return earliest(o.sceneAt, o.pollTimers(n, ep, now))
}

func (o *OnOff) pollTimers(n *im.Node, ep uint16, now time.Time) time.Time {
	counting := func() bool {
		if o.On {
			return o.onTime > 0 && o.onTime < 0xFFFF
		}
		return o.offWaitTime > 0 && o.offWaitTime < 0xFFFF
	}
	if !o.Lighting || !counting() {
		o.tick = time.Time{}
		return time.Time{}
	}
	if o.tick.IsZero() {
		o.tick = now.Add(onOffTick)
	}
	for counting() && !now.Before(o.tick) {
		o.tick = o.tick.Add(onOffTick)
		if o.On {
			o.onTime--
			if o.onTime == 0 {
				n.Changed(ep, IDOnOff, onOffOnTime)
				o.setTimes(n, ep, 0, 0)
				o.set(n, ep, now, false, false)
			}
		} else {
			o.offWaitTime--
			if o.offWaitTime == 0 {
				n.Changed(ep, IDOnOff, onOffOffWaitTime)
			}
		}
	}
	if !counting() {
		o.tick = time.Time{}
	}
	return o.tick
}

// EncodeState saves OnOff and StartUpOnOff (im.Persister).
func (o *OnOff) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.StartStruct(tag)
	w.PutBool(tlv.ContextTag(0), o.On)
	if o.startUp.valid {
		w.PutUint(tlv.ContextTag(1), uint64(o.startUp.v))
	}
	w.EndContainer()
}

// DecodeState restores the state and applies StartUpOnOff (im.Persister).
func (o *OnOff) DecodeState(r *tlv.Reader) error {
	return im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			o.On, err = r.Bool()
		case 1:
			var v uint8
			v, err = r.Uint8()
			o.startUp = nullU8{v, v <= startUpToggle}
		}
		if err == nil && tag == 1 && o.Lighting && o.startUp.valid {
			switch o.startUp.v {
			case startUpOff:
				o.On = false
			case startUpOn:
				o.On = true
			case startUpToggle:
				o.On = !o.On
			}
		}
		return err
	})
}

// Scenes hold the OnOff attribute. A recall that turns the light on does
// so at once (so Level Control and Color Control fade in visibly); one
// that turns it off does so when the transition ends.

func (o *OnOff) sceneSave(dst []scenePair) []scenePair {
	v := int64(0)
	if o.On {
		v = 1
	}
	return append(dst, scenePair{onOffAttr, sceneU8, v})
}

func (o *OnOff) sceneKind(attr uint32) uint8 {
	if attr == onOffAttr {
		return sceneU8
	}
	return 0
}

func (o *OnOff) sceneClamp(p *scenePair) { clampPair(p, 0, 1) }

func (o *OnOff) sceneApply(n *im.Node, ep uint16, now time.Time, pairs []scenePair, dur time.Duration) im.Status {
	v, ok := sceneValue(pairs, onOffAttr)
	if !ok {
		return im.Success
	}
	if dur <= 0 || v != 0 {
		o.sceneAt = time.Time{}
		o.set(n, ep, now, v != 0, false)
		return im.Success
	}
	o.sceneOn, o.sceneAt = false, now.Add(dur)
	return im.Success
}
