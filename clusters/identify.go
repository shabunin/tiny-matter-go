package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Identify types (IdentifyTypeEnum).
const (
	IdentifyNone             = 0
	IdentifyLightOutput      = 1
	IdentifyVisibleIndicator = 2
	IdentifyAudibleBeep      = 3
	IdentifyDisplay          = 4
	IdentifyActuator         = 5
)

// Identify is the Identify cluster: a controller asks the endpoint to make
// itself noticeable (blink a light, beep) for a number of seconds.
type Identify struct {
	im.ClusterBase
	Type uint8
	// OnIdentify, if set, is called when identification starts and stops.
	OnIdentify func(on bool)
	// Effects enables the TriggerEffect command (required on lights). An
	// effect identifies for its length; Effect says which one runs.
	Effects bool

	until  time.Time // zero: not identifying
	effect uint8
}

// Identify effects (EffectIdentifierEnum).
const (
	EffectBlink         = 0x00
	EffectBreathe       = 0x01
	EffectOkay          = 0x02
	EffectChannelChange = 0x0B
	EffectFinish        = 0xFE
	EffectStop          = 0xFF
	// EffectIdentify is what Effect returns for the Identify command.
	EffectIdentify = 0x80
)

func (*Identify) ID() uint32       { return IDIdentify }
func (*Identify) Revision() uint16 { return 5 }

var (
	identifyAttrs = []uint32{0, 1}
	identifyCmds  = []uint32{0}
	effectCmds    = []uint32{0, 0x40}
)

func (*Identify) Attributes() []uint32 { return identifyAttrs }

func (i *Identify) AcceptedCommands() []uint32 {
	if i.Effects {
		return effectCmds
	}
	return identifyCmds
}

func (*Identify) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*Identify) WritePrivilege(uint32) im.Privilege  { return im.Operate }
func (*Identify) InvokePrivilege(uint32) im.Privilege { return im.Manage }

// Identifying reports whether the endpoint is identifying itself.
func (i *Identify) Identifying() bool { return !i.until.IsZero() }

// Effect returns the running effect (Effect* constants), EffectIdentify
// for the Identify command or attribute.
func (i *Identify) Effect() uint8 { return i.effect }

// remaining returns IdentifyTime: the whole seconds left, rounded up.
func (i *Identify) remaining(now time.Time) uint64 {
	if i.until.IsZero() || !now.Before(i.until) {
		return 0
	}
	return uint64((i.until.Sub(now) + time.Second - 1) / time.Second)
}

func (i *Identify) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0: // IdentifyTime
		w.PutUint(tag, i.remaining(ctx.Now))
	case 1: // IdentifyType
		w.PutUint(tag, uint64(i.Type))
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (i *Identify) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != 0 {
		return im.UnsupportedWrite
	}
	if appendItem {
		return im.InvalidAction
	}
	v, err := r.Uint16()
	if err != nil {
		return im.InvalidDataType
	}
	i.Set(ctx.Node, ctx.Endpoint, ctx.Now, v)
	return im.Success
}

func (i *Identify) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	if cmd == 0x40 && i.Effects {
		return i.triggerEffect(ctx, r)
	}
	if cmd != 0 {
		return im.UnsupportedCommand
	}
	var secs uint16
	seen := false
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		if tag == 0 {
			secs, err = r.Uint16()
			seen = true
		}
		return err
	})
	if err != nil || !seen {
		return im.InvalidCommand
	}
	i.Set(ctx.Node, ctx.Endpoint, ctx.Now, secs)
	return im.Success
}

// triggerEffect runs TriggerEffect: an effect identifies for its length,
// Finish ends the running one within a second, Stop at once.
func (i *Identify) triggerEffect(ctx *im.Context, r *tlv.Reader) im.Status {
	f, ok := decodeNumFields(r)
	if !ok || !f.present(0, 1) {
		return im.InvalidCommand
	}
	// A variant the device does not know runs the default one (spec 1.2.7.2.2),
	// so only the identifier is checked.
	effect, okE := f.u(0, 0xFF)
	_, okV := f.u(1, 0xFF)
	if !okE || !okV {
		return im.ConstraintError
	}
	var d time.Duration
	switch effect {
	case EffectBlink:
		d = time.Second
	case EffectBreathe:
		d = 15 * time.Second
	case EffectOkay:
		d = 2 * time.Second
	case EffectChannelChange:
		d = 8 * time.Second
	case EffectFinish:
		if i.Identifying() && i.until.Sub(ctx.Now) > time.Second {
			i.until = ctx.Now.Add(time.Second)
			ctx.Node.Changed(ctx.Endpoint, IDIdentify, 0)
		}
		return im.Success
	case EffectStop:
		i.stop(ctx.Node, ctx.Endpoint)
		return im.Success
	default:
		return im.ConstraintError
	}
	i.start(ctx.Node, ctx.Endpoint, ctx.Now.Add(d), uint8(effect))
	return im.Success
}

// Set identifies the endpoint for secs seconds (zero stops). IdentifyTime
// is reported when it is set and when it runs out, not every second.
func (i *Identify) Set(n *im.Node, endpoint uint16, now time.Time, secs uint16) {
	if secs == 0 {
		i.stop(n, endpoint)
		return
	}
	i.start(n, endpoint, now.Add(time.Duration(secs)*time.Second), EffectIdentify)
}

func (i *Identify) start(n *im.Node, endpoint uint16, until time.Time, effect uint8) {
	was, wasEffect := i.Identifying(), i.effect
	i.until, i.effect = until, effect
	n.Changed(endpoint, IDIdentify, 0)
	if i.OnIdentify != nil && (!was || wasEffect != effect) {
		i.OnIdentify(true)
	}
}

func (i *Identify) stop(n *im.Node, endpoint uint16) {
	was := i.Identifying()
	i.until, i.effect = time.Time{}, 0
	n.Changed(endpoint, IDIdentify, 0)
	if was && i.OnIdentify != nil {
		i.OnIdentify(false)
	}
}

// Poll stops identifying when the time runs out (im.Poller).
func (i *Identify) Poll(n *im.Node, endpoint uint16, now time.Time) time.Time {
	if i.until.IsZero() {
		return time.Time{}
	}
	if now.Before(i.until) {
		return i.until
	}
	i.Set(n, endpoint, now, 0)
	return time.Time{}
}
