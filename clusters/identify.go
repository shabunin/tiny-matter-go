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

	until time.Time // zero: not identifying
}

func (*Identify) ID() uint32       { return IDIdentify }
func (*Identify) Revision() uint16 { return 5 }

var (
	identifyAttrs = []uint32{0, 1}
	identifyCmds  = []uint32{0}
)

func (*Identify) Attributes() []uint32       { return identifyAttrs }
func (*Identify) AcceptedCommands() []uint32 { return identifyCmds }

func (*Identify) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*Identify) WritePrivilege(uint32) im.Privilege  { return im.Operate }
func (*Identify) InvokePrivilege(uint32) im.Privilege { return im.Manage }

// Identifying reports whether the endpoint is identifying itself.
func (i *Identify) Identifying() bool { return !i.until.IsZero() }

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

// Set identifies the endpoint for secs seconds (zero stops). IdentifyTime
// is reported when it is set and when it runs out, not every second.
func (i *Identify) Set(n *im.Node, endpoint uint16, now time.Time, secs uint16) {
	was := i.Identifying()
	if secs == 0 {
		i.until = time.Time{}
	} else {
		i.until = now.Add(time.Duration(secs) * time.Second)
	}
	n.Changed(endpoint, IDIdentify, 0)
	if was != i.Identifying() && i.OnIdentify != nil {
		i.OnIdentify(!was)
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
