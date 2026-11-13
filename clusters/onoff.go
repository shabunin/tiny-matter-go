package clusters

import (
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// OnOff is the On/Off cluster without optional features.
type OnOff struct {
	im.ClusterBase
	On bool
	// OnChange, if set, is called when a command changes the state.
	OnChange func(on bool)
}

func (*OnOff) ID() uint32       { return IDOnOff }
func (*OnOff) Revision() uint16 { return 6 }

var (
	onOffAttrs = []uint32{0}
	onOffCmds  = []uint32{0, 1, 2}
)

func (*OnOff) Attributes() []uint32       { return onOffAttrs }
func (*OnOff) AcceptedCommands() []uint32 { return onOffCmds }

func (o *OnOff) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr != 0 {
		return im.UnsupportedAttribute
	}
	w.PutBool(tag, o.On)
	return im.Success
}

func (o *OnOff) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	on := o.On
	switch cmd {
	case 0:
		on = false
	case 1:
		on = true
	case 2:
		on = !on
	default:
		return im.UnsupportedCommand
	}
	o.Set(ctx.Node, ctx.Endpoint, on)
	return im.Success
}

// Set changes the state, reporting the change to the node.
func (o *OnOff) Set(n *im.Node, endpoint uint16, on bool) {
	if on == o.On {
		return
	}
	o.On = on
	n.Changed(endpoint, IDOnOff, 0)
	if o.OnChange != nil {
		o.OnChange(on)
	}
}
