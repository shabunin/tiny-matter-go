package clusters

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Label clusters (spec 9.7-9.9).
const (
	IDFixedLabel = 0x0040
	IDUserLabel  = 0x0041
)

const (
	labelMaxLen = 16 // LabelStruct's Label and Value
	// MaxUserLabels is how many labels a User Label cluster holds (the
	// spec asks for at least 4; the SDK keeps 10).
	MaxUserLabels = 10
)

// Label is a LabelStruct: a label and its value, such as "room",
// "kitchen".
type Label struct {
	Label, Value string
}

var labelAttrs = []uint32{0}

func encodeLabels(w *tlv.Writer, tag tlv.Tag, ls []Label) {
	w.StartArray(tag)
	for _, l := range ls {
		w.StartStruct(tlv.Anonymous)
		w.PutString(tlv.ContextTag(0), l.Label)
		w.PutString(tlv.ContextTag(1), l.Value)
		w.EndContainer()
	}
	w.EndContainer()
}

// decodeLabel reads a LabelStruct, with ConstraintError for a label or
// value too long.
func decodeLabel(r *tlv.Reader) (l Label, st im.Status) {
	var have uint8
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			l.Label, err = r.String()
			have |= 1
		case 1:
			l.Value, err = r.String()
			have |= 2
		}
		return err
	})
	if err != nil || have != 3 {
		return l, im.InvalidDataType
	}
	if len(l.Label) > labelMaxLen || len(l.Value) > labelMaxLen {
		return l, im.ConstraintError
	}
	return l, im.Success
}

// FixedLabel is the Fixed Label cluster: labels the manufacturer gives an
// endpoint.
type FixedLabel struct {
	im.ClusterBase
	Labels []Label
}

func (*FixedLabel) ID() uint32           { return IDFixedLabel }
func (*FixedLabel) Revision() uint16     { return 1 }
func (*FixedLabel) Attributes() []uint32 { return labelAttrs }

func (f *FixedLabel) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr != 0 {
		return im.UnsupportedAttribute
	}
	encodeLabels(w, tag, f.Labels)
	return im.Success
}

// UserLabel is the User Label cluster: labels users give an endpoint
// (written with Manage), kept across restarts (im.Persister).
type UserLabel struct {
	im.ClusterBase
	Labels []Label
}

func (*UserLabel) ID() uint32           { return IDUserLabel }
func (*UserLabel) Revision() uint16     { return 1 }
func (*UserLabel) Attributes() []uint32 { return labelAttrs }

func (*UserLabel) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*UserLabel) WritePrivilege(uint32) im.Privilege  { return im.Manage }
func (*UserLabel) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (u *UserLabel) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr != 0 {
		return im.UnsupportedAttribute
	}
	encodeLabels(w, tag, u.Labels)
	return im.Success
}

func (u *UserLabel) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != 0 {
		return im.UnsupportedWrite
	}
	var fresh []Label
	if appendItem {
		l, st := decodeLabel(r)
		if st != im.Success {
			return st
		}
		fresh = append(append([]Label(nil), u.Labels...), l)
	} else {
		if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
			return im.InvalidDataType
		}
		for r.Next() == nil {
			l, st := decodeLabel(r)
			if st != im.Success {
				return st
			}
			if len(fresh) == MaxUserLabels {
				return im.ResourceExhausted
			}
			fresh = append(fresh, l)
		}
		if r.ExitContainer() != nil {
			return im.InvalidDataType
		}
	}
	if len(fresh) > MaxUserLabels {
		return im.ResourceExhausted
	}
	u.Labels = fresh
	ctx.Node.Changed(ctx.Endpoint, IDUserLabel, 0)
	return im.Success
}

var errLabelState = errors.New("user label: malformed stored state")

// EncodeState saves the labels (im.Persister).
func (u *UserLabel) EncodeState(w *tlv.Writer, tag tlv.Tag) { encodeLabels(w, tag, u.Labels) }

// DecodeState restores the labels (im.Persister).
func (u *UserLabel) DecodeState(r *tlv.Reader) error {
	var ls []Label
	err := eachItem(r, func() error {
		l, st := decodeLabel(r)
		if st != im.Success {
			return errLabelState
		}
		ls = append(ls, l)
		return nil
	})
	if err != nil {
		return err
	}
	u.Labels = ls
	return nil
}
