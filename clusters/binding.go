package clusters

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// IDBinding is the Binding cluster (spec 9.6).
const IDBinding = 0x001E

// MaxBindings is how many targets one Binding cluster holds, across
// fabrics.
const MaxBindings = 10

const fieldFabricIndex = 0xFE

// BindingTarget is an entry of the Binding list (TargetStruct): either a
// node's endpoint or a group, optionally for one cluster only.
type BindingTarget struct {
	FabricIndex uint8
	Node        uint64
	Group       uint16 // 0: a node target
	Endpoint    uint16
	Cluster     uint32
	HasCluster  bool // the target is for Cluster only
}

// IsGroup reports whether the target is a group.
func (t BindingTarget) IsGroup() bool { return t.Group != 0 }

// For reports whether the target takes commands of cluster.
func (t BindingTarget) For(cluster uint32) bool { return !t.HasCluster || t.Cluster == cluster }

// Binding is the Binding cluster: where an endpoint's client clusters send
// their commands. Controllers write the list; the application reads
// Targets (device.SendBound does).
type Binding struct {
	im.ClusterBase
	Targets []BindingTarget
}

var bindingAttrs = []uint32{0}

func (*Binding) ID() uint32           { return IDBinding }
func (*Binding) Revision() uint16     { return 1 }
func (*Binding) Attributes() []uint32 { return bindingAttrs }

func (*Binding) ReadPrivilege(uint32) im.Privilege  { return im.View }
func (*Binding) WritePrivilege(uint32) im.Privilege { return im.Manage }

func (b *Binding) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr != 0 {
		return im.UnsupportedAttribute
	}
	w.StartArray(tag)
	for _, t := range b.Targets {
		if ctx.FabricFiltered && t.FabricIndex != accessingFabric(ctx) {
			continue
		}
		encodeBindingTarget(w, tlv.Anonymous, &t)
	}
	w.EndContainer()
	return im.Success
}

func encodeBindingTarget(w *tlv.Writer, tag tlv.Tag, t *BindingTarget) {
	w.StartStruct(tag)
	if t.IsGroup() {
		w.PutUint(tlv.ContextTag(2), uint64(t.Group))
	} else {
		w.PutUint(tlv.ContextTag(1), t.Node)
		w.PutUint(tlv.ContextTag(3), uint64(t.Endpoint))
	}
	if t.HasCluster {
		w.PutUint(tlv.ContextTag(4), uint64(t.Cluster))
	}
	w.PutUint(tlv.ContextTag(fieldFabricIndex), uint64(t.FabricIndex))
	w.EndContainer()
}

var errBindingFields = errors.New("binding: malformed target")

// decodeBindingTarget reads a TargetStruct. It returns ConstraintError for
// a target that is neither a node's endpoint nor a group alone.
func decodeBindingTarget(r *tlv.Reader) (t BindingTarget, st im.Status) {
	var have uint8
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			t.Node, err = r.Uint()
			have |= 1
		case 2:
			t.Group, err = r.Uint16()
			have |= 2
		case 3:
			t.Endpoint, err = r.Uint16()
			have |= 4
		case 4:
			t.Cluster, err = r.Uint32()
			t.HasCluster = true
		case fieldFabricIndex:
			t.FabricIndex, err = r.Uint8()
		}
		return err
	})
	if err != nil {
		return t, im.InvalidDataType
	}
	switch {
	case have == 2 && t.Group != 0: // a group
	case have == 1|4: // a node's endpoint
	default:
		return t, im.ConstraintError
	}
	return t, im.Success
}

// WriteAttribute replaces the accessing fabric's targets, or appends one.
func (b *Binding) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != 0 {
		return im.UnsupportedWrite
	}
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return im.UnsupportedAccess
	}
	var fresh []BindingTarget
	if appendItem {
		t, st := decodeBindingTarget(r)
		if st != im.Success {
			return st
		}
		t.FabricIndex = fabric
		fresh = append(append([]BindingTarget(nil), b.Targets...), t)
	} else {
		if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
			return im.InvalidDataType
		}
		fresh = filter(b.Targets, func(t *BindingTarget) bool { return t.FabricIndex != fabric })
		for r.Next() == nil {
			t, st := decodeBindingTarget(r)
			if st != im.Success {
				return st
			}
			t.FabricIndex = fabric
			fresh = append(fresh, t)
		}
		if r.ExitContainer() != nil {
			return im.InvalidDataType
		}
	}
	if len(fresh) > MaxBindings {
		return im.ResourceExhausted
	}
	b.Targets = fresh
	ctx.Node.Changed(ctx.Endpoint, IDBinding, 0)
	return im.Success
}

// RemoveFabric drops a removed fabric's targets.
func (b *Binding) RemoveFabric(n *im.Node, endpoint uint16, index uint8) {
	before := len(b.Targets)
	b.Targets = filter(b.Targets, func(t *BindingTarget) bool { return t.FabricIndex != index })
	if len(b.Targets) != before {
		n.Changed(endpoint, IDBinding, 0)
	}
}

// EncodeState saves the targets (im.Persister).
func (b *Binding) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.StartArray(tag)
	for _, t := range b.Targets {
		encodeBindingTarget(w, tlv.Anonymous, &t)
	}
	w.EndContainer()
}

// DecodeState restores the targets (im.Persister).
func (b *Binding) DecodeState(r *tlv.Reader) error {
	var ts []BindingTarget
	err := eachItem(r, func() error {
		t, st := decodeBindingTarget(r)
		if st != im.Success {
			return errBindingFields
		}
		ts = append(ts, t)
		return nil
	})
	if err != nil {
		return err
	}
	b.Targets = ts
	return nil
}
