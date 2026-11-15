package im

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/tlv"
)

var errMalformed = errors.New("im: malformed message")

// AttributePath is an attribute path from a request; any of Endpoint,
// Cluster and Attribute may be a wildcard.
type AttributePath struct {
	Endpoint  uint16
	Cluster   uint32
	Attribute uint32
	// Wildcard flags.
	AnyEndpoint, AnyCluster, AnyAttribute bool
	// ListIndex: for writes, ListAppend means "append one item" (null list
	// index); a numeric index is not supported by Matter 1.4.
	ListAppend bool
	hasListIdx bool
}

// IsWildcard reports whether p contains a wildcard.
func (p *AttributePath) IsWildcard() bool { return p.AnyEndpoint || p.AnyCluster || p.AnyAttribute }

// ConcretePath identifies one attribute.
type ConcretePath struct {
	Endpoint  uint16
	Cluster   uint32
	Attribute uint32
}

// CommandPath identifies one command.
type CommandPath struct {
	Endpoint uint16
	Cluster  uint32
	Command  uint32
}

// DecodeAttributePath decodes the AttributePathIB list the reader is
// positioned on.
func DecodeAttributePath(r *tlv.Reader) (AttributePath, error) {
	p := AttributePath{AnyEndpoint: true, AnyCluster: true, AnyAttribute: true}
	if r.Type() != tlv.TypeList {
		return p, errMalformed
	}
	if err := r.EnterContainer(); err != nil {
		return p, err
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return p, err
		}
		if r.Tag().Kind != tlv.TagContext {
			continue
		}
		switch r.Tag().Number {
		case 1: // node: only accepted for compatibility, not checked
			if _, err = r.Uint(); err != nil {
				return p, err
			}
		case 2:
			p.Endpoint, err = r.Uint16()
			p.AnyEndpoint = false
		case 3:
			p.Cluster, err = r.Uint32()
			p.AnyCluster = false
		case 4:
			p.Attribute, err = r.Uint32()
			p.AnyAttribute = false
		case 5:
			p.hasListIdx = true
			if r.IsNull() {
				p.ListAppend = true
			} else {
				_, err = r.Uint16()
			}
		}
		if err != nil {
			return p, err
		}
	}
	if err := r.ExitContainer(); err != nil {
		return p, err
	}
	// A wildcard cluster with a concrete non-global attribute is invalid
	// (spec 8.9.2.2).
	if p.AnyCluster && !p.AnyAttribute && !isGlobalAttribute(p.Attribute) {
		return p, InvalidAction
	}
	return p, nil
}

// encodeAttributePath writes a concrete AttributePathIB list.
func encodeAttributePath(w *tlv.Writer, tag tlv.Tag, p ConcretePath, appendItem bool) {
	w.StartList(tag)
	w.PutUint(tlv.ContextTag(2), uint64(p.Endpoint))
	w.PutUint(tlv.ContextTag(3), uint64(p.Cluster))
	w.PutUint(tlv.ContextTag(4), uint64(p.Attribute))
	if appendItem {
		w.PutNull(tlv.ContextTag(5))
	}
	w.EndContainer()
}

// EncodeAttributePath writes a request AttributePathIB, omitting wildcard
// fields.
func EncodeAttributePath(w *tlv.Writer, tag tlv.Tag, p AttributePath) {
	w.StartList(tag)
	if !p.AnyEndpoint {
		w.PutUint(tlv.ContextTag(2), uint64(p.Endpoint))
	}
	if !p.AnyCluster {
		w.PutUint(tlv.ContextTag(3), uint64(p.Cluster))
	}
	if !p.AnyAttribute {
		w.PutUint(tlv.ContextTag(4), uint64(p.Attribute))
	}
	if p.ListAppend {
		w.PutNull(tlv.ContextTag(5))
	}
	w.EndContainer()
}

// DecodeCommandPath decodes the CommandPathIB list the reader is positioned
// on. All fields must be present (wildcard invokes are group-only).
func DecodeCommandPath(r *tlv.Reader) (CommandPath, error) {
	p, seen, err := decodeCommandPath(r)
	if err == nil && seen != 0b111 {
		err = InvalidAction
	}
	return p, err
}

// decodeGroupCommandPath decodes the path of a command sent to a group,
// which names the cluster and command, and should not name an endpoint.
func decodeGroupCommandPath(r *tlv.Reader) (cluster, command uint32, hasEndpoint bool, err error) {
	p, seen, err := decodeCommandPath(r)
	if err == nil && seen&0b110 != 0b110 {
		err = InvalidAction
	}
	return p.Cluster, p.Command, seen&1 != 0, err
}

// decodeCommandPath decodes a CommandPathIB, returning which of its
// endpoint, cluster and command fields (bits 0-2) were present.
func decodeCommandPath(r *tlv.Reader) (CommandPath, uint8, error) {
	var p CommandPath
	if r.Type() != tlv.TypeList {
		return p, 0, errMalformed
	}
	if err := r.EnterContainer(); err != nil {
		return p, 0, err
	}
	var seen uint8
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return p, seen, err
		}
		if r.Tag().Kind != tlv.TagContext {
			continue
		}
		switch r.Tag().Number {
		case 0:
			p.Endpoint, err = r.Uint16()
		case 1:
			p.Cluster, err = r.Uint32()
		case 2:
			p.Command, err = r.Uint32()
		default:
			continue
		}
		if err != nil {
			return p, seen, err
		}
		seen |= 1 << r.Tag().Number
	}
	return p, seen, r.ExitContainer()
}

// EncodeCommandPath writes a CommandPathIB list.
func EncodeCommandPath(w *tlv.Writer, tag tlv.Tag, p CommandPath) {
	w.StartList(tag)
	w.PutUint(tlv.ContextTag(0), uint64(p.Endpoint))
	w.PutUint(tlv.ContextTag(1), uint64(p.Cluster))
	w.PutUint(tlv.ContextTag(2), uint64(p.Command))
	w.EndContainer()
}

// encodeStatusIB writes a StatusIB structure.
func encodeStatusIB(w *tlv.Writer, tag tlv.Tag, s Status, clusterStatus *uint8) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(0), uint64(s))
	if clusterStatus != nil {
		w.PutUint(tlv.ContextTag(1), uint64(*clusterStatus))
	}
	w.EndContainer()
}

// DecodeStatusIB decodes the StatusIB structure the reader is positioned on.
func DecodeStatusIB(r *tlv.Reader) (s Status, clusterStatus uint8, hasCluster bool, err error) {
	if r.Type() != tlv.TypeStruct {
		return 0, 0, false, errMalformed
	}
	if err = r.EnterContainer(); err != nil {
		return
	}
	for {
		if err = r.Next(); err == tlv.ErrEndOfContainer {
			break
		} else if err != nil {
			return
		}
		switch {
		case r.Tag().IsContext(0):
			var v uint8
			v, err = r.Uint8()
			s = Status(v)
		case r.Tag().IsContext(1):
			clusterStatus, err = r.Uint8()
			hasCluster = true
		}
		if err != nil {
			return
		}
	}
	err = r.ExitContainer()
	return
}

// ForEachField iterates over the context-tagged fields of the structure r
// is positioned on, calling f for each. Cluster command handlers use it to
// decode command fields.
func ForEachField(r *tlv.Reader, f func(r *tlv.Reader, tag uint8) error) error {
	return structFields(r, f)
}

// structFields iterates over the context-tagged fields of the structure the
// reader is positioned on (or, if it is not yet positioned, of the top-level
// anonymous structure), calling f for each.
func structFields(r *tlv.Reader, f func(r *tlv.Reader, tag uint8) error) error {
	if r.Depth() == 0 && r.Type() == 0 {
		if err := r.Next(); err != nil {
			return err
		}
	}
	if r.Type() != tlv.TypeStruct {
		return errMalformed
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return err
		}
		if r.Tag().Kind != tlv.TagContext || r.Tag().Number > 0xFF {
			continue
		}
		if err := f(r, uint8(r.Tag().Number)); err != nil {
			return err
		}
	}
	return r.ExitContainer()
}

// arrayItems iterates over the items of the array or list the reader is
// positioned on.
func arrayItems(r *tlv.Reader, f func() error) error {
	if r.Type() != tlv.TypeArray && r.Type() != tlv.TypeList {
		return errMalformed
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return err
		}
		if err := f(); err != nil {
			return err
		}
	}
	return r.ExitContainer()
}
