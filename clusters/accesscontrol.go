package clusters

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Access control limits advertised (spec minimums).
const (
	SubjectsPerEntry = 4
	TargetsPerEntry  = 3
	EntriesPerFabric = 4
)

// ACLTarget restricts an entry to a cluster, endpoint or device type; nil
// fields match anything.
type ACLTarget struct {
	Cluster    *uint32
	Endpoint   *uint16
	DeviceType *uint32
}

// ACLEntry is one access control entry.
type ACLEntry struct {
	FabricIndex uint8
	Privilege   im.Privilege
	AuthMode    exchange.AuthMode
	Subjects    []uint64    // nil: any subject
	Targets     []ACLTarget // nil: everything
}

// AccessControl is the Access Control cluster and the node's access
// checker (im.AccessChecker).
type AccessControl struct {
	im.ClusterBase
	Entries []ACLEntry
}

func (*AccessControl) ID() uint32       { return IDAccessControl }
func (*AccessControl) Revision() uint16 { return 2 }

var aclAttrs = []uint32{0, 2, 3, 4}

func (*AccessControl) Attributes() []uint32 { return aclAttrs }

func (*AccessControl) ReadPrivilege(attr uint32) im.Privilege {
	if attr == 0 {
		return im.Administer
	}
	return im.View
}
func (*AccessControl) WritePrivilege(uint32) im.Privilege  { return im.Administer }
func (*AccessControl) InvokePrivilege(uint32) im.Privilege { return im.Administer }

// EventACLEntryChanged is the AccessControlEntryChanged event.
const EventACLEntryChanged = 0x00

// ACL change types (ChangeTypeEnum).
const (
	ACLChanged = 0
	ACLAdded   = 1
	ACLRemoved = 2
)

var aclEvents = []uint32{EventACLEntryChanged}

func (*AccessControl) Events() []uint32                   { return aclEvents }
func (*AccessControl) EventPrivilege(uint32) im.Privilege { return im.Administer }

// entryChanged records AccessControlEntryChanged for an entry the subject
// of ctx changed: a fabric-sensitive event naming the administrator by
// node ID (CASE) or passcode ID (PASE).
func entryChanged(ctx *im.Context, change uint8, e *ACLEntry) {
	if ctx.Node == nil {
		return
	}
	ctx.Node.Emit(ctx.Now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: 0, Cluster: IDAccessControl, Event: EventACLEntryChanged},
		Priority: im.PriorityInfo,
		Fabric:   e.FabricIndex,
		Fields: func(w *tlv.Writer) {
			if s := ctx.Session; s != nil && s.AuthMode == exchange.AuthCASE {
				w.PutUint(tlv.ContextTag(1), s.PeerNodeID())
				w.PutNull(tlv.ContextTag(2))
			} else {
				w.PutNull(tlv.ContextTag(1))
				w.PutUint(tlv.ContextTag(2), 0) // the commissioning passcode
			}
			w.PutUint(tlv.ContextTag(3), uint64(change))
			encodeACLEntry(w, tlv.ContextTag(4), e, true)
		},
	})
}

// RemoveFabric drops the entries of a fabric.
func (a *AccessControl) RemoveFabric(index uint8) {
	out := a.Entries[:0]
	for _, e := range a.Entries {
		if e.FabricIndex != index {
			out = append(out, e)
		}
	}
	a.Entries = out
}

// Allowed implements im.AccessChecker (spec 6.6.6).
func (a *AccessControl) Allowed(ctx *im.Context, endpoint uint16, cluster uint32, p im.Privilege) bool {
	s := ctx.Session
	if s == nil {
		return false
	}
	switch s.AuthMode {
	case exchange.AuthPASE:
		// A PASE session commissioning the node holds an implicit
		// Administer grant.
		return true
	case exchange.AuthCASE, exchange.AuthGroup:
	default:
		return false
	}
	for i := range a.Entries {
		e := &a.Entries[i]
		if e.FabricIndex != s.FabricIndex || e.AuthMode != s.AuthMode || !e.Privilege.Grants(p) {
			continue
		}
		if !subjectMatches(e.Subjects, s) || !targetMatches(ctx, e.Targets, endpoint, cluster) {
			continue
		}
		return true
	}
	return false
}

func subjectMatches(subjects []uint64, s *exchange.Session) bool {
	if len(subjects) == 0 { // null or empty: any subject
		return true
	}
	peer := s.PeerNodeID()
	for _, subj := range subjects {
		if subj == peer {
			return true
		}
		// CASE Authenticated Tag subjects: 0xFFFFFFFD_IIIIVVVV.
		if subj>>32 == 0xFFFFFFFD {
			for _, cat := range s.PeerCATs {
				if cat>>16 == uint32(subj>>16)&0xFFFF && cat&0xFFFF >= uint32(subj)&0xFFFF {
					return true
				}
			}
		}
	}
	return false
}

func targetMatches(ctx *im.Context, targets []ACLTarget, endpoint uint16, cluster uint32) bool {
	if len(targets) == 0 { // null or empty: everything
		return true
	}
	for _, t := range targets {
		if t.Cluster != nil && *t.Cluster != cluster {
			continue
		}
		if t.Endpoint != nil && *t.Endpoint != endpoint {
			continue
		}
		if t.DeviceType != nil && !endpointHasDeviceType(ctx.Node, endpoint, *t.DeviceType) {
			continue
		}
		return true
	}
	return false
}

func endpointHasDeviceType(n *im.Node, endpoint uint16, dt uint32) bool {
	if e := n.Endpoint(endpoint); e != nil {
		for _, d := range e.DeviceTypes {
			if d.ID == dt {
				return true
			}
		}
	}
	return false
}

func (a *AccessControl) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0:
		w.StartArray(tag)
		for i := range a.Entries {
			e := &a.Entries[i]
			if ctx.FabricFiltered && e.FabricIndex != accessingFabric(ctx) {
				continue
			}
			encodeACLEntry(w, tlv.Anonymous, e, e.FabricIndex == accessingFabric(ctx))
		}
		w.EndContainer()
	case 2:
		w.PutUint(tag, SubjectsPerEntry)
	case 3:
		w.PutUint(tag, TargetsPerEntry)
	case 4:
		w.PutUint(tag, EntriesPerFabric)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func accessingFabric(ctx *im.Context) uint8 {
	if ctx.Session == nil {
		return 0
	}
	return ctx.Session.FabricIndex
}

// encodeACLEntry writes an AccessControlEntryStruct; fabric-sensitive
// fields are only written for the accessing fabric.
func encodeACLEntry(w *tlv.Writer, tag tlv.Tag, e *ACLEntry, sensitive bool) {
	w.StartStruct(tag)
	if sensitive {
		w.PutUint(tlv.ContextTag(1), uint64(e.Privilege))
		w.PutUint(tlv.ContextTag(2), uint64(e.AuthMode))
		if e.Subjects == nil {
			w.PutNull(tlv.ContextTag(3))
		} else {
			w.StartArray(tlv.ContextTag(3))
			for _, s := range e.Subjects {
				w.PutUint(tlv.Anonymous, s)
			}
			w.EndContainer()
		}
		if e.Targets == nil {
			w.PutNull(tlv.ContextTag(4))
		} else {
			w.StartArray(tlv.ContextTag(4))
			for _, t := range e.Targets {
				w.StartStruct(tlv.Anonymous)
				putNullable32(w, 0, t.Cluster)
				if t.Endpoint == nil {
					w.PutNull(tlv.ContextTag(1))
				} else {
					w.PutUint(tlv.ContextTag(1), uint64(*t.Endpoint))
				}
				putNullable32(w, 2, t.DeviceType)
				w.EndContainer()
			}
			w.EndContainer()
		}
	}
	w.PutUint(tlv.ContextTag(0xFE), uint64(e.FabricIndex))
	w.EndContainer()
}

func putNullable32(w *tlv.Writer, tag uint8, v *uint32) {
	if v == nil {
		w.PutNull(tlv.ContextTag(tag))
	} else {
		w.PutUint(tlv.ContextTag(tag), uint64(*v))
	}
}

func decodeACLEntry(r *tlv.Reader, fabric uint8) (ACLEntry, bool) {
	e := ACLEntry{FabricIndex: fabric}
	ok := true
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			var v uint8
			v, err = r.Uint8()
			e.Privilege = im.Privilege(v)
		case 2:
			var v uint8
			v, err = r.Uint8()
			e.AuthMode = exchange.AuthMode(v)
		case 3:
			if r.IsNull() {
				return nil
			}
			e.Subjects = []uint64{}
			if r.EnterContainer() != nil {
				return im.InvalidDataType
			}
			for r.Next() == nil {
				v, err := r.Uint()
				if err != nil {
					return err
				}
				e.Subjects = append(e.Subjects, v)
			}
			return r.ExitContainer()
		case 4:
			if r.IsNull() {
				return nil
			}
			e.Targets = []ACLTarget{}
			if r.EnterContainer() != nil {
				return im.InvalidDataType
			}
			for r.Next() == nil {
				var t ACLTarget
				err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
					if r.IsNull() {
						return nil
					}
					v, err := r.Uint32()
					switch tag {
					case 0:
						t.Cluster = &v
					case 1:
						ep := uint16(v)
						if v > 0xFFFF {
							return im.ConstraintError
						}
						t.Endpoint = &ep
					case 2:
						t.DeviceType = &v
					}
					return err
				})
				if err != nil {
					return err
				}
				e.Targets = append(e.Targets, t)
			}
			return r.ExitContainer()
		}
		return err
	})
	if err != nil || e.Privilege < im.View || e.Privilege > im.Administer ||
		e.AuthMode < exchange.AuthPASE || e.AuthMode > exchange.AuthGroup || e.AuthMode == exchange.AuthPASE ||
		len(e.Subjects) > SubjectsPerEntry || len(e.Targets) > TargetsPerEntry {
		ok = false
	}
	if e.AuthMode == exchange.AuthGroup && e.Privilege == im.Administer {
		ok = false
	}
	return e, ok
}

// WriteAttribute replaces (or appends to) the accessing fabric's entries.
// Like the SDK, a replacement reports each index as changed, added or
// removed.
func (a *AccessControl) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != 0 {
		return im.UnsupportedWrite
	}
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return im.UnsupportedAccess
	}
	if appendItem {
		e, ok := decodeACLEntry(r, fabric)
		if !ok {
			return im.ConstraintError
		}
		if a.count(fabric) >= EntriesPerFabric {
			return im.ResourceExhausted
		}
		a.Entries = append(a.Entries, e)
		entryChanged(ctx, ACLAdded, &e)
		return im.Success
	}
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return im.InvalidDataType
	}
	var fresh []ACLEntry
	for r.Next() == nil {
		e, ok := decodeACLEntry(r, fabric)
		if !ok {
			return im.ConstraintError
		}
		fresh = append(fresh, e)
	}
	if r.ExitContainer() != nil {
		return im.InvalidDataType
	}
	if len(fresh) > EntriesPerFabric {
		return im.ResourceExhausted
	}
	var old []ACLEntry
	for _, e := range a.Entries {
		if e.FabricIndex == fabric {
			old = append(old, e)
		}
	}
	a.RemoveFabric(fabric)
	a.Entries = append(a.Entries, fresh...)
	for i := range fresh {
		change := uint8(ACLAdded)
		if i < len(old) {
			change = ACLChanged
		}
		entryChanged(ctx, change, &fresh[i])
	}
	for i := len(old) - 1; i >= len(fresh); i-- {
		entryChanged(ctx, ACLRemoved, &old[i])
	}
	return im.Success
}

func (a *AccessControl) count(fabric uint8) int {
	n := 0
	for _, e := range a.Entries {
		if e.FabricIndex == fabric {
			n++
		}
	}
	return n
}

// EncodeEntries writes the entries of the fabrics for which keep returns
// true, as an array under tag, for persistent storage.
func (a *AccessControl) EncodeEntries(w *tlv.Writer, tag tlv.Tag, keep func(fabric uint8) bool) {
	w.StartArray(tag)
	for i := range a.Entries {
		if keep(a.Entries[i].FabricIndex) {
			encodeACLEntry(w, tlv.Anonymous, &a.Entries[i], true)
		}
	}
	w.EndContainer()
}

// DecodeEntries appends the entries written by EncodeEntries; r is
// positioned on the array.
func (a *AccessControl) DecodeEntries(r *tlv.Reader) error {
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return errors.New("acl: malformed stored entries")
	}
	for r.Next() == nil {
		var fabric uint8
		sub := *r // a copy to find the fabric index first
		im.ForEachField(&sub, func(r *tlv.Reader, tag uint8) error {
			if tag == 0xFE {
				fabric, _ = r.Uint8()
			}
			return nil
		})
		e, ok := decodeACLEntry(r, fabric)
		if !ok || fabric == 0 {
			return errors.New("acl: invalid stored entry")
		}
		a.Entries = append(a.Entries, e)
	}
	return r.ExitContainer()
}
