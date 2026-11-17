package clusters

import (
	"errors"
	"net/netip"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Group limits per fabric (as the SDK's defaults): four groups, and four
// group key sets counting the IPK's.
const (
	MaxGroupsPerFabric    = 4
	MaxGroupKeysPerFabric = 4
	maxGroupNameLength    = 16
	maxEpochKeys          = 3
)

// Group key security policies (GroupKeySecurityPolicyEnum).
const (
	GroupKeyTrustFirst   = 0
	GroupKeyCacheAndSync = 1
)

// GroupKeySet is a group key set of a fabric (spec 11.2.6.4). Only the
// operational keys derived from its epoch keys are kept.
type GroupKeySet struct {
	FabricIndex uint8
	ID          uint16
	Policy      uint8
	Epochs      []GroupEpoch
}

// GroupEpoch is one epoch key of a key set.
type GroupEpoch struct {
	StartTime uint64 // epoch_us
	Keys      message.GroupKeys
	cipher    *message.Cipher
}

// GroupKeyMapping maps a group to the key set it uses (GroupKeyMapStruct).
type GroupKeyMapping struct {
	FabricIndex uint8
	GroupID     uint16
	KeySetID    uint16
}

// GroupInfo is a group with the endpoints that are its members
// (GroupInfoMapStruct).
type GroupInfo struct {
	FabricIndex uint8
	GroupID     uint16
	Name        string
	Endpoints   []uint16
}

// GroupData holds the group key sets, the group key map and the group
// table that the Group Key Management and Groups clusters manage, and
// answers the questions the message layer and the Interaction Model ask
// about groups.
type GroupData struct {
	Fabrics *fabric.Table
	KeySets []GroupKeySet
	KeyMap  []GroupKeyMapping
	Groups  []GroupInfo

	// OnChange, if set, is called after any change, so the data can be
	// saved and multicast memberships updated.
	OnChange func()

	keys []exchange.GroupKey // derived from the above by rebuild
}

func (g *GroupData) changed() {
	g.rebuild()
	if g.OnChange != nil {
		g.OnChange()
	}
}

// rebuild lists the keys group messages may arrive with: each epoch key of
// the key set each group is mapped to.
func (g *GroupData) rebuild() {
	g.keys = g.keys[:0]
	for _, m := range g.KeyMap {
		ks := g.keySet(m.FabricIndex, m.KeySetID)
		if ks == nil {
			continue
		}
		for i := range ks.Epochs {
			e := &ks.Epochs[i]
			if e.cipher == nil {
				c, err := message.NewCipher(e.Keys.Encryption[:])
				if err != nil {
					continue
				}
				e.cipher = c
			}
			g.keys = append(g.keys, exchange.GroupKey{
				FabricIndex: m.FabricIndex, GroupID: m.GroupID, SessionID: e.Keys.SessionID,
				Cipher: e.cipher, PrivacyKey: e.Keys.Privacy,
			})
		}
	}
}

// Keys implements exchange.GroupKeyFunc.
func (g *GroupData) Keys(sessionID uint16, yield func(k *exchange.GroupKey) bool) {
	for i := range g.keys {
		if g.keys[i].SessionID == sessionID && !yield(&g.keys[i]) {
			return
		}
	}
}

// Endpoints returns the endpoints that are members of a group, for
// im.Server.GroupEndpoints.
func (g *GroupData) Endpoints(fabricIndex uint8, groupID uint16) []uint16 {
	if gi := g.group(fabricIndex, groupID); gi != nil {
		return gi.Endpoints
	}
	return nil
}

// MulticastAddrs returns the IPv6 multicast addresses of the groups with
// members, which the node must listen on.
func (g *GroupData) MulticastAddrs() []netip.Addr {
	var out []netip.Addr
	for _, gi := range g.Groups {
		f := g.Fabrics.Get(gi.FabricIndex)
		if f == nil || len(gi.Endpoints) == 0 {
			continue
		}
		out = append(out, exchange.GroupMulticastAddr(f.FabricID, gi.GroupID))
	}
	return out
}

// RemoveFabric drops a fabric's groups and keys.
func (g *GroupData) RemoveFabric(index uint8) {
	g.KeySets = filter(g.KeySets, func(k *GroupKeySet) bool { return k.FabricIndex != index })
	g.KeyMap = filter(g.KeyMap, func(m *GroupKeyMapping) bool { return m.FabricIndex != index })
	g.Groups = filter(g.Groups, func(gi *GroupInfo) bool { return gi.FabricIndex != index })
	g.changed()
}

func filter[T any](s []T, keep func(*T) bool) []T {
	out := s[:0]
	for i := range s {
		if keep(&s[i]) {
			out = append(out, s[i])
		}
	}
	clear(s[len(out):])
	return out
}

func (g *GroupData) keySet(fabricIndex uint8, id uint16) *GroupKeySet {
	for i := range g.KeySets {
		if g.KeySets[i].FabricIndex == fabricIndex && g.KeySets[i].ID == id {
			return &g.KeySets[i]
		}
	}
	return nil
}

func (g *GroupData) group(fabricIndex uint8, id uint16) *GroupInfo {
	for i := range g.Groups {
		if g.Groups[i].FabricIndex == fabricIndex && g.Groups[i].GroupID == id {
			return &g.Groups[i]
		}
	}
	return nil
}

func (g *GroupData) mapped(fabricIndex uint8, groupID uint16) bool {
	for _, m := range g.KeyMap {
		if m.FabricIndex == fabricIndex && m.GroupID == groupID {
			return true
		}
	}
	return false
}

func countFabric[T any](s []T, fabricOf func(*T) uint8, index uint8) int {
	n := 0
	for i := range s {
		if fabricOf(&s[i]) == index {
			n++
		}
	}
	return n
}

// addEndpoint makes endpoint a member of a group, naming the group.
func (g *GroupData) addEndpoint(fabricIndex uint8, groupID uint16, name string, endpoint uint16) im.Status {
	gi := g.group(fabricIndex, groupID)
	if gi == nil {
		if countFabric(g.Groups, func(x *GroupInfo) uint8 { return x.FabricIndex }, fabricIndex) >= MaxGroupsPerFabric {
			return im.ResourceExhausted
		}
		g.Groups = append(g.Groups, GroupInfo{FabricIndex: fabricIndex, GroupID: groupID})
		gi = &g.Groups[len(g.Groups)-1]
	}
	gi.Name = name
	for _, e := range gi.Endpoints {
		if e == endpoint {
			return im.Success
		}
	}
	gi.Endpoints = append(gi.Endpoints, endpoint)
	return im.Success
}

// ForgetEndpoint ends every group membership of an endpoint that is gone
// (a bridged device removed), reporting the change. It reports whether
// the endpoint was in any group.
func (g *GroupData) ForgetEndpoint(n *im.Node, endpoint uint16) bool {
	found := false
	for i := 0; i < len(g.Groups); i++ {
		gi := &g.Groups[i]
		if g.removeEndpoint(gi.FabricIndex, gi.GroupID, endpoint) {
			found = true
			i = -1 // the group may be gone: start over
		}
	}
	if found {
		g.changed()
		n.Changed(0, IDGroupKeyManagement, gkGroupTable)
	}
	return found
}

// removeEndpoint ends endpoint's membership of a group, dropping a group
// left without members. It reports whether endpoint was a member.
func (g *GroupData) removeEndpoint(fabricIndex uint8, groupID uint16, endpoint uint16) bool {
	gi := g.group(fabricIndex, groupID)
	if gi == nil || !hasEndpoint(gi.Endpoints, endpoint) {
		return false
	}
	gi.Endpoints = filter(gi.Endpoints, func(e *uint16) bool { return *e != endpoint })
	if len(gi.Endpoints) == 0 {
		g.Groups = filter(g.Groups, func(x *GroupInfo) bool { return x.FabricIndex != fabricIndex || x.GroupID != groupID })
	}
	return true
}

// ---- Group Key Management ----

// GroupKeyManagement is the Group Key Management cluster (spec 11.2): the
// group key sets of each fabric and the key set each group uses. Key set
// 0 is the fabric's IPK, which it reads but cannot change.
type GroupKeyManagement struct {
	im.ClusterBase
	Data *GroupData
}

const (
	gkGroupKeyMap            = 0
	gkGroupTable             = 1
	gkMaxGroupsPerFabric     = 2
	gkMaxGroupKeysPerFabric  = 3
	gkKeySetWrite            = 0x00
	gkKeySetRead             = 0x01
	gkKeySetReadResponse     = 0x02
	gkKeySetRemove           = 0x03
	gkKeySetReadAllIndices   = 0x04
	gkKeySetReadAllResponse  = 0x05
	groupKeySetIPK           = 0
	gkFieldFabricIndex       = 0xFE
	groupNameSupport         = 0x80 // NameSupportBitmap.GroupNames
	groupsFeatureGroupNames  = 1
	groupsAddGroup           = 0x00
	groupsViewGroup          = 0x01
	groupsGetGroupMembership = 0x02
	groupsRemoveGroup        = 0x03
	groupsRemoveAllGroups    = 0x04
	groupsAddIfIdentifying   = 0x05
)

var (
	gkAttrs     = []uint32{gkGroupKeyMap, gkGroupTable, gkMaxGroupsPerFabric, gkMaxGroupKeysPerFabric}
	gkAccepted  = []uint32{gkKeySetWrite, gkKeySetRead, gkKeySetRemove, gkKeySetReadAllIndices}
	gkGenerated = []uint32{gkKeySetReadResponse, gkKeySetReadAllResponse}
)

func (*GroupKeyManagement) ID() uint32                  { return IDGroupKeyManagement }
func (*GroupKeyManagement) Revision() uint16            { return 4 }
func (*GroupKeyManagement) Attributes() []uint32        { return gkAttrs }
func (*GroupKeyManagement) AcceptedCommands() []uint32  { return gkAccepted }
func (*GroupKeyManagement) GeneratedCommands() []uint32 { return gkGenerated }

func (*GroupKeyManagement) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*GroupKeyManagement) WritePrivilege(uint32) im.Privilege  { return im.Manage }
func (*GroupKeyManagement) InvokePrivilege(uint32) im.Privilege { return im.Administer }

func (k *GroupKeyManagement) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	d := k.Data
	switch attr {
	case gkGroupKeyMap:
		w.StartArray(tag)
		for _, m := range d.KeyMap {
			if ctx.FabricFiltered && m.FabricIndex != accessingFabric(ctx) {
				continue
			}
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), uint64(m.GroupID))
			w.PutUint(tlv.ContextTag(2), uint64(m.KeySetID))
			w.PutUint(tlv.ContextTag(gkFieldFabricIndex), uint64(m.FabricIndex))
			w.EndContainer()
		}
		w.EndContainer()
	case gkGroupTable:
		w.StartArray(tag)
		for _, gi := range d.Groups {
			if ctx.FabricFiltered && gi.FabricIndex != accessingFabric(ctx) {
				continue
			}
			encodeGroupInfo(w, tlv.Anonymous, &gi)
		}
		w.EndContainer()
	case gkMaxGroupsPerFabric:
		w.PutUint(tag, MaxGroupsPerFabric)
	case gkMaxGroupKeysPerFabric:
		w.PutUint(tag, MaxGroupKeysPerFabric)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func encodeGroupInfo(w *tlv.Writer, tag tlv.Tag, gi *GroupInfo) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(1), uint64(gi.GroupID))
	w.StartArray(tlv.ContextTag(2))
	for _, e := range gi.Endpoints {
		w.PutUint(tlv.Anonymous, uint64(e))
	}
	w.EndContainer()
	w.PutString(tlv.ContextTag(3), gi.Name)
	w.PutUint(tlv.ContextTag(gkFieldFabricIndex), uint64(gi.FabricIndex))
	w.EndContainer()
}

func decodeKeyMapping(r *tlv.Reader, fabric uint8) (GroupKeyMapping, im.Status) {
	m := GroupKeyMapping{FabricIndex: fabric}
	var have uint8
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			m.GroupID, err = r.Uint16()
			have |= 1
		case 2:
			m.KeySetID, err = r.Uint16()
			have |= 2
		}
		return err
	})
	if err != nil || have != 3 {
		return m, im.InvalidDataType
	}
	if m.GroupID == 0 || m.KeySetID == groupKeySetIPK { // the IPK cannot be mapped to a group
		return m, im.ConstraintError
	}
	return m, im.Success
}

// WriteAttribute replaces or appends to the accessing fabric's group key
// map. A group maps to one key set.
func (k *GroupKeyManagement) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != gkGroupKeyMap {
		return im.UnsupportedWrite
	}
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return im.UnsupportedAccess
	}
	d := k.Data
	fabricOf := func(m *GroupKeyMapping) uint8 { return m.FabricIndex }
	if appendItem {
		m, st := decodeKeyMapping(r, fabric)
		if st != im.Success {
			return st
		}
		if d.mapped(fabric, m.GroupID) {
			return im.ConstraintError
		}
		if countFabric(d.KeyMap, fabricOf, fabric) >= MaxGroupsPerFabric {
			return im.ResourceExhausted
		}
		d.KeyMap = append(d.KeyMap, m)
		d.changed()
		return im.Success
	}
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return im.InvalidDataType
	}
	var fresh []GroupKeyMapping
	for r.Next() == nil {
		m, st := decodeKeyMapping(r, fabric)
		if st != im.Success {
			return st
		}
		for _, x := range fresh {
			if x.GroupID == m.GroupID {
				return im.ConstraintError
			}
		}
		fresh = append(fresh, m)
	}
	if r.ExitContainer() != nil {
		return im.InvalidDataType
	}
	if len(fresh) > MaxGroupsPerFabric {
		return im.ResourceExhausted
	}
	d.KeyMap = filter(d.KeyMap, func(m *GroupKeyMapping) bool { return m.FabricIndex != fabric })
	d.KeyMap = append(d.KeyMap, fresh...)
	d.changed()
	return im.Success
}

// keySetWrite decodes a GroupKeySetStruct and validates it as the SDK
// does.
func (k *GroupKeyManagement) keySetWrite(ctx *im.Context, fabricIndex uint8, r *tlv.Reader) im.Status {
	var (
		id         uint16
		policy     uint64
		keys       [maxEpochKeys][]byte
		starts     [maxEpochKeys]uint64
		keyNull    [maxEpochKeys]bool
		startNull  [maxEpochKeys]bool
		have, seen uint8
	)
	for i := range keyNull { // absent epoch keys 1 and 2 count as null
		keyNull[i], startNull[i] = true, true
	}
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		if tag != 0 {
			return nil
		}
		have = 1
		return im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			if tag > 7 {
				return nil
			}
			seen |= 1 << tag
			switch {
			case tag == 0:
				id, err = r.Uint16()
			case tag == 1:
				policy, err = r.Uint()
			case r.IsNull():
			case tag%2 == 0: // epochKeyN
				i := tag/2 - 1
				keys[i], err = r.Bytes()
				keyNull[i] = false
			default: // epochStartTimeN
				i := tag/2 - 1
				starts[i], err = r.Uint()
				startNull[i] = false
			}
			return err
		})
	})
	if err != nil || have == 0 || seen&0x0F != 0x0F {
		return im.InvalidCommand
	}
	if id == groupKeySetIPK {
		return im.InvalidCommand // the IPK is set by AddNOC
	}
	switch policy {
	case GroupKeyTrustFirst:
	case GroupKeyCacheAndSync:
		return im.InvalidCommand // needs message counter synchronization
	default:
		return im.ConstraintError
	}
	if keyNull[0] || startNull[0] || starts[0] == 0 {
		return im.InvalidCommand
	}
	n := 1
	for i := 0; i < maxEpochKeys; i++ {
		if keyNull[i] != startNull[i] {
			return im.InvalidCommand
		}
		if keyNull[i] {
			continue
		}
		if len(keys[i]) != message.KeySize {
			return im.ConstraintError
		}
		if i > 0 {
			if keyNull[i-1] || starts[i] <= starts[i-1] {
				return im.InvalidCommand
			}
			n = i + 1
		}
	}
	f := k.Data.Fabrics.Get(fabricIndex)
	if f == nil {
		return im.UnsupportedAccess
	}
	ks := GroupKeySet{FabricIndex: fabricIndex, ID: id, Policy: uint8(policy)}
	for i := 0; i < n; i++ {
		gk, err := message.DeriveGroupKeys(keys[i], f.CompressedFabricID)
		if err != nil {
			return im.Failure
		}
		ks.Epochs = append(ks.Epochs, GroupEpoch{StartTime: starts[i], Keys: gk})
	}
	d := k.Data
	if old := d.keySet(fabricIndex, id); old != nil {
		*old = ks
	} else {
		// The IPK counts toward MaxGroupKeysPerFabric.
		if countFabric(d.KeySets, func(x *GroupKeySet) uint8 { return x.FabricIndex }, fabricIndex)+1 >= MaxGroupKeysPerFabric {
			return im.ResourceExhausted
		}
		d.KeySets = append(d.KeySets, ks)
	}
	d.changed()
	return im.Success
}

func (k *GroupKeyManagement) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	fabricIndex := accessingFabric(ctx)
	if fabricIndex == 0 {
		return im.UnsupportedAccess
	}
	d := k.Data
	switch cmd {
	case gkKeySetWrite:
		return k.keySetWrite(ctx, fabricIndex, r)

	case gkKeySetRead, gkKeySetRemove:
		var id uint16
		have := false
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			if tag == 0 {
				id, err = r.Uint16()
				have = true
			}
			return err
		})
		if err != nil || !have {
			return im.InvalidCommand
		}
		if cmd == gkKeySetRemove {
			if id == groupKeySetIPK {
				return im.InvalidCommand
			}
			if d.keySet(fabricIndex, id) == nil {
				return im.NotFound
			}
			d.KeySets = filter(d.KeySets, func(x *GroupKeySet) bool { return x.FabricIndex != fabricIndex || x.ID != id })
			n := len(d.KeyMap)
			d.KeyMap = filter(d.KeyMap, func(m *GroupKeyMapping) bool { return m.FabricIndex != fabricIndex || m.KeySetID != id })
			if len(d.KeyMap) != n {
				ctx.Node.Changed(0, IDGroupKeyManagement, gkGroupKeyMap)
			}
			d.changed()
			return im.Success
		}
		var ks *GroupKeySet
		ipk := GroupKeySet{FabricIndex: fabricIndex, ID: groupKeySetIPK, Policy: GroupKeyTrustFirst, Epochs: make([]GroupEpoch, 1)}
		if id == groupKeySetIPK {
			ks = &ipk
		} else if ks = d.keySet(fabricIndex, id); ks == nil {
			return im.NotFound
		}
		w := resp.Fields(gkKeySetReadResponse)
		w.StartStruct(tlv.ContextTag(0))
		w.PutUint(tlv.ContextTag(0), uint64(ks.ID))
		w.PutUint(tlv.ContextTag(1), uint64(ks.Policy))
		for i := 0; i < maxEpochKeys; i++ {
			w.PutNull(tlv.ContextTag(uint8(2 + 2*i))) // epoch keys are never read back
			if i < len(ks.Epochs) {
				w.PutUint(tlv.ContextTag(uint8(3+2*i)), ks.Epochs[i].StartTime)
			} else {
				w.PutNull(tlv.ContextTag(uint8(3 + 2*i)))
			}
		}
		w.EndContainer()
		return im.Success

	case gkKeySetReadAllIndices:
		w := resp.Fields(gkKeySetReadAllResponse)
		w.StartArray(tlv.ContextTag(0))
		w.PutUint(tlv.Anonymous, groupKeySetIPK)
		for _, ks := range d.KeySets {
			if ks.FabricIndex == fabricIndex {
				w.PutUint(tlv.Anonymous, uint64(ks.ID))
			}
		}
		w.EndContainer()
		return im.Success
	}
	return im.UnsupportedCommand
}

// ---- Groups ----

// Groups is the Groups cluster of an endpoint (spec 1.3): it adds the
// endpoint to groups, whose commands then reach it. A group must have a
// key set mapped to it first (Group Key Management).
type Groups struct {
	im.ClusterBase
	Data *GroupData
	// Identify, if set, is the endpoint's Identify cluster, for
	// AddGroupIfIdentifying.
	Identify *Identify
	// Scenes, if set, is the endpoint's Scenes Management cluster: leaving
	// a group deletes the group's scenes.
	Scenes *ScenesManagement
}

func (g *Groups) removeScenes(ctx *im.Context, fabricIndex uint8, id uint16) {
	if g.Scenes != nil {
		g.Scenes.RemoveGroup(ctx.Node, ctx.Endpoint, fabricIndex, id)
	}
}

var (
	groupsAttrs     = []uint32{0}
	groupsAccepted  = []uint32{groupsAddGroup, groupsViewGroup, groupsGetGroupMembership, groupsRemoveGroup, groupsRemoveAllGroups, groupsAddIfIdentifying}
	groupsGenerated = []uint32{groupsAddGroup, groupsViewGroup, groupsGetGroupMembership, groupsRemoveGroup}
)

func (*Groups) ID() uint32                  { return IDGroups }
func (*Groups) Revision() uint16            { return 4 }
func (*Groups) FeatureMap() uint32          { return groupsFeatureGroupNames }
func (*Groups) Attributes() []uint32        { return groupsAttrs }
func (*Groups) AcceptedCommands() []uint32  { return groupsAccepted }
func (*Groups) GeneratedCommands() []uint32 { return groupsGenerated }

func (*Groups) ReadPrivilege(uint32) im.Privilege  { return im.View }
func (*Groups) WritePrivilege(uint32) im.Privilege { return im.Operate }
func (*Groups) InvokePrivilege(cmd uint32) im.Privilege {
	if cmd == groupsViewGroup || cmd == groupsGetGroupMembership {
		return im.Operate
	}
	return im.Manage
}

func (*Groups) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr != 0 {
		return im.UnsupportedAttribute
	}
	w.PutUint(tag, groupNameSupport)
	return im.Success
}

func (*Groups) WriteAttribute(*im.Context, uint32, bool, *tlv.Reader) im.Status {
	return im.UnsupportedWrite
}

var errGroupFields = errors.New("groups: bad fields")

func decodeGroupRequest(r *tlv.Reader) (id uint16, name string, err error) {
	have := false
	err = im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			id, err = r.Uint16()
			have = true
		case 1:
			var b []byte
			b, err = r.UTF8()
			name = string(b)
		}
		return err
	})
	if err == nil && !have {
		err = errGroupFields
	}
	return id, name, err
}

func (g *Groups) addGroup(ctx *im.Context, fabricIndex uint8, id uint16, name string) im.Status {
	switch {
	case id == 0 || len(name) > maxGroupNameLength:
		return im.ConstraintError
	case !g.Data.mapped(fabricIndex, id):
		return im.UnsupportedAccess // no key set for the group
	}
	st := g.Data.addEndpoint(fabricIndex, id, name, ctx.Endpoint)
	if st == im.Success {
		g.groupTableChanged(ctx)
	}
	return st
}

func (g *Groups) groupTableChanged(ctx *im.Context) {
	ctx.Node.Changed(0, IDGroupKeyManagement, gkGroupTable)
	g.Data.changed()
}

func groupStatusResponse(resp *im.Response, cmd uint32, st im.Status, id uint16) im.Status {
	w := resp.Fields(cmd)
	w.PutUint(tlv.ContextTag(0), uint64(st))
	w.PutUint(tlv.ContextTag(1), uint64(id))
	return im.Success
}

func (g *Groups) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	fabricIndex := accessingFabric(ctx)
	if fabricIndex == 0 {
		return im.UnsupportedAccess
	}
	d := g.Data
	switch cmd {
	case groupsAddGroup, groupsAddIfIdentifying:
		id, name, err := decodeGroupRequest(r)
		if err != nil {
			return im.InvalidCommand
		}
		if cmd == groupsAddIfIdentifying {
			if g.Identify == nil || !g.Identify.Identifying() {
				return im.Success
			}
			return g.addGroup(ctx, fabricIndex, id, name)
		}
		return groupStatusResponse(resp, groupsAddGroup, g.addGroup(ctx, fabricIndex, id, name), id)

	case groupsViewGroup, groupsRemoveGroup:
		id, _, err := decodeGroupRequest(r)
		if err != nil {
			return im.InvalidCommand
		}
		st := im.Success
		gi := d.group(fabricIndex, id)
		member := gi != nil && hasEndpoint(gi.Endpoints, ctx.Endpoint)
		switch {
		case id == 0:
			st = im.ConstraintError
		case !member:
			st = im.NotFound
		case cmd == groupsRemoveGroup:
			g.removeScenes(ctx, fabricIndex, id)
			d.removeEndpoint(fabricIndex, id, ctx.Endpoint)
			g.groupTableChanged(ctx)
		}
		if cmd == groupsRemoveGroup {
			return groupStatusResponse(resp, groupsRemoveGroup, st, id)
		}
		w := resp.Fields(groupsViewGroup)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		w.PutUint(tlv.ContextTag(1), uint64(id))
		name := ""
		if st == im.Success {
			name = gi.Name
		}
		w.PutString(tlv.ContextTag(2), name)
		return im.Success

	case groupsGetGroupMembership:
		var want []uint16
		have := false
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
			if tag != 0 {
				return nil
			}
			have = true
			if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
				return errGroupFields
			}
			for r.Next() == nil {
				v, err := r.Uint16()
				if err != nil {
					return err
				}
				want = append(want, v)
			}
			return r.ExitContainer()
		})
		if err != nil || !have {
			return im.InvalidCommand
		}
		w := resp.Fields(groupsGetGroupMembership)
		w.PutNull(tlv.ContextTag(0)) // capacity unknown
		w.StartArray(tlv.ContextTag(1))
		for _, gi := range d.Groups {
			if gi.FabricIndex != fabricIndex || !hasEndpoint(gi.Endpoints, ctx.Endpoint) {
				continue
			}
			if len(want) > 0 && !hasEndpoint(want, gi.GroupID) {
				continue
			}
			w.PutUint(tlv.Anonymous, uint64(gi.GroupID))
		}
		w.EndContainer()
		return im.Success

	case groupsRemoveAllGroups:
		removed := false
		g.removeScenes(ctx, fabricIndex, 0)
		for _, gi := range append([]GroupInfo(nil), d.Groups...) {
			if gi.FabricIndex == fabricIndex && hasEndpoint(gi.Endpoints, ctx.Endpoint) {
				g.removeScenes(ctx, fabricIndex, gi.GroupID)
				d.removeEndpoint(fabricIndex, gi.GroupID, ctx.Endpoint)
				removed = true
			}
		}
		if removed {
			g.groupTableChanged(ctx)
		}
		return im.Success
	}
	return im.UnsupportedCommand
}

func hasEndpoint(s []uint16, v uint16) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ---- Persistence ----

// Encode writes the group data of the fabrics for which keep returns true
// under tag, for persistent storage:
//
//	{ 1: [ { 1: fabric, 2: key set ID, 3: policy,
//	         4: [ { 1: start time, 2: operational key } ] } ],
//	  2: [ { 1: fabric, 2: group, 3: key set ID } ],
//	  3: [ { 1: fabric, 2: group, 3: name, 4: [endpoints] } ] }
func (g *GroupData) Encode(w *tlv.Writer, tag tlv.Tag, keep func(fabric uint8) bool) {
	w.StartStruct(tag)
	w.StartArray(tlv.ContextTag(1))
	for _, ks := range g.KeySets {
		if !keep(ks.FabricIndex) {
			continue
		}
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), uint64(ks.FabricIndex))
		w.PutUint(tlv.ContextTag(2), uint64(ks.ID))
		w.PutUint(tlv.ContextTag(3), uint64(ks.Policy))
		w.StartArray(tlv.ContextTag(4))
		for _, e := range ks.Epochs {
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), e.StartTime)
			w.PutBytes(tlv.ContextTag(2), e.Keys.Encryption[:])
			w.EndContainer()
		}
		w.EndContainer()
		w.EndContainer()
	}
	w.EndContainer()
	w.StartArray(tlv.ContextTag(2))
	for _, m := range g.KeyMap {
		if !keep(m.FabricIndex) {
			continue
		}
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), uint64(m.FabricIndex))
		w.PutUint(tlv.ContextTag(2), uint64(m.GroupID))
		w.PutUint(tlv.ContextTag(3), uint64(m.KeySetID))
		w.EndContainer()
	}
	w.EndContainer()
	w.StartArray(tlv.ContextTag(3))
	for _, gi := range g.Groups {
		if !keep(gi.FabricIndex) {
			continue
		}
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), uint64(gi.FabricIndex))
		w.PutUint(tlv.ContextTag(2), uint64(gi.GroupID))
		w.PutString(tlv.ContextTag(3), gi.Name)
		w.StartArray(tlv.ContextTag(4))
		for _, e := range gi.Endpoints {
			w.PutUint(tlv.Anonymous, uint64(e))
		}
		w.EndContainer()
		w.EndContainer()
	}
	w.EndContainer()
	w.EndContainer()
}

var errGroupState = errors.New("groups: malformed stored state")

// eachItem calls f for each element of the array r is positioned on.
func eachItem(r *tlv.Reader, f func() error) error {
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return errGroupState
	}
	for r.Next() == nil {
		if err := f(); err != nil {
			return err
		}
	}
	return r.ExitContainer()
}

// Decode restores what Encode wrote; r is positioned on the structure.
func (g *GroupData) Decode(r *tlv.Reader) error {
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		switch tag {
		case 1:
			return eachItem(r, func() error {
				var ks GroupKeySet
				err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
					switch tag {
					case 1:
						ks.FabricIndex, err = r.Uint8()
					case 2:
						ks.ID, err = r.Uint16()
					case 3:
						ks.Policy, err = r.Uint8()
					case 4:
						return eachItem(r, func() error {
							var e GroupEpoch
							var op []byte
							err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
								switch tag {
								case 1:
									e.StartTime, err = r.Uint()
								case 2:
									op, err = r.Bytes()
								}
								return err
							})
							if err != nil || len(op) != message.KeySize {
								return errGroupState
							}
							var key [message.KeySize]byte
							copy(key[:], op)
							if e.Keys, err = message.GroupKeysFromOperational(key); err != nil {
								return err
							}
							ks.Epochs = append(ks.Epochs, e)
							return nil
						})
					}
					return err
				})
				if err != nil || len(ks.Epochs) == 0 || len(ks.Epochs) > maxEpochKeys {
					return errGroupState
				}
				g.KeySets = append(g.KeySets, ks)
				return nil
			})
		case 2:
			return eachItem(r, func() error {
				var m GroupKeyMapping
				err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
					switch tag {
					case 1:
						m.FabricIndex, err = r.Uint8()
					case 2:
						m.GroupID, err = r.Uint16()
					case 3:
						m.KeySetID, err = r.Uint16()
					}
					return err
				})
				g.KeyMap = append(g.KeyMap, m)
				return err
			})
		case 3:
			return eachItem(r, func() error {
				var gi GroupInfo
				err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
					switch tag {
					case 1:
						gi.FabricIndex, err = r.Uint8()
					case 2:
						gi.GroupID, err = r.Uint16()
					case 3:
						var b []byte
						b, err = r.UTF8()
						gi.Name = string(b)
					case 4:
						return eachItem(r, func() error {
							e, err := r.Uint16()
							gi.Endpoints = append(gi.Endpoints, e)
							return err
						})
					}
					return err
				})
				g.Groups = append(g.Groups, gi)
				return err
			})
		}
		return nil
	})
	if err != nil {
		return err
	}
	g.rebuild()
	return nil
}
