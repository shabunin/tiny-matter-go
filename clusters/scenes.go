package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// IDScenesManagement is the Scenes Management cluster ID.
const IDScenesManagement = 0x0062

// scenePair is one AttributeValuePairStruct of a scene's extension field
// set: an attribute and its value in the value field kind (the field's
// tag: 1 u8, 2 s8, 3 u16, 4 s16, 5 u32, 6 s32, 7 u64, 8 s64).
type scenePair struct {
	attr uint32
	kind uint8
	v    int64
}

const (
	sceneU8  = 1
	sceneU16 = 3
)

// sceneCluster is a cluster whose state scenes capture and recall.
type sceneCluster interface {
	im.Cluster
	// sceneSave appends the cluster's current values.
	sceneSave(dst []scenePair) []scenePair
	// sceneKind returns the value field an attribute is stored in, or 0 if
	// scenes do not hold it.
	sceneKind(attr uint32) uint8
	// sceneClamp brings a value from AddScene into the attribute's range.
	sceneClamp(p *scenePair)
	// sceneApply recalls values over a transition.
	sceneApply(n *im.Node, ep uint16, now time.Time, pairs []scenePair, dur time.Duration) im.Status
}

func clampPair(p *scenePair, lo, hi int64) { p.v = min(max(p.v, lo), hi) }

// sceneValue returns the value of attr among pairs.
func sceneValue(pairs []scenePair, attr uint32) (int64, bool) {
	for _, p := range pairs {
		if p.attr == attr {
			return p.v, true
		}
	}
	return 0, false
}

// Scene limits (the SDK's defaults).
const (
	sceneTableSize       = 16
	scenesPerFabric      = (sceneTableSize - 1) / 2
	sceneNameMax         = 16
	sceneMaxTransitionMs = 60_000_000
	sceneMaxSets         = 4
	sceneMaxPairs        = 15
	sceneUndefined       = 0xFF
)

// SceneSet is a scene's extension field set: the values of one cluster.
type sceneSet struct {
	cluster uint32
	pairs   []scenePair
}

// scene is one entry of an endpoint's scene table.
type scene struct {
	fabric       uint8
	group        uint16
	id           uint8
	name         string
	transitionMs uint32
	sets         []sceneSet
}

// ScenesManagement is the Scenes Management cluster of an endpoint (spec
// 1.4, revision 2, with scene names): scenes are stored values of the
// endpoint's On/Off, Level Control and Color Control clusters, per fabric
// and group, recalled with a transition. Group 0 scene 0 is the global
// scene On/Off stores and recalls.
//
// FabricSceneInfo tracks each fabric's current scene: the one it last
// stored or recalled, valid until a command changes the endpoint's lights
// (Invalidate) or the scene is removed. Like the SDK, it lists a fabric
// once the fabric has had a scene. It is not kept across restarts.
type ScenesManagement struct {
	im.ClusterBase
	// Groups is the node's group data: scenes of a group need the
	// endpoint to be in it.
	Groups *GroupData

	scenes  []scene
	current []currentScene
}

// currentScene is a fabric's CurrentScene, CurrentGroup and SceneValid.
type currentScene struct {
	fabric uint8
	group  uint16
	id     uint8
	valid  bool
}

func (s *ScenesManagement) currentOf(fabric uint8) *currentScene {
	for i := range s.current {
		if s.current[i].fabric == fabric {
			return &s.current[i]
		}
	}
	return nil
}

// setCurrent makes a scene its fabric's current, valid scene.
func (s *ScenesManagement) setCurrent(ctx *im.Context, fabric uint8, group uint16, id uint8) {
	c := s.currentOf(fabric)
	if c == nil {
		s.current = append(s.current, currentScene{fabric: fabric})
		c = &s.current[len(s.current)-1]
	}
	if *c != (currentScene{fabric, group, id, true}) {
		*c = currentScene{fabric, group, id, true}
		ctx.Node.Changed(ctx.Endpoint, IDScenesManagement, scenesFabricInfo)
	}
}

// invalidate clears SceneValid of the current scenes match selects (all of
// them with a nil match).
func (s *ScenesManagement) invalidate(n *im.Node, ep uint16, match func(c *currentScene) bool) {
	changed := false
	for i := range s.current {
		if c := &s.current[i]; c.valid && (match == nil || match(c)) {
			c.valid = false
			changed = true
		}
	}
	if changed {
		n.Changed(ep, IDScenesManagement, scenesFabricInfo)
	}
}

// Invalidate marks every fabric's current scene invalid: call it when a
// command (not a scene recall) changes a cluster that scenes hold on the
// endpoint, as the SDK's On/Off, Level and Color servers do.
func (s *ScenesManagement) Invalidate(n *im.Node, ep uint16) { s.invalidate(n, ep, nil) }

// NewScenes returns Scenes Management over the node's groups.
func NewScenes(groups *GroupData) *ScenesManagement { return &ScenesManagement{Groups: groups} }

const (
	scenesTableSize      = 0x0001
	scenesFabricInfo     = 0x0002
	scenesFeatureNames   = 0x1
	scenesAdd            = 0x00
	scenesView           = 0x01
	scenesRemove         = 0x02
	scenesRemoveAll      = 0x03
	scenesStore          = 0x04
	scenesRecall         = 0x05
	scenesGetMembership  = 0x06
	scenesCopy           = 0x40
	scenesCopyAll        = 0x01
	globalSceneGroup     = 0
	globalSceneID        = 0
	scenesFieldFabricIdx = 0xFE
)

var (
	scenesAttrs     = []uint32{scenesTableSize, scenesFabricInfo}
	scenesAccepted  = []uint32{scenesAdd, scenesView, scenesRemove, scenesRemoveAll, scenesStore, scenesRecall, scenesGetMembership, scenesCopy}
	scenesGenerated = []uint32{scenesAdd, scenesView, scenesRemove, scenesRemoveAll, scenesStore, scenesGetMembership, scenesCopy}
)

func (*ScenesManagement) ID() uint32                  { return IDScenesManagement }
func (*ScenesManagement) Revision() uint16            { return 2 }
func (*ScenesManagement) FeatureMap() uint32          { return scenesFeatureNames }
func (*ScenesManagement) Attributes() []uint32        { return scenesAttrs }
func (*ScenesManagement) AcceptedCommands() []uint32  { return scenesAccepted }
func (*ScenesManagement) GeneratedCommands() []uint32 { return scenesGenerated }

func (*ScenesManagement) ReadPrivilege(uint32) im.Privilege  { return im.View }
func (*ScenesManagement) WritePrivilege(uint32) im.Privilege { return im.Operate }

func (*ScenesManagement) InvokePrivilege(cmd uint32) im.Privilege {
	switch cmd {
	case scenesView, scenesRecall, scenesGetMembership:
		return im.Operate
	}
	return im.Manage
}

func (s *ScenesManagement) count(fabric uint8) (perFabric, all int) {
	for i := range s.scenes {
		if s.scenes[i].fabric == fabric {
			perFabric++
		}
	}
	return perFabric, len(s.scenes)
}

// capacity returns RemainingCapacity for a fabric.
func (s *ScenesManagement) capacity(fabric uint8) int {
	f, all := s.count(fabric)
	return max(0, min(scenesPerFabric-f, sceneTableSize-all))
}

func (s *ScenesManagement) find(fabric uint8, group uint16, id uint8) *scene {
	for i := range s.scenes {
		sc := &s.scenes[i]
		if sc.fabric == fabric && sc.group == group && sc.id == id {
			return sc
		}
	}
	return nil
}

func (s *ScenesManagement) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case scenesTableSize:
		w.PutUint(tag, sceneTableSize)
	case scenesFabricInfo:
		accessing := accessingFabric(ctx)
		w.StartArray(tag)
		if s.Groups != nil && s.Groups.Fabrics != nil {
			for _, f := range s.Groups.Fabrics.Fabrics() {
				if f.Pending || (ctx.FabricFiltered && f.Index != accessing) {
					continue
				}
				n, _ := s.count(f.Index)
				c := s.currentOf(f.Index)
				if c == nil && n == 0 {
					continue // never had a scene
				}
				w.StartStruct(tlv.Anonymous)
				w.PutUint(tlv.ContextTag(0), uint64(n))
				if f.Index == accessing { // fabric-sensitive fields
					var cur currentScene
					if c != nil {
						cur = *c
					}
					w.PutUint(tlv.ContextTag(1), uint64(cur.id))
					w.PutUint(tlv.ContextTag(2), uint64(cur.group))
					w.PutBool(tlv.ContextTag(3), cur.valid)
				}
				w.PutUint(tlv.ContextTag(4), uint64(s.capacity(f.Index)))
				w.PutUint(tlv.ContextTag(scenesFieldFabricIdx), uint64(f.Index))
				w.EndContainer()
			}
		}
		w.EndContainer()
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// inGroup reports whether the endpoint may hold scenes of a group: group
// 0, or a group the endpoint is in.
func (s *ScenesManagement) inGroup(fabric uint8, group uint16, ep uint16) bool {
	return group == globalSceneGroup || (s.Groups != nil && hasEndpoint(s.Groups.Endpoints(fabric, group), ep))
}

// changed reports the table change (FabricSceneInfo), which also saves it.
func (s *ScenesManagement) changed(ctx *im.Context) {
	for _, sc := range s.scenes {
		if s.currentOf(sc.fabric) == nil {
			s.current = append(s.current, currentScene{fabric: sc.fabric})
		}
	}
	ctx.Node.Changed(ctx.Endpoint, IDScenesManagement, scenesFabricInfo)
}

// sceneClusters returns the endpoint's clusters that scenes hold, in
// data-model order.
func sceneClusters(n *im.Node, ep uint16) []sceneCluster {
	e := n.Endpoint(ep)
	if e == nil {
		return nil
	}
	var out []sceneCluster
	var ids [16]uint32
	for _, id := range e.ClusterIDs(ids[:0]) {
		if c, ok := e.Cluster(id).(sceneCluster); ok {
			out = append(out, c)
		}
	}
	return out
}

func sceneClusterOf(n *im.Node, ep uint16, id uint32) sceneCluster {
	if e := n.Endpoint(ep); e != nil {
		c, _ := e.Cluster(id).(sceneCluster)
		return c
	}
	return nil
}

// capture records the endpoint's current values.
func capture(n *im.Node, ep uint16) []sceneSet {
	var sets []sceneSet
	for _, c := range sceneClusters(n, ep) {
		if pairs := c.sceneSave(nil); len(pairs) > 0 {
			sets = append(sets, sceneSet{c.ID(), pairs})
		}
	}
	return sets
}

// apply recalls a scene's values over dur.
func apply(n *im.Node, ep uint16, now time.Time, sets []sceneSet, dur time.Duration) im.Status {
	st := im.Success
	for _, set := range sets {
		if c := sceneClusterOf(n, ep, set.cluster); c != nil {
			if s := c.sceneApply(n, ep, now, set.pairs, dur); s != im.Success {
				st = im.Failure
			}
		}
	}
	return st
}

// StoreGlobalScene stores the global scene (OnOff OffWithEffect).
func (s *ScenesManagement) StoreGlobalScene(ctx *im.Context) {
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return
	}
	s.store(ctx, fabric, globalSceneGroup, globalSceneID)
}

// RecallGlobalScene recalls the global scene (OnOff
// OnWithRecallGlobalScene).
func (s *ScenesManagement) RecallGlobalScene(ctx *im.Context) {
	fabric := accessingFabric(ctx)
	if sc := s.find(fabric, globalSceneGroup, globalSceneID); fabric != 0 && sc != nil {
		apply(ctx.Node, ctx.Endpoint, ctx.Now, sc.sets, time.Duration(sc.transitionMs)*time.Millisecond)
	}
}

// store captures the current values into a scene, keeping the name and
// transition time of an existing one.
func (s *ScenesManagement) store(ctx *im.Context, fabric uint8, group uint16, id uint8) im.Status {
	sets := capture(ctx.Node, ctx.Endpoint)
	if sc := s.find(fabric, group, id); sc != nil {
		sc.sets = sets
	} else {
		if s.capacity(fabric) == 0 {
			return im.ResourceExhausted
		}
		s.scenes = append(s.scenes, scene{fabric: fabric, group: group, id: id, sets: sets})
	}
	s.changed(ctx)
	if group != globalSceneGroup || id != globalSceneID {
		s.setCurrent(ctx, fabric, group, id)
	}
	return im.Success
}

// RemoveGroup deletes the scenes of a group on the endpoint (for the
// Groups cluster, before it removes the endpoint from the group).
func (s *ScenesManagement) RemoveGroup(n *im.Node, ep uint16, fabric uint8, group uint16) {
	before := len(s.scenes)
	s.scenes = filter(s.scenes, func(sc *scene) bool { return sc.fabric != fabric || sc.group != group })
	if len(s.scenes) != before {
		n.Changed(ep, IDScenesManagement, scenesFabricInfo)
	}
	s.invalidate(n, ep, func(c *currentScene) bool { return c.fabric == fabric && c.group == group })
}

// RemoveFabric deletes a fabric's scenes.
func (s *ScenesManagement) RemoveFabric(n *im.Node, ep uint16, fabric uint8) {
	before := len(s.scenes)
	s.scenes = filter(s.scenes, func(sc *scene) bool { return sc.fabric != fabric })
	if len(s.scenes) != before {
		n.Changed(ep, IDScenesManagement, scenesFabricInfo)
	}
	s.current = filter(s.current, func(c *currentScene) bool { return c.fabric != fabric })
}

// sceneStatusResponse writes a response with Status, GroupID and SceneID.
func sceneStatusResponse(resp *im.Response, cmd uint32, st im.Status, group uint16, id uint8) im.Status {
	w := resp.Fields(cmd)
	w.PutUint(tlv.ContextTag(0), uint64(st))
	w.PutUint(tlv.ContextTag(1), uint64(group))
	w.PutUint(tlv.ContextTag(2), uint64(id))
	return im.Success
}

func (s *ScenesManagement) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return im.UnsupportedAccess
	}
	switch cmd {
	case scenesAdd:
		return s.add(ctx, fabric, r, resp)
	case scenesCopy:
		return s.copy(ctx, fabric, r, resp)
	}
	f, ok := decodeNumFields(r)
	if !ok || !f.present(0) {
		return im.InvalidCommand
	}
	g, okG := f.u(0, 0xFFFF)
	if !okG {
		return im.ConstraintError
	}
	group := uint16(g)
	needID := cmd != scenesRemoveAll && cmd != scenesGetMembership
	var id uint8
	if needID {
		v, ok := f.u(1, 0xFF)
		if !f.present(1) || !ok {
			return im.InvalidCommand
		}
		id = uint8(v)
	}
	st := im.Success
	switch {
	case needID && id == sceneUndefined:
		st = im.ConstraintError
	case !s.inGroup(fabric, group, ctx.Endpoint):
		st = im.InvalidCommand
	}
	switch cmd {
	case scenesView:
		var sc *scene
		if st == im.Success {
			if sc = s.find(fabric, group, id); sc == nil {
				st = im.NotFound
			}
		}
		w := resp.Fields(scenesView)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		w.PutUint(tlv.ContextTag(1), uint64(group))
		w.PutUint(tlv.ContextTag(2), uint64(id))
		if sc != nil {
			w.PutUint(tlv.ContextTag(3), uint64(sc.transitionMs))
			w.PutString(tlv.ContextTag(4), sc.name)
			w.StartArray(tlv.ContextTag(5))
			for _, set := range sc.sets {
				encodeSceneSet(w, set)
			}
			w.EndContainer()
		}
		return im.Success
	case scenesRemove:
		if st == im.Success {
			if s.find(fabric, group, id) == nil {
				st = im.NotFound
			} else {
				s.scenes = filter(s.scenes, func(sc *scene) bool { return sc.fabric != fabric || sc.group != group || sc.id != id })
				s.changed(ctx)
				s.invalidate(ctx.Node, ctx.Endpoint, func(c *currentScene) bool {
					return c.fabric == fabric && c.group == group && c.id == id
				})
			}
		}
		return sceneStatusResponse(resp, scenesRemove, st, group, id)
	case scenesRemoveAll:
		if st == im.Success {
			s.RemoveGroup(ctx.Node, ctx.Endpoint, fabric, group)
		}
		w := resp.Fields(scenesRemoveAll)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		w.PutUint(tlv.ContextTag(1), uint64(group))
		return im.Success
	case scenesStore:
		if st == im.Success {
			st = s.store(ctx, fabric, group, id)
		}
		return sceneStatusResponse(resp, scenesStore, st, group, id)
	case scenesRecall:
		if st != im.Success {
			return st
		}
		sc := s.find(fabric, group, id)
		if sc == nil {
			return im.NotFound
		}
		ms := int64(sc.transitionMs)
		if f.present(2) && !f.isNull(2) {
			v, ok := f.u(2, 0xFFFFFFFF)
			if !ok {
				return im.ConstraintError
			}
			ms = int64(v)
		}
		if st := apply(ctx.Node, ctx.Endpoint, ctx.Now, sc.sets, time.Duration(ms)*time.Millisecond); st != im.Success {
			return st
		}
		s.setCurrent(ctx, fabric, group, id)
		return im.Success
	case scenesGetMembership:
		w := resp.Fields(scenesGetMembership)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		if st != im.Success {
			w.PutNull(tlv.ContextTag(1))
			w.PutUint(tlv.ContextTag(2), uint64(group))
			return im.Success
		}
		w.PutUint(tlv.ContextTag(1), uint64(s.capacity(fabric)))
		w.PutUint(tlv.ContextTag(2), uint64(group))
		w.StartArray(tlv.ContextTag(3))
		for _, sc := range s.scenes {
			if sc.fabric == fabric && sc.group == group {
				w.PutUint(tlv.Anonymous, uint64(sc.id))
			}
		}
		w.EndContainer()
		return im.Success
	}
	return im.UnsupportedCommand
}

func encodeSceneSet(w *tlv.Writer, set sceneSet) {
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(0), uint64(set.cluster))
	w.StartArray(tlv.ContextTag(1))
	for _, p := range set.pairs {
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(0), uint64(p.attr))
		if p.kind%2 == 0 { // signed kinds
			w.PutInt(tlv.ContextTag(p.kind), p.v)
		} else {
			w.PutUint(tlv.ContextTag(p.kind), uint64(p.v))
		}
		w.EndContainer()
	}
	w.EndContainer()
	w.EndContainer()
}

// decodeSceneSet reads an ExtensionFieldSetStruct.
func decodeSceneSet(r *tlv.Reader) (set sceneSet, st im.Status) {
	st = im.Success
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			var v uint64
			v, err = r.Uint()
			set.cluster = uint32(v)
		case 1:
			if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
				return im.InvalidCommand
			}
			for r.Next() == nil {
				if len(set.pairs) == sceneMaxPairs {
					st = im.Failure
					continue
				}
				var p scenePair
				values := 0
				err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
					switch {
					case tag == 0:
						var v uint64
						v, err = r.Uint()
						p.attr = uint32(v)
					case tag >= 1 && tag <= 8:
						values++
						p.kind = tag
						if tag%2 == 0 {
							p.v, err = r.Int()
						} else {
							var v uint64
							v, err = r.Uint()
							p.v = int64(v)
						}
					}
					return err
				})
				if err != nil {
					return im.InvalidCommand
				}
				if values != 1 {
					st = im.Failure
				}
				set.pairs = append(set.pairs, p)
			}
			return r.ExitContainer()
		}
		return err
	})
	if err != nil {
		return set, im.InvalidCommand
	}
	return set, st
}

func (s *ScenesManagement) add(ctx *im.Context, fabric uint8, r *tlv.Reader, resp *im.Response) im.Status {
	var (
		group      uint64
		id         uint64
		ms         uint64
		name       string
		sets       []sceneSet
		have       uint8
		setsStatus = im.Success
	)
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		if tag <= 4 {
			have |= 1 << tag
		}
		switch tag {
		case 0:
			group, err = r.Uint()
		case 1:
			id, err = r.Uint()
		case 2:
			ms, err = r.Uint()
		case 3:
			name, err = r.String()
		case 4:
			if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
				return im.InvalidCommand
			}
			for r.Next() == nil {
				set, st := decodeSceneSet(r)
				if st == im.InvalidCommand {
					return st
				}
				if len(sets) >= sceneMaxSets {
					continue // the SDK ignores the rest
				}
				if st != im.Success && setsStatus == im.Success {
					setsStatus = st
				}
				sets = append(sets, set)
			}
			return r.ExitContainer()
		}
		return err
	})
	if err != nil || have != 0x1F || group > 0xFFFF || id > 0xFF {
		return im.InvalidCommand
	}
	respond := func(st im.Status) im.Status {
		return sceneStatusResponse(resp, scenesAdd, st, uint16(group), uint8(id))
	}
	if ms > sceneMaxTransitionMs || len(name) > sceneNameMax || id == sceneUndefined {
		return respond(im.ConstraintError)
	}
	if !s.inGroup(fabric, uint16(group), ctx.Endpoint) {
		return respond(im.InvalidCommand)
	}
	if setsStatus != im.Success {
		return respond(setsStatus)
	}
	// Check each set against its cluster: sets of clusters the endpoint
	// lacks are dropped, a duplicate replaces the earlier one.
	var kept []sceneSet
	for _, set := range sets {
		c := sceneClusterOf(ctx.Node, ctx.Endpoint, set.cluster)
		if c == nil || len(set.pairs) == 0 {
			continue
		}
		for i := range set.pairs {
			p := &set.pairs[i]
			kind := c.sceneKind(p.attr)
			if kind == 0 {
				return respond(im.InvalidCommand)
			}
			if p.kind != kind {
				return respond(im.Failure)
			}
			c.sceneClamp(p)
		}
		kept = filter(kept, func(x *sceneSet) bool { return x.cluster != set.cluster })
		kept = append(kept, set)
	}
	if s.capacity(fabric) == 0 {
		return respond(im.ResourceExhausted)
	}
	sc := scene{fabric: fabric, group: uint16(group), id: uint8(id), name: name, transitionMs: uint32(ms), sets: kept}
	if old := s.find(fabric, sc.group, sc.id); old != nil {
		*old = sc
	} else {
		s.scenes = append(s.scenes, sc)
	}
	s.changed(ctx)
	return respond(im.Success)
}

func (s *ScenesManagement) copy(ctx *im.Context, fabric uint8, r *tlv.Reader, resp *im.Response) im.Status {
	f, ok := decodeNumFields(r)
	if !ok || !f.present(0, 1, 2, 3, 4) {
		return im.InvalidCommand
	}
	mode, ok0 := f.u(0, 0xFF)
	gFrom, ok1 := f.u(1, 0xFFFF)
	sFrom, ok2 := f.u(2, 0xFF)
	gTo, ok3 := f.u(3, 0xFFFF)
	sTo, ok4 := f.u(4, 0xFF)
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 {
		return im.InvalidCommand
	}
	respond := func(st im.Status) im.Status {
		w := resp.Fields(scenesCopy)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		w.PutUint(tlv.ContextTag(1), gFrom)
		w.PutUint(tlv.ContextTag(2), sFrom)
		return im.Success
	}
	switch {
	case sFrom == sceneUndefined || sTo == sceneUndefined:
		return respond(im.ConstraintError)
	case !s.inGroup(fabric, uint16(gFrom), ctx.Endpoint) || !s.inGroup(fabric, uint16(gTo), ctx.Endpoint):
		return respond(im.InvalidCommand)
	case s.capacity(fabric) == 0: // like the SDK, even to replace a scene
		return respond(im.ResourceExhausted)
	}
	copyOne := func(src *scene, toID uint8) im.Status {
		dst := *src
		dst.group, dst.id = uint16(gTo), toID
		dst.sets = append([]sceneSet(nil), src.sets...)
		if old := s.find(fabric, dst.group, dst.id); old != nil {
			*old = dst
			return im.Success
		}
		if s.capacity(fabric) == 0 {
			return im.ResourceExhausted
		}
		s.scenes = append(s.scenes, dst)
		return im.Success
	}
	st := im.Success
	if mode&scenesCopyAll != 0 {
		var srcs []scene
		for _, sc := range s.scenes {
			if sc.fabric == fabric && sc.group == uint16(gFrom) {
				srcs = append(srcs, sc)
			}
		}
		for i := range srcs {
			if st = copyOne(&srcs[i], srcs[i].id); st != im.Success {
				break
			}
		}
	} else {
		src := s.find(fabric, uint16(gFrom), uint8(sFrom))
		if src == nil {
			return respond(im.NotFound)
		}
		st = copyOne(src, uint8(sTo))
	}
	s.changed(ctx)
	return respond(st)
}

// EncodeState saves the scene table (im.Persister):
//
//	[ { 0: fabric, 1: group, 2: scene, 3: name, 4: transition ms,
//	    5: [ { 0: cluster, 1: [ { 0: attribute, kind: value } ] } ] } ]
func (s *ScenesManagement) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.StartArray(tag)
	for _, sc := range s.scenes {
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(0), uint64(sc.fabric))
		w.PutUint(tlv.ContextTag(1), uint64(sc.group))
		w.PutUint(tlv.ContextTag(2), uint64(sc.id))
		if sc.name != "" {
			w.PutString(tlv.ContextTag(3), sc.name)
		}
		w.PutUint(tlv.ContextTag(4), uint64(sc.transitionMs))
		w.StartArray(tlv.ContextTag(5))
		for _, set := range sc.sets {
			encodeSceneSet(w, set)
		}
		w.EndContainer()
		w.EndContainer()
	}
	w.EndContainer()
}

// DecodeState restores the scene table (im.Persister).
func (s *ScenesManagement) DecodeState(r *tlv.Reader) error {
	s.scenes = nil
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return errGroupState
	}
	for r.Next() == nil {
		var sc scene
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 0:
				sc.fabric, err = r.Uint8()
			case 1:
				sc.group, err = r.Uint16()
			case 2:
				sc.id, err = r.Uint8()
			case 3:
				sc.name, err = r.String()
			case 4:
				sc.transitionMs, err = r.Uint32()
			case 5:
				return eachItem(r, func() error {
					set, st := decodeSceneSet(r)
					if st != im.Success {
						return errGroupState
					}
					sc.sets = append(sc.sets, set)
					return nil
				})
			}
			return err
		})
		if err != nil {
			return err
		}
		if len(s.scenes) < sceneTableSize {
			s.scenes = append(s.scenes, sc)
		}
	}
	return r.ExitContainer()
}
