package controller

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Group is a group of the controller's fabric (spec 2.11): nodes add
// their endpoints to it, and commands sent to it reach them all at once.
type Group struct {
	ID       uint16 `json:"id"`
	Name     string `json:"name,omitempty"`
	KeySetID uint16 `json:"keySetId"`
}

// GroupKeySet is a group key set: the epoch key the operational group
// key of the groups mapped to it is derived from.
type GroupKeySet struct {
	ID        uint16 `json:"id"`
	EpochKey  []byte `json:"epochKey"`
	StartTime uint64 `json:"startTime"` // microseconds since the Matter epoch
}

// Cluster and attribute IDs the group setup uses.
const (
	idGroups             = 0x0004
	idAccessControl      = 0x001F
	idGroupKeyManagement = 0x003F
	authModeGroup        = 3
	privilegeOperate     = 3
	groupKeyTrustFirst   = 0
)

var (
	// ErrUnknownGroup is returned for a group the controller has not
	// created.
	ErrUnknownGroup = errors.New("controller: unknown group")
	errGroupID      = errors.New("controller: group IDs are 1 to 0xFEFF")
)

// Groups returns the fabric's groups.
func (c *Controller) Groups() []Group {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Group(nil), c.st.Groups...)
}

func (st *state) group(id uint16) *Group {
	for i := range st.Groups {
		if st.Groups[i].ID == id {
			return &st.Groups[i]
		}
	}
	return nil
}

func (st *state) keySet(id uint16) *GroupKeySet {
	for i := range st.KeySets {
		if st.KeySets[i].ID == id {
			return &st.KeySets[i]
		}
	}
	return nil
}

// AddGroup creates a group with a key set of its own (with the group's
// ID), or renames it if it exists.
func (c *Controller) AddGroup(id uint16, name string) (Group, error) {
	if id == 0 || id >= 0xFF00 {
		return Group{}, errGroupID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if g := c.st.group(id); g != nil {
		g.Name = name
		return *g, c.st.save(c.opts.Dir)
	}
	if c.st.keySet(id) == nil {
		key := make([]byte, message.KeySize)
		if _, err := rand.Read(key); err != nil {
			return Group{}, err
		}
		start := uint64(time.Now().Unix()-credentials.MatterEpoch) * 1e6
		c.st.KeySets = append(c.st.KeySets, GroupKeySet{ID: id, EpochKey: key, StartTime: start})
	}
	g := Group{ID: id, Name: name, KeySetID: id}
	c.st.Groups = append(c.st.Groups, g)
	return g, c.st.save(c.opts.Dir)
}

// DeleteGroup forgets a group and its key set. Nodes keep it until each
// is removed from it.
func (c *Controller) DeleteGroup(id uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.st.group(id)
	if g == nil {
		return ErrUnknownGroup
	}
	ks := g.KeySetID
	c.st.Groups = deleteFunc(c.st.Groups, func(x Group) bool { return x.ID == id })
	shared := false
	for _, x := range c.st.Groups {
		shared = shared || x.KeySetID == ks
	}
	if !shared {
		c.st.KeySets = deleteFunc(c.st.KeySets, func(x GroupKeySet) bool { return x.ID == ks })
	}
	return c.st.save(c.opts.Dir)
}

func deleteFunc[T any](s []T, del func(T) bool) []T {
	out := s[:0]
	for _, x := range s {
		if !del(x) {
			out = append(out, x)
		}
	}
	return out
}

// JoinGroup makes an endpoint of a node a member of a group: it gives the
// node the group's key set and maps the group to it (Group Key
// Management), lets the group operate the node (an Access Control entry),
// and adds the endpoint to the group (Groups).
func (c *Controller) JoinGroup(ctx context.Context, node uint64, endpoint uint16, group uint16) error {
	c.mu.Lock()
	g := c.st.group(group)
	var (
		gi Group
		ks GroupKeySet
	)
	if g != nil {
		gi = *g
		if k := c.st.keySet(g.KeySetID); k != nil {
			ks = *k
		}
	}
	c.mu.Unlock()
	if g == nil {
		return ErrUnknownGroup
	}
	if ks.EpochKey == nil {
		return fmt.Errorf("controller: group %#x has no key set", group)
	}
	return c.withSession(ctx, node, func(s *exchange.Session) error {
		// The key set.
		_, err := c.invokeOn(ctx, s, im.CommandPath{Endpoint: 0, Cluster: idGroupKeyManagement, Command: 0}, 0, func(w *tlv.Writer) {
			w.StartStruct(tlv.ContextTag(0))
			w.PutUint(tlv.ContextTag(0), uint64(ks.ID))
			w.PutUint(tlv.ContextTag(1), groupKeyTrustFirst)
			w.PutBytes(tlv.ContextTag(2), ks.EpochKey)
			w.PutUint(tlv.ContextTag(3), ks.StartTime)
			for tag := uint8(4); tag <= 7; tag++ {
				w.PutNull(tlv.ContextTag(tag))
			}
			w.EndContainer()
		})
		if err != nil {
			return fmt.Errorf("KeySetWrite: %w", err)
		}

		// The group key map: replaced whole, with the group mapped to its
		// key set.
		items, err := c.readList(ctx, s, 0, idGroupKeyManagement, 0)
		if err != nil {
			return fmt.Errorf("reading the group key map: %w", err)
		}
		type mapping struct{ group, keySet uint16 }
		var maps []mapping
		mapped := false
		for _, it := range items {
			var m mapping
			im.ForEachField(tlv.NewReader(it), func(r *tlv.Reader, tag uint8) (err error) {
				switch tag {
				case 1:
					m.group, err = r.Uint16()
				case 2:
					m.keySet, err = r.Uint16()
				}
				return err
			})
			if m.group == group {
				mapped = m.keySet == ks.ID
				m.keySet = ks.ID
			}
			maps = append(maps, m)
		}
		if !mapped {
			if !containsFunc(maps, func(m mapping) bool { return m.group == group }) {
				maps = append(maps, mapping{group, ks.ID})
			}
			err = c.writeOn(ctx, s, im.AttributePath{Endpoint: 0, Cluster: idGroupKeyManagement, Attribute: 0}, 0,
				func(w *tlv.Writer, tag tlv.Tag) {
					w.StartArray(tag)
					for _, m := range maps {
						w.StartStruct(tlv.Anonymous)
						w.PutUint(tlv.ContextTag(1), uint64(m.group))
						w.PutUint(tlv.ContextTag(2), uint64(m.keySet))
						w.EndContainer()
					}
					w.EndContainer()
				})
			if err != nil {
				return fmt.Errorf("writing the group key map: %w", err)
			}
		}

		// Access: an entry letting the group operate the node.
		items, err = c.readList(ctx, s, 0, idAccessControl, 0)
		if err != nil {
			return fmt.Errorf("reading the ACL: %w", err)
		}
		allowed := false
		for _, it := range items {
			allowed = allowed || groupEntryAllows(it, group)
		}
		if !allowed {
			err = c.writeOn(ctx, s, im.AttributePath{Endpoint: 0, Cluster: idAccessControl, Attribute: 0, ListAppend: true}, 0,
				func(w *tlv.Writer, tag tlv.Tag) {
					w.StartStruct(tag)
					w.PutUint(tlv.ContextTag(1), privilegeOperate)
					w.PutUint(tlv.ContextTag(2), authModeGroup)
					w.StartArray(tlv.ContextTag(3))
					w.PutUint(tlv.Anonymous, uint64(group))
					w.EndContainer()
					w.PutNull(tlv.ContextTag(4))
					w.EndContainer()
				})
			if err != nil {
				return fmt.Errorf("adding an ACL entry: %w", err)
			}
		}

		// The membership.
		res, err := c.invokeOn(ctx, s, im.CommandPath{Endpoint: endpoint, Cluster: idGroups, Command: 0}, 0, func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), uint64(group))
			w.PutString(tlv.ContextTag(1), gi.Name)
		})
		if err != nil {
			return fmt.Errorf("AddGroup: %w", err)
		}
		return groupsStatus(res, "AddGroup")
	})
}

// LeaveGroup removes an endpoint of a node from a group.
func (c *Controller) LeaveGroup(ctx context.Context, node uint64, endpoint uint16, group uint16) error {
	return c.withSession(ctx, node, func(s *exchange.Session) error {
		res, err := c.invokeOn(ctx, s, im.CommandPath{Endpoint: endpoint, Cluster: idGroups, Command: 3}, 0, func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), uint64(group))
		})
		if err != nil {
			return fmt.Errorf("RemoveGroup: %w", err)
		}
		return groupsStatus(res, "RemoveGroup")
	})
}

// groupsStatus returns the error of a Groups command's status field.
func groupsStatus(res im.InvokeResult, cmd string) error {
	var st uint64
	im.ForEachField(tlv.NewReader(res.Fields), func(r *tlv.Reader, tag uint8) (err error) {
		if tag == 0 {
			st, err = r.Uint()
		}
		return err
	})
	if st != 0 {
		return fmt.Errorf("%s: %w", cmd, &CommandError{Status: im.Status(st)})
	}
	return nil
}

func containsFunc[T any](s []T, f func(T) bool) bool {
	for _, x := range s {
		if f(x) {
			return true
		}
	}
	return false
}

// groupEntryAllows reports whether an ACL entry grants a group at least
// Operate on every target.
func groupEntryAllows(entry []byte, group uint16) bool {
	var (
		priv, mode uint64
		subject    bool
		anyTarget  bool
	)
	im.ForEachField(tlv.NewReader(entry), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			priv, err = r.Uint()
		case 2:
			mode, err = r.Uint()
		case 3:
			if r.IsNull() || r.EnterContainer() != nil {
				return nil
			}
			for r.Next() == nil {
				if v, err := r.Uint(); err == nil && v == uint64(group) {
					subject = true
				}
			}
			return r.ExitContainer()
		case 4:
			anyTarget = r.IsNull()
		}
		return err
	})
	return mode == authModeGroup && priv >= privilegeOperate && subject && anyTarget
}

// readList reads a list attribute (of the accessing fabric) and returns
// its items as raw TLV, whether reported whole or in chunks.
func (c *Controller) readList(ctx context.Context, s *exchange.Session, ep uint16, cluster, attr uint32) ([][]byte, error) {
	rep, err := c.readOn(ctx, s, im.Request{FabricFiltered: true,
		Attributes: []im.AttributePath{{Endpoint: ep, Cluster: cluster, Attribute: attr}}})
	if err != nil {
		return nil, err
	}
	var items [][]byte
	for _, a := range rep.Attributes {
		if a.Status != im.Success {
			return nil, a.Status
		}
		if a.Path.ListAppend {
			items = append(items, a.Data)
			continue
		}
		items = items[:0]
		r := tlv.NewReader(a.Data)
		if r.Next() != nil || r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
			return nil, errors.New("controller: list attribute is not a list")
		}
		for r.Next() == nil {
			it, err := r.RawElement()
			if err != nil {
				return nil, err
			}
			items = append(items, it)
		}
	}
	return items, nil
}

// GroupInvoke sends a command to a group: to every member endpoint of
// every node in it, over IPv6 multicast on each interface. Nothing
// answers, so success means only that it was sent.
func (c *Controller) GroupInvoke(ctx context.Context, group uint16, cluster, command uint32, fields func(w *tlv.Writer)) error {
	c.mu.Lock()
	var ks GroupKeySet
	g := c.st.group(group)
	if g != nil {
		if k := c.st.keySet(g.KeySetID); k != nil {
			ks = *k
		}
	}
	c.mu.Unlock()
	if g == nil {
		return ErrUnknownGroup
	}
	keys, err := message.DeriveGroupKeys(ks.EpochKey, c.fab.CompressedFabricID)
	if err != nil {
		return err
	}
	cipher, err := message.NewCipher(keys.Encryption[:])
	if err != nil {
		return err
	}
	k := &exchange.GroupKey{GroupID: group, SessionID: keys.SessionID, Cipher: cipher, PrivacyKey: keys.Privacy}
	source, counter, err := c.nextGroupCounter()
	if err != nil {
		return err
	}
	to := netip.AddrPortFrom(exchange.GroupMulticastAddr(c.fab.FabricID, group), matterPort)
	payload := im.EncodeGroupInvokeRequest(cluster, command, fields)
	var sendErr error
	if err := c.do(func(time.Time) {
		sendErr = c.m.SendGroup(to, k, source, counter, message.ProtocolInteractionModel, im.OpInvokeRequest, payload)
	}); err != nil {
		return err
	}
	return sendErr
}

// matterPort is the UDP port of Matter nodes, group messages' destination.
const matterPort = 5540

// nextGroupCounter returns the node ID group messages are sent from and
// the next value of the group data message counter (spec 4.6.1.2), saved
// before use: nodes trust the first counter they see from a sender and
// drop older ones after it, so it must never repeat.
//
// The node ID is fixed for the fabric's state, unlike a controller's CASE
// node ID, as receivers keep counters for only a few senders. The counter
// is reread from disk, so controllers sharing a state directory one after
// another continue it.
func (c *Controller) nextGroupCounter() (uint64, uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, err := os.ReadFile(filepath.Join(c.opts.Dir, stateFile)); err == nil {
		var disk struct {
			GroupNodeID  uint64 `json:"groupNodeId"`
			GroupCounter uint32 `json:"groupCounter"`
		}
		if json.Unmarshal(b, &disk) == nil && disk.GroupNodeID == c.st.GroupNodeID && disk.GroupCounter > c.st.GroupCounter {
			c.st.GroupCounter = disk.GroupCounter
		}
	}
	if c.st.GroupNodeID == 0 {
		c.st.GroupNodeID = controllerNodeID()
		c.st.GroupCounter = uint32(randUint64()%(1<<28)) + 1
	}
	c.st.GroupCounter++
	return c.st.GroupNodeID, c.st.GroupCounter, c.st.save(c.opts.Dir)
}
