package controller

import (
	"context"
	"fmt"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const (
	idBinding    = 0x001E
	authModeCASE = 2
)

// Binding is a Binding cluster entry: a node's endpoint, or a group
// (Group nonzero), optionally for one cluster only.
type Binding struct {
	Node       uint64
	Group      uint16
	Endpoint   uint16
	Cluster    uint32
	HasCluster bool
}

// Bind makes an endpoint of node send the commands of cluster to an
// endpoint of target, directly (a binding): it lets node operate cluster
// on that endpoint of target (an ACL entry, if none allows it yet), then
// adds the target to node's Binding list.
func (c *Controller) Bind(ctx context.Context, node uint64, endpoint uint16, target uint64, targetEndpoint uint16, cluster uint32) error {
	err := c.withSession(ctx, target, func(s *exchange.Session) error {
		items, err := c.readList(ctx, s, 0, idAccessControl, 0)
		if err != nil {
			return fmt.Errorf("reading the target's ACL: %w", err)
		}
		for _, it := range items {
			if caseEntryAllows(it, node, targetEndpoint, cluster) {
				return nil
			}
		}
		err = c.writeOn(ctx, s, im.AttributePath{Endpoint: 0, Cluster: idAccessControl, Attribute: 0, ListAppend: true}, 0,
			func(w *tlv.Writer, tag tlv.Tag) {
				w.StartStruct(tag)
				w.PutUint(tlv.ContextTag(1), privilegeOperate)
				w.PutUint(tlv.ContextTag(2), authModeCASE)
				w.StartArray(tlv.ContextTag(3))
				w.PutUint(tlv.Anonymous, node)
				w.EndContainer()
				w.StartArray(tlv.ContextTag(4))
				w.StartStruct(tlv.Anonymous)
				w.PutUint(tlv.ContextTag(0), uint64(cluster))
				w.PutUint(tlv.ContextTag(1), uint64(targetEndpoint))
				w.EndContainer()
				w.EndContainer()
				w.EndContainer()
			})
		if err != nil {
			return fmt.Errorf("adding an ACL entry on the target: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return c.editBindings(ctx, node, endpoint, func(bs []Binding) []Binding {
		for _, b := range bs {
			if b.Group == 0 && b.Node == target && b.Endpoint == targetEndpoint && (!b.HasCluster || b.Cluster == cluster) {
				return bs
			}
		}
		return append(bs, Binding{Node: target, Endpoint: targetEndpoint, Cluster: cluster, HasCluster: true})
	})
}

// BindGroup makes an endpoint of node send the commands of cluster to a
// group of the controller's fabric (as group messages): it gives node the
// group's key (without making it a member), then adds the group to node's
// Binding list. Members are added with JoinGroup.
func (c *Controller) BindGroup(ctx context.Context, node uint64, endpoint uint16, group uint16, cluster uint32) error {
	_, ks, err := c.groupKeySet(group)
	if err != nil {
		return err
	}
	err = c.withSession(ctx, node, func(s *exchange.Session) error {
		return c.giveGroupKey(ctx, s, group, ks)
	})
	if err != nil {
		return err
	}
	return c.editBindings(ctx, node, endpoint, func(bs []Binding) []Binding {
		for _, b := range bs {
			if b.Group == group && (!b.HasCluster || b.Cluster == cluster) {
				return bs
			}
		}
		return append(bs, Binding{Group: group, Cluster: cluster, HasCluster: true})
	})
}

// UnbindGroup removes node's bindings to a group (for cluster only,
// unless cluster is zero). The node keeps the group's key.
func (c *Controller) UnbindGroup(ctx context.Context, node uint64, endpoint uint16, group uint16, cluster uint32) error {
	return c.editBindings(ctx, node, endpoint, func(bs []Binding) []Binding {
		var keep []Binding
		for _, b := range bs {
			if b.Group == group && (cluster == 0 || b.Cluster == cluster) {
				continue
			}
			keep = append(keep, b)
		}
		return keep
	})
}

// Unbind removes node's bindings to an endpoint of target (for cluster
// only, unless cluster is zero). The target's ACL entry stays.
func (c *Controller) Unbind(ctx context.Context, node uint64, endpoint uint16, target uint64, targetEndpoint uint16, cluster uint32) error {
	return c.editBindings(ctx, node, endpoint, func(bs []Binding) []Binding {
		var keep []Binding
		for _, b := range bs {
			if b.Group == 0 && b.Node == target && b.Endpoint == targetEndpoint && (cluster == 0 || b.Cluster == cluster) {
				continue
			}
			keep = append(keep, b)
		}
		return keep
	})
}

// Bindings returns an endpoint's Binding list on the controller's fabric.
func (c *Controller) Bindings(ctx context.Context, node uint64, endpoint uint16) ([]Binding, error) {
	var bs []Binding
	err := c.withSession(ctx, node, func(s *exchange.Session) error {
		var err error
		bs, err = c.readBindings(ctx, s, endpoint)
		return err
	})
	return bs, err
}

func (c *Controller) readBindings(ctx context.Context, s *exchange.Session, endpoint uint16) ([]Binding, error) {
	items, err := c.readList(ctx, s, endpoint, idBinding, 0)
	if err != nil {
		return nil, fmt.Errorf("reading the Binding list: %w", err)
	}
	bs := make([]Binding, 0, len(items))
	for _, it := range items {
		bs = append(bs, parseBinding(it))
	}
	return bs, nil
}

// parseBinding decodes a Binding list entry.
func parseBinding(item []byte) (b Binding) {
	im.ForEachField(tlv.NewReader(item), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			b.Node, err = r.Uint()
		case 2:
			b.Group, err = r.Uint16()
		case 3:
			b.Endpoint, err = r.Uint16()
		case 4:
			b.Cluster, err = r.Uint32()
			b.HasCluster = true
		}
		return err
	})
	return b
}

// editBindings rewrites an endpoint's Binding list on the controller's
// fabric with what edit makes of it.
func (c *Controller) editBindings(ctx context.Context, node uint64, endpoint uint16, edit func([]Binding) []Binding) error {
	return c.withSession(ctx, node, func(s *exchange.Session) error {
		bs, err := c.readBindings(ctx, s, endpoint)
		if err != nil {
			return err
		}
		bs = edit(bs)
		err = c.writeOn(ctx, s, im.AttributePath{Endpoint: endpoint, Cluster: idBinding, Attribute: 0}, 0,
			func(w *tlv.Writer, tag tlv.Tag) {
				w.StartArray(tag)
				for _, b := range bs {
					w.StartStruct(tlv.Anonymous)
					if b.Group != 0 {
						w.PutUint(tlv.ContextTag(2), uint64(b.Group))
					} else {
						w.PutUint(tlv.ContextTag(1), b.Node)
						w.PutUint(tlv.ContextTag(3), uint64(b.Endpoint))
					}
					if b.HasCluster {
						w.PutUint(tlv.ContextTag(4), uint64(b.Cluster))
					}
					w.EndContainer()
				}
				w.EndContainer()
			})
		if err != nil {
			return fmt.Errorf("writing the Binding list: %w", err)
		}
		return nil
	})
}

// caseEntryAllows reports whether an ACL entry lets node (over CASE)
// operate cluster on endpoint.
func caseEntryAllows(entry []byte, node uint64, endpoint uint16, cluster uint32) bool {
	var (
		priv, mode uint64
		subject    bool
		target     bool
	)
	im.ForEachField(tlv.NewReader(entry), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			priv, err = r.Uint()
		case 2:
			mode, err = r.Uint()
		case 3:
			if r.IsNull() {
				subject = true // any node of the fabric
				return nil
			}
			if r.EnterContainer() != nil {
				return nil
			}
			for r.Next() == nil {
				if v, err := r.Uint(); err == nil && v == node {
					subject = true
				}
			}
			return r.ExitContainer()
		case 4:
			if r.IsNull() {
				target = true
				return nil
			}
			if r.EnterContainer() != nil {
				return nil
			}
			for r.Next() == nil {
				var (
					cl, ep       uint64
					hasCl, hasEP bool
					hasDT        bool
				)
				im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
					switch tag {
					case 0:
						if !r.IsNull() {
							cl, err = r.Uint()
							hasCl = true
						}
					case 1:
						if !r.IsNull() {
							ep, err = r.Uint()
							hasEP = true
						}
					case 2:
						hasDT = !r.IsNull()
					}
					return err
				})
				if !hasDT && (!hasCl || cl == uint64(cluster)) && (!hasEP || ep == uint64(endpoint)) {
					target = true
				}
			}
			return r.ExitContainer()
		}
		return err
	})
	return mode == authModeCASE && priv >= privilegeOperate && subject && target
}
