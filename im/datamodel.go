package im

import (
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Global attribute IDs (spec 7.13).
const (
	AttrGeneratedCommandList = 0xFFF8
	AttrAcceptedCommandList  = 0xFFF9
	AttrAttributeList        = 0xFFFB
	AttrFeatureMap           = 0xFFFC
	AttrClusterRevision      = 0xFFFD
)

var globalAttributes = [...]uint32{
	AttrGeneratedCommandList, AttrAcceptedCommandList, AttrAttributeList, AttrFeatureMap, AttrClusterRevision,
}

func isGlobalAttribute(id uint32) bool {
	for _, g := range globalAttributes {
		if g == id {
			return true
		}
	}
	return false
}

// Context describes the interaction a cluster callback runs in.
type Context struct {
	Now      time.Time
	Node     *Node
	Session  *exchange.Session
	Endpoint uint16
	// FabricFiltered is set for fabric-filtered reads.
	FabricFiltered bool
	// Timed is set for writes and invokes inside a timed interaction.
	Timed bool
}

// Cluster is a server cluster instance on an endpoint. Implementations
// usually embed ClusterBase. The global attributes (revision, feature map,
// attribute and command lists) are served by the framework from the
// metadata methods.
type Cluster interface {
	ID() uint32
	Revision() uint16
	FeatureMap() uint32
	// Attributes returns the IDs of the cluster-specific attributes the
	// instance supports, in ascending order.
	Attributes() []uint32
	AcceptedCommands() []uint32
	GeneratedCommands() []uint32

	// ReadAttribute writes the value of attr with the given tag.
	ReadAttribute(ctx *Context, attr uint32, w *tlv.Writer, tag tlv.Tag) Status
	// WriteAttribute sets attr from the element r is positioned on. When
	// appendItem is set, the element is one item to append to a list.
	WriteAttribute(ctx *Context, attr uint32, appendItem bool, r *tlv.Reader) Status
	// Invoke runs cmd with the fields structure r is positioned on. A
	// command with a response writes it with resp.Fields.
	Invoke(ctx *Context, cmd uint32, r *tlv.Reader, resp *Response) Status
}

// ClusterBase provides defaults for the optional parts of Cluster.
type ClusterBase struct{}

func (ClusterBase) FeatureMap() uint32          { return 0 }
func (ClusterBase) AcceptedCommands() []uint32  { return nil }
func (ClusterBase) GeneratedCommands() []uint32 { return nil }
func (ClusterBase) WriteAttribute(*Context, uint32, bool, *tlv.Reader) Status {
	return UnsupportedWrite
}
func (ClusterBase) Invoke(*Context, uint32, *tlv.Reader, *Response) Status {
	return UnsupportedCommand
}

// DeviceType is a device type an endpoint implements.
type DeviceType struct {
	ID       uint32
	Revision uint16
}

// Endpoint is one endpoint of a node.
type Endpoint struct {
	ID          uint16
	DeviceTypes []DeviceType
	clusters    []clusterEntry
}

type clusterEntry struct {
	c       Cluster
	version uint32
}

// Node is the data model of a device: its endpoints and their clusters,
// and the events they generated.
type Node struct {
	endpoints []*Endpoint
	version   uint32 // next initial data version
	// OnChange, if set, is called after an attribute changes.
	OnChange func(p ConcretePath)
	// Events records the node's events; NewNode creates one with the
	// default buffer sizes, which may be replaced before use.
	Events *EventLog
	// OnEvent, if set, is called after an event is recorded.
	OnEvent func(p ConcreteEventPath)
	// OnAddCluster, if set, is called for each cluster added, so stored
	// state can be restored into it (see Persister).
	OnAddCluster func(endpoint uint16, c Cluster)
}

// Persister is implemented by clusters with state that survives restarts
// (nonvolatile attributes, scene tables). A device saves the state soon
// after the cluster reports an attribute change with Node.Changed, and
// restores it when the cluster is added at start.
type Persister interface {
	// EncodeState writes the state as one element with the given tag.
	EncodeState(w *tlv.Writer, tag tlv.Tag)
	// DecodeState restores what EncodeState wrote; r is positioned on the
	// element. It runs once, before the node starts, so it is where
	// start-up behaviour (such as StartUpOnOff) applies.
	DecodeState(r *tlv.Reader) error
}

// NewNode returns an empty node. seed randomizes initial data versions.
func NewNode(seed uint32) *Node {
	return &Node{version: seed, Events: NewEventLog(DefaultDebugBuffer, DefaultInfoBuffer, DefaultCriticalBuffer)}
}

// AddEndpoint adds an endpoint. Endpoints should be added in ascending order.
func (n *Node) AddEndpoint(id uint16, types ...DeviceType) *Endpoint {
	e := &Endpoint{ID: id, DeviceTypes: types}
	n.endpoints = append(n.endpoints, e)
	return e
}

// AddCluster adds clusters to endpoint e.
func (n *Node) AddCluster(e *Endpoint, cs ...Cluster) {
	for _, c := range cs {
		n.version++
		e.clusters = append(e.clusters, clusterEntry{c: c, version: n.version * 0x9E3779B1})
		if n.OnAddCluster != nil {
			n.OnAddCluster(e.ID, c)
		}
	}
}

// Endpoints returns the node's endpoints.
func (n *Node) Endpoints() []*Endpoint { return n.endpoints }

// Endpoint returns the endpoint with the given ID, or nil.
func (n *Node) Endpoint(id uint16) *Endpoint {
	for _, e := range n.endpoints {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Cluster returns the cluster with the given ID on e, or nil.
func (e *Endpoint) Cluster(id uint32) Cluster {
	if c := e.entry(id); c != nil {
		return c.c
	}
	return nil
}

// ClusterIDs appends the IDs of the clusters on e to dst.
func (e *Endpoint) ClusterIDs(dst []uint32) []uint32 {
	for _, c := range e.clusters {
		dst = append(dst, c.c.ID())
	}
	return dst
}

func (e *Endpoint) entry(id uint32) *clusterEntry {
	for i := range e.clusters {
		if e.clusters[i].c.ID() == id {
			return &e.clusters[i]
		}
	}
	return nil
}

// Changed records that an attribute changed: it bumps the cluster's data
// version and notifies OnChange.
func (n *Node) Changed(endpoint uint16, cluster, attr uint32) {
	e := n.Endpoint(endpoint)
	if e == nil {
		return
	}
	if c := e.entry(cluster); c != nil {
		c.version++
	}
	if n.OnChange != nil {
		n.OnChange(ConcretePath{endpoint, cluster, attr})
	}
}

// Poller is implemented by clusters with timers; Node.Poll runs them.
type Poller interface {
	// Poll runs the instance on endpoint of n and returns when it next
	// needs to run (zero if idle).
	Poll(n *Node, endpoint uint16, now time.Time) time.Time
}

// Poll runs the timers of the clusters that implement Poller and returns
// when it next needs to run (zero if idle).
func (n *Node) Poll(now time.Time) time.Time {
	var next time.Time
	for _, e := range n.endpoints {
		for i := range e.clusters {
			if p, ok := e.clusters[i].c.(Poller); ok {
				if t := p.Poll(n, e.ID, now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
					next = t
				}
			}
		}
	}
	return next
}

// DataVersion returns the data version of a cluster instance.
func (n *Node) DataVersion(endpoint uint16, cluster uint32) (uint32, bool) {
	if e := n.Endpoint(endpoint); e != nil {
		if c := e.entry(cluster); c != nil {
			return c.version, true
		}
	}
	return 0, false
}

func hasID(ids []uint32, id uint32) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// hasAttribute reports whether c supports attr, including globals.
func hasAttribute(c Cluster, attr uint32) bool {
	return isGlobalAttribute(attr) || hasID(c.Attributes(), attr)
}

// readAttribute reads attr of c, serving the global attributes.
func readAttribute(ctx *Context, c Cluster, attr uint32, w *tlv.Writer, tag tlv.Tag) Status {
	switch attr {
	case AttrClusterRevision:
		w.PutUint(tag, uint64(c.Revision()))
	case AttrFeatureMap:
		w.PutUint(tag, uint64(c.FeatureMap()))
	case AttrAttributeList:
		w.StartArray(tag)
		for _, a := range c.Attributes() {
			w.PutUint(tlv.Anonymous, uint64(a))
		}
		for _, a := range globalAttributes {
			w.PutUint(tlv.Anonymous, uint64(a))
		}
		w.EndContainer()
	case AttrAcceptedCommandList:
		putIDs(w, tag, c.AcceptedCommands())
	case AttrGeneratedCommandList:
		putIDs(w, tag, c.GeneratedCommands())
	default:
		return c.ReadAttribute(ctx, attr, w, tag)
	}
	return Success
}

func putIDs(w *tlv.Writer, tag tlv.Tag, ids []uint32) {
	w.StartArray(tag)
	for _, id := range ids {
		w.PutUint(tlv.Anonymous, uint64(id))
	}
	w.EndContainer()
}

// attributeIDs appends all attribute IDs of c, in report order.
func attributeIDs(dst []uint32, c Cluster) []uint32 {
	dst = append(dst, c.Attributes()...)
	return append(dst, globalAttributes[:]...)
}
