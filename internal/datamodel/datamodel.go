// Package datamodel describes Matter clusters for controllers and tools:
// the names and types of their attributes, commands and events. It is
// parsed from the Matter SDK's IDL of the clusters a controller knows
// (controller-clusters.matter, from github.com/project-chip/connectedhomeip,
// Apache-2.0, Copyright Project CHIP Authors). It formats TLV values with
// those names and encodes values written by people.
//
// The model is large; it is meant for host tools, not firmware.
package datamodel

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed controller-clusters.matter
var idl string

// Kind is the TLV shape of a type.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindBool
	KindUint
	KindInt
	KindFloat  // single precision
	KindDouble // double precision
	KindString
	KindBytes
	KindEnum
	KindBitmap
	KindStruct
)

// Type is a data type: a primitive (named as in the IDL, such as int16u
// or vendor_id), or an enum, bitmap or struct a cluster defines.
type Type struct {
	Name string
	Kind Kind
	// Items are the values of an enum, or the bits of a bitmap.
	Items []Item
	// Fields are the fields of a struct, in ID order.
	Fields       []*Field
	FabricScoped bool
	// Base is the primitive an enum or bitmap is encoded as (enum8...).
	Base string
}

// Item is an enum value or a bitmap bit (Value is then the bit's mask).
type Item struct {
	Name  string // without the IDL's "k" prefix
	Value uint64
}

// Field is a struct, command or event field, or an attribute's value.
type Field struct {
	ID       uint32
	Name     string
	Type     *Type
	List     bool
	Optional bool
	Nullable bool

	typeName string
}

// Attribute is a cluster attribute.
type Attribute struct {
	Field
	Writable bool
	Doc      string
}

// Command is a cluster command.
type Command struct {
	ID   uint32
	Name string
	// Request holds the fields (nil: none). Response is the response
	// command's fields (nil: a plain status).
	Request, Response *Type
	ResponseID        uint32
	Timed             bool // requires a timed invoke
	FabricScoped      bool
	Doc               string

	request, response string
}

// Event is a cluster event.
type Event struct {
	ID       uint32
	Name     string
	Priority string // critical, info or debug
	Fields   []*Field
	Doc      string
}

// Cluster is a cluster definition.
type Cluster struct {
	ID         uint32
	Name       string
	Revision   int
	Doc        string
	Attributes []*Attribute
	Commands   []*Command
	Events     []*Event

	types map[string]*Type
}

// Model is a set of cluster definitions.
type Model struct {
	Clusters []*Cluster
	types    map[string]*Type // top-level types
	prims    map[string]*Type // primitive types in use
	byID     map[uint32]*Cluster
}

var (
	once  sync.Once
	model *Model
)

// Default returns the model of the clusters in the embedded SDK IDL. It
// panics if the IDL does not parse, which tests rule out.
func Default() *Model {
	once.Do(func() {
		m, err := Parse(idl)
		if err != nil {
			panic("datamodel: " + err.Error())
		}
		model = m
	})
	return model
}

// key normalizes a name for lookups: case and punctuation do not matter.
func key(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b = append(b, c+'a'-'A')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b = append(b, c)
		}
	}
	return string(b)
}

// number parses a decimal or 0x-prefixed ID.
func number(s string) (uint64, bool) {
	n, err := parseUint(s)
	return n, err == nil
}

// find looks up a named, numbered item: by number, by name (case and
// punctuation aside), or by a prefix of one name only.
func find[T any](items []T, s string, name func(T) string, id func(T) uint32) (T, bool) {
	var zero T
	if n, ok := number(s); ok {
		for _, it := range items {
			if id(it) == uint32(n) {
				return it, true
			}
		}
		return zero, false
	}
	k := key(s)
	if k == "" {
		return zero, false
	}
	var prefixed []T
	for _, it := range items {
		nk := key(name(it))
		if nk == k {
			return it, true
		}
		if strings.HasPrefix(nk, k) {
			prefixed = append(prefixed, it)
		}
	}
	if len(prefixed) == 1 {
		return prefixed[0], true
	}
	return zero, false
}

// Cluster finds a cluster by name, unique name prefix, or ID.
func (m *Model) Cluster(s string) *Cluster {
	c, _ := find(m.Clusters, s, func(c *Cluster) string { return c.Name }, func(c *Cluster) uint32 { return c.ID })
	return c
}

// ClusterByID finds a cluster by ID.
func (m *Model) ClusterByID(id uint32) *Cluster { return m.byID[id] }

// Attribute finds an attribute by name, unique name prefix, or ID.
func (c *Cluster) Attribute(s string) *Attribute {
	a, _ := find(c.Attributes, s, func(a *Attribute) string { return a.Name }, func(a *Attribute) uint32 { return a.ID })
	return a
}

// AttributeByID finds an attribute by ID.
func (c *Cluster) AttributeByID(id uint32) *Attribute {
	for _, a := range c.Attributes {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// Command finds a command by name, unique name prefix, or ID.
func (c *Cluster) Command(s string) *Command {
	cmd, _ := find(c.Commands, s, func(c *Command) string { return c.Name }, func(c *Command) uint32 { return c.ID })
	return cmd
}

// Response finds the command whose response has the given ID.
func (c *Cluster) Response(id uint32) *Command {
	for _, cmd := range c.Commands {
		if cmd.Response != nil && cmd.ResponseID == id {
			return cmd
		}
	}
	return nil
}

// Event finds an event by name, unique name prefix, or ID.
func (c *Cluster) Event(s string) *Event {
	e, _ := find(c.Events, s, func(e *Event) string { return e.Name }, func(e *Event) uint32 { return e.ID })
	return e
}

// EventByID finds an event by ID.
func (c *Cluster) EventByID(id uint32) *Event {
	for _, e := range c.Events {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Item finds an enum value or bitmap bit by name.
func (t *Type) Item(s string) (Item, bool) {
	k := key(s)
	for _, it := range t.Items {
		if key(it.Name) == k {
			return it, true
		}
	}
	return Item{}, false
}

// Field finds a struct field by name, unique name prefix, or ID.
func (t *Type) Field(s string) *Field {
	f, _ := find(t.Fields, s, func(f *Field) string { return f.Name }, func(f *Field) uint32 { return f.ID })
	return f
}

// TypeString describes a field's type as in the IDL.
func (f *Field) TypeString() string {
	var b strings.Builder
	if f.Optional {
		b.WriteString("optional ")
	}
	if f.Nullable {
		b.WriteString("nullable ")
	}
	b.WriteString(f.Type.Name)
	if f.List {
		b.WriteString("[]")
	}
	return b.String()
}
