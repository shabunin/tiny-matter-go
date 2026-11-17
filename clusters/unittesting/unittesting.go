// Package unittesting is the Unit Testing cluster (0xFFF1FC05), a test-only
// cluster with an attribute of every data type, list and struct attributes,
// and commands that echo their arguments. The Matter SDK's YAML conformance
// tests (TestCluster and friends) drive it; it follows the SDK's own
// implementation (test-cluster-server.cpp) where its behaviour is not set by
// the data model. It is meant for host test devices, not firmware.
package unittesting

import (
	"bytes"
	"errors"
	"math"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// ID is the Unit Testing cluster.
const ID = 0xFFF1FC05

// Events.
const (
	EventTest                = 1
	EventTestFabricScoped    = 2
	EventTestDifferentVendor = 0xFFF200EE
)

type kind uint8

const (
	kBool kind = iota
	kUint
	kInt
	kF32
	kF64
	kOctets
	kChars
	kStruct
)

// attr describes a stored attribute.
type attr struct {
	kind     kind
	bits     uint8 // integers
	size     int   // strings: maximum length
	nullable bool
	ranged   bool
	min, max int64
	def      int64  // integer default
	defRaw   []byte // struct default (anonymous tag); nil: null
}

const (
	attrListInt8u            = 26
	attrListOctetString      = 27
	attrListStructOctet      = 28
	attrListNullablesStructs = 35
	attrListLongOctetString  = 42
	attrListFabricScoped     = 43
	attrTimedWriteBoolean    = 48
	attrGeneralErrorBoolean  = 49
	attrClusterErrorBoolean  = 50
	attrMeiInt8u             = 0xFFF24F01
)

var schema = map[uint32]attr{}

var attrIDs []uint32

func init() {
	u := func(bits uint8) attr { return attr{kind: kUint, bits: bits} }
	s := func(bits uint8) attr { return attr{kind: kInt, bits: bits} }
	simple := encode(func(w *tlv.Writer) { simpleStruct(w, tlv.Anonymous) })
	global := encode(func(w *tlv.Writer) {
		w.StartStruct(tlv.Anonymous)
		w.PutString(tlv.ContextTag(0), "")
		w.PutNull(tlv.ContextTag(1))
		w.EndContainer()
	})
	base := map[uint32]attr{
		0: {kind: kBool}, 1: u(8), 2: u(16), 3: u(32), 4: u(64),
		5: u(8), 6: u(16), 7: u(24), 8: u(32), 9: u(40), 10: u(48), 11: u(56), 12: u(64),
		13: s(8), 14: s(16), 15: s(24), 16: s(32), 17: s(40), 18: s(48), 19: s(56), 20: s(64),
		21: u(8), 22: u(16), 23: {kind: kF32}, 24: {kind: kF64},
		25: {kind: kOctets, size: 10}, 29: {kind: kOctets, size: 1000},
		30: {kind: kChars, size: 10}, 31: {kind: kChars, size: 1000},
		32: u(64), 33: u(32), 34: u(16), 36: u(8),
		37: {kind: kStruct, defRaw: simple},
		38: {kind: kUint, bits: 8, ranged: true, min: 20, max: 100, def: 70},
		39: {kind: kInt, bits: 8, ranged: true, min: -40, max: 50, def: -20},
		40: {kind: kUint, bits: 16, ranged: true, min: 100, max: 1000, def: 200},
		41: {kind: kInt, bits: 16, ranged: true, min: -150, max: 200, def: -100},
		51: u(8), 52: {kind: kStruct, defRaw: global},
	}
	for id, a := range base {
		schema[id] = a
	}
	schema[attrTimedWriteBoolean] = attr{kind: kBool}
	schema[attrMeiInt8u] = u(8)
	// The nullable variants live at 0x4000 + the ID of the plain one.
	for _, id := range []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 30, 36, 38, 39, 40, 41, 51} {
		a := schema[id]
		a.nullable = true
		schema[0x4000+id] = a
	}
	schema[0x4025] = attr{kind: kStruct, nullable: true}
	schema[0x4034] = attr{kind: kStruct, nullable: true}

	for id := uint32(0); id <= 52; id++ {
		if id < 44 || id >= 48 {
			attrIDs = append(attrIDs, id)
		}
	}
	for id := uint32(0x4000); id <= 0x4034; id++ {
		if _, ok := schema[id]; ok {
			attrIDs = append(attrIDs, id)
		}
	}
	attrIDs = append(attrIDs, attrMeiInt8u)
}

// simpleStruct writes a SimpleStruct of zero values.
func simpleStruct(w *tlv.Writer, tag tlv.Tag) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(0), 0)
	w.PutBool(tlv.ContextTag(1), false)
	w.PutUint(tlv.ContextTag(2), 0)
	w.PutBytes(tlv.ContextTag(3), nil)
	w.PutString(tlv.ContextTag(4), "")
	w.PutUint(tlv.ContextTag(5), 0)
	w.PutFloat32(tlv.ContextTag(6), 0)
	w.PutFloat64(tlv.ContextTag(7), 0)
	w.EndContainer()
}

func encode(f func(w *tlv.Writer)) []byte {
	w := tlv.NewWriter(nil)
	f(w)
	return w.Bytes()
}

// Status codes of the SDK's list handling.
const (
	listMax  = 4 // kAttributeListLength
	entryMax = 6 // kAttributeEntryLength
)

// longOctets is the only value a listLongOctetString entry may have.
var longOctets = func() []byte {
	b := make([]byte, 512)
	for i := range b {
		b[i] = "0123456789abcdef"[i%16]
	}
	return b
}()

type structOctet struct {
	member1 uint64
	member2 []byte
}

type fabricEntry struct {
	fabric uint8
	fields []byte // the struct, anonymous tag, without FabricIndex
}

// Cluster is a Unit Testing cluster instance.
type Cluster struct {
	im.ClusterBase
	values map[uint32][]byte // anonymous-tag TLV

	listInt8u     []uint8
	listOctets    [][]byte
	listStruct    []structOctet
	longCount     int
	nullables     []byte // the one NullablesAndOptionalsStruct
	nullableCount int
	fabricScoped  []fabricEntry
}

// New returns a cluster with the SDK's initial values.
func New() *Cluster {
	c := &Cluster{
		listInt8u:     make([]uint8, listMax),
		listOctets:    make([][]byte, listMax),
		listStruct:    make([]structOctet, listMax),
		longCount:     listMax,
		nullableCount: 1,
	}
	c.reset()
	return c
}

// reset sets the stored attributes to their defaults, like the Test
// command: list contents are cleared but keep their length.
func (c *Cluster) reset() {
	c.values = make(map[uint32][]byte, len(schema))
	for id, a := range schema {
		c.values[id] = defaultValue(a)
	}
	for i := range c.listInt8u {
		c.listInt8u[i] = 0
	}
	for i := range c.listOctets {
		c.listOctets[i] = nil
	}
	for i := range c.listStruct {
		c.listStruct[i] = structOctet{}
	}
	c.nullables = encode(func(w *tlv.Writer) {
		w.StartStruct(tlv.Anonymous)
		w.PutNull(tlv.ContextTag(0))
		w.PutNull(tlv.ContextTag(3))
		w.PutNull(tlv.ContextTag(6))
		w.PutNull(tlv.ContextTag(9))
		w.EndContainer()
	})
}

func defaultValue(a attr) []byte {
	return encode(func(w *tlv.Writer) {
		switch a.kind {
		case kBool:
			w.PutBool(tlv.Anonymous, false)
		case kUint:
			w.PutUint(tlv.Anonymous, uint64(a.def))
		case kInt:
			w.PutInt(tlv.Anonymous, a.def)
		case kF32:
			w.PutFloat32(tlv.Anonymous, 0)
		case kF64:
			w.PutFloat64(tlv.Anonymous, 0)
		case kOctets:
			w.PutBytes(tlv.Anonymous, nil)
		case kChars:
			w.PutString(tlv.Anonymous, "")
		case kStruct:
			if a.defRaw == nil {
				w.PutNull(tlv.Anonymous)
			} else {
				w.PutRaw(a.defRaw)
			}
		}
	})
}

func (*Cluster) ID() uint32           { return ID }
func (*Cluster) Revision() uint16     { return 1 }
func (*Cluster) Attributes() []uint32 { return attrIDs }

var (
	accepted  = []uint32{0, 1, 2, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 0xFFF200AA}
	generated = []uint32{0, 1, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 0xFFF200BB}
)

func (*Cluster) AcceptedCommands() []uint32  { return accepted }
func (*Cluster) GeneratedCommands() []uint32 { return generated }

func (*Cluster) Events() []uint32 {
	return []uint32{EventTest, EventTestFabricScoped, EventTestDifferentVendor}
}

func (c *Cluster) ReadAttribute(ctx *im.Context, id uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch id {
	case attrGeneralErrorBoolean:
		return im.InvalidDataType
	case attrClusterErrorBoolean:
		return ctx.ClusterStatus(17)
	case attrListInt8u:
		w.StartArray(tag)
		for _, v := range c.listInt8u {
			w.PutUint(tlv.Anonymous, uint64(v))
		}
		w.EndContainer()
	case attrListOctetString:
		w.StartArray(tag)
		for _, v := range c.listOctets {
			w.PutBytes(tlv.Anonymous, v)
		}
		w.EndContainer()
	case attrListStructOctet:
		w.StartArray(tag)
		for _, v := range c.listStruct {
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(0), v.member1)
			w.PutBytes(tlv.ContextTag(1), v.member2)
			w.EndContainer()
		}
		w.EndContainer()
	case attrListNullablesStructs:
		w.StartArray(tag)
		w.PutRaw(c.nullables)
		w.EndContainer()
	case attrListLongOctetString:
		w.StartArray(tag)
		for range c.longCount {
			w.PutBytes(tlv.Anonymous, longOctets)
		}
		w.EndContainer()
	case attrListFabricScoped:
		fabric := accessingFabric(ctx)
		w.StartArray(tag)
		for _, e := range c.fabricScoped {
			if ctx.FabricFiltered && e.fabric != fabric {
				continue
			}
			w.StartStruct(tlv.Anonymous)
			if e.fabric == fabric {
				copyFields(w, e.fields)
			}
			w.PutUint(tlv.ContextTag(254), uint64(e.fabric))
			w.EndContainer()
		}
		w.EndContainer()
	default:
		v, ok := c.values[id]
		if !ok {
			return im.UnsupportedAttribute
		}
		r := tlv.NewReader(v)
		if r.Next() != nil || copyElem(w, tag, r) != nil {
			return im.Failure
		}
	}
	return im.Success
}

func accessingFabric(ctx *im.Context) uint8 {
	if ctx.Session == nil {
		return 0
	}
	return ctx.Session.FabricIndex
}

func (c *Cluster) WriteAttribute(ctx *im.Context, id uint32, appendItem bool, r *tlv.Reader) im.Status {
	switch id {
	case attrGeneralErrorBoolean:
		return im.InvalidDataType
	case attrClusterErrorBoolean:
		return ctx.ClusterStatus(17)
	case attrTimedWriteBoolean:
		if !ctx.Timed {
			return im.NeedsTimedInteraction
		}
	case attrListInt8u, attrListOctetString, attrListStructOctet, attrListNullablesStructs,
		attrListLongOctetString, attrListFabricScoped:
		st := c.writeList(ctx, id, appendItem, r)
		if st == im.Success {
			ctx.Node.Changed(ctx.Endpoint, ID, id)
		}
		return st
	}
	a, ok := schema[id]
	if !ok {
		return im.UnsupportedAttribute
	}
	if appendItem {
		return im.InvalidAction
	}
	v, st := validate(a, r)
	if st != im.Success {
		return st
	}
	if !bytes.Equal(v, c.values[id]) {
		c.values[id] = v
		ctx.Node.Changed(ctx.Endpoint, ID, id)
	}
	return im.Success
}

// validate checks a written value against a and returns its encoding.
func validate(a attr, r *tlv.Reader) ([]byte, im.Status) {
	w := tlv.NewWriter(nil)
	if r.Type() == tlv.TypeNull {
		if !a.nullable {
			return nil, im.InvalidDataType
		}
		w.PutNull(tlv.Anonymous)
		return w.Bytes(), im.Success
	}
	switch a.kind {
	case kBool:
		v, err := r.Bool()
		if err != nil {
			return nil, im.InvalidDataType
		}
		w.PutBool(tlv.Anonymous, v)
	case kUint:
		if r.Type() != tlv.TypeUint && r.Type() != tlv.TypeInt {
			return nil, im.InvalidDataType
		}
		v, err := r.Uint()
		if err != nil {
			return nil, im.ConstraintError
		}
		top := uint64(math.MaxUint64) >> (64 - a.bits)
		if v > top || a.nullable && v == top || a.ranged && (v < uint64(a.min) || v > uint64(a.max)) {
			return nil, im.ConstraintError
		}
		w.PutUint(tlv.Anonymous, v)
	case kInt:
		if r.Type() != tlv.TypeUint && r.Type() != tlv.TypeInt {
			return nil, im.InvalidDataType
		}
		v, err := r.Int()
		if err != nil {
			return nil, im.ConstraintError
		}
		lo, hi := int64(math.MinInt64)>>(64-a.bits), int64(math.MaxInt64)>>(64-a.bits)
		if v < lo || v > hi || a.nullable && v == lo || a.ranged && (v < a.min || v > a.max) {
			return nil, im.ConstraintError
		}
		w.PutInt(tlv.Anonymous, v)
	case kF32, kF64:
		v, err := r.Float()
		if err != nil {
			return nil, im.InvalidDataType
		}
		if a.kind == kF32 {
			w.PutFloat32(tlv.Anonymous, float32(v))
		} else {
			w.PutFloat64(tlv.Anonymous, v)
		}
	case kOctets:
		v, err := r.Bytes()
		if err != nil {
			return nil, im.InvalidDataType
		}
		if len(v) > a.size {
			return nil, im.ConstraintError
		}
		w.PutBytes(tlv.Anonymous, v)
	case kChars:
		v, err := r.String()
		if err != nil {
			return nil, im.InvalidDataType
		}
		if len(v) > a.size {
			return nil, im.ConstraintError
		}
		w.PutString(tlv.Anonymous, v)
	case kStruct:
		if r.Type() != tlv.TypeStruct || copyElem(w, tlv.Anonymous, r) != nil {
			return nil, im.InvalidDataType
		}
	}
	return w.Bytes(), im.Success
}

// writeList replaces a list attribute, or appends an item to it.
func (c *Cluster) writeList(ctx *im.Context, id uint32, appendItem bool, r *tlv.Reader) im.Status {
	var items []*tlv.Reader // each positioned on its element
	if appendItem {
		items = []*tlv.Reader{r}
	} else {
		if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
			return im.InvalidDataType
		}
		for r.Next() == nil {
			raw, err := r.RawElement()
			if err != nil {
				return im.InvalidDataType
			}
			ir := tlv.NewReader(raw)
			ir.Next()
			items = append(items, ir)
		}
		if r.ExitContainer() != nil {
			return im.InvalidDataType
		}
	}
	switch id {
	case attrListInt8u:
		l := c.listInt8u
		if !appendItem {
			l = nil
		}
		for _, ir := range items {
			v, err := ir.Uint8()
			if err != nil {
				return im.InvalidDataType
			}
			if len(l) == listMax {
				return im.Failure
			}
			l = append(l, v)
		}
		c.listInt8u = l
	case attrListOctetString:
		l := c.listOctets
		if !appendItem {
			l = nil
		}
		for _, ir := range items {
			v, err := ir.Bytes()
			if err != nil {
				return im.InvalidDataType
			}
			if len(l) == listMax || len(v) > entryMax {
				return im.Failure
			}
			l = append(l, bytes.Clone(v))
		}
		c.listOctets = l
	case attrListStructOctet:
		l := c.listStruct
		if !appendItem {
			l = nil
		}
		for _, ir := range items {
			var e structOctet
			err := im.ForEachField(ir, func(r *tlv.Reader, tag uint8) (err error) {
				switch tag {
				case 0:
					e.member1, err = r.Uint()
				case 1:
					var b []byte
					b, err = r.Bytes()
					e.member2 = bytes.Clone(b)
				}
				return err
			})
			if err != nil {
				return im.InvalidDataType
			}
			if len(l) == listMax || len(e.member2) > entryMax {
				return im.Failure
			}
			l = append(l, e)
		}
		c.listStruct = l
	case attrListLongOctetString:
		n := c.longCount
		if !appendItem {
			n = 0
		}
		for _, ir := range items {
			v, err := ir.Bytes()
			if err != nil {
				return im.InvalidDataType
			}
			if !bytes.Equal(v, longOctets) {
				return im.Failure
			}
			n++
		}
		c.longCount = n
	case attrListNullablesStructs:
		return c.writeNullables(appendItem, items)
	case attrListFabricScoped:
		return c.writeFabricScoped(accessingFabric(ctx), appendItem, items)
	}
	return im.Success
}

// writeNullables mirrors the SDK: the list may only be replaced by an empty
// one, then one item appended, of which only some fields may be set.
func (c *Cluster) writeNullables(appendItem bool, items []*tlv.Reader) im.Status {
	if !appendItem {
		c.nullableCount = len(items)
		if len(items) != 0 {
			return im.Failure
		}
		return im.Success
	}
	if c.nullableCount != 0 {
		return im.Failure
	}
	var nullableInt, optionalInt, nullableOptionalInt, nullableList []byte
	bad := false
	err := im.ForEachField(items[0], func(r *tlv.Reader, tag uint8) error {
		raw, err := r.RawElement()
		switch tag {
		case 0:
			nullableInt = raw
		case 1:
			optionalInt = raw
		case 2:
			nullableOptionalInt = raw
		case 3, 6:
			bad = bad || !r.IsNull()
		case 9:
			nullableList = raw
		default:
			bad = true
		}
		return err
	})
	if err != nil || nullableInt == nil {
		return im.InvalidDataType
	}
	if bad {
		return im.Failure
	}
	c.nullableCount++
	c.nullables = encode(func(w *tlv.Writer) {
		w.StartStruct(tlv.Anonymous)
		for _, raw := range [][]byte{nullableInt, optionalInt, nullableOptionalInt} {
			if raw != nil {
				w.PutRaw(raw)
			}
		}
		w.PutNull(tlv.ContextTag(3))
		w.PutNull(tlv.ContextTag(6))
		if nullableList != nil {
			w.PutRaw(nullableList)
		} else {
			w.PutNull(tlv.ContextTag(9))
		}
		w.EndContainer()
	})
	return im.Success
}

// writeFabricScoped replaces the accessing fabric's entries of
// listFabricScoped, or appends one.
func (c *Cluster) writeFabricScoped(fabric uint8, appendItem bool, items []*tlv.Reader) im.Status {
	l := c.fabricScoped
	if !appendItem {
		l = nil
		for _, e := range c.fabricScoped {
			if e.fabric != fabric {
				l = append(l, e)
			}
		}
	}
	for _, ir := range items {
		if len(l) == listMax {
			return im.Failure
		}
		w := tlv.NewWriter(nil)
		w.StartStruct(tlv.Anonymous)
		err := im.ForEachField(ir, func(r *tlv.Reader, tag uint8) error {
			if tag == 254 {
				return nil // set to the accessing fabric
			}
			return copyElem(w, tlv.ContextTag(tag), r)
		})
		w.EndContainer()
		if err != nil {
			return im.InvalidDataType
		}
		l = append(l, fabricEntry{fabric: fabric, fields: w.Bytes()})
	}
	c.fabricScoped = l
	return im.Success
}

// RemoveFabric drops a removed fabric's listFabricScoped entries.
func (c *Cluster) RemoveFabric(fabric uint8) {
	l := c.fabricScoped[:0]
	for _, e := range c.fabricScoped {
		if e.fabric != fabric {
			l = append(l, e)
		}
	}
	c.fabricScoped = l
}

var errType = errors.New("unittesting: unknown TLV type")

// copyElem writes the element r is positioned on with tag.
func copyElem(w *tlv.Writer, tag tlv.Tag, r *tlv.Reader) error {
	var err error
	switch r.Type() {
	case tlv.TypeInt:
		var v int64
		v, err = r.Int()
		w.PutInt(tag, v)
	case tlv.TypeUint:
		var v uint64
		v, err = r.Uint()
		w.PutUint(tag, v)
	case tlv.TypeBool:
		var v bool
		v, err = r.Bool()
		w.PutBool(tag, v)
	case tlv.TypeFloat32:
		var v float64
		v, err = r.Float()
		w.PutFloat32(tag, float32(v))
	case tlv.TypeFloat64:
		var v float64
		v, err = r.Float()
		w.PutFloat64(tag, v)
	case tlv.TypeUTF8:
		var v string
		v, err = r.String()
		w.PutString(tag, v)
	case tlv.TypeBytes:
		var v []byte
		v, err = r.Bytes()
		w.PutBytes(tag, v)
	case tlv.TypeNull:
		w.PutNull(tag)
	case tlv.TypeStruct, tlv.TypeArray, tlv.TypeList:
		switch r.Type() {
		case tlv.TypeStruct:
			w.StartStruct(tag)
		case tlv.TypeArray:
			w.StartArray(tag)
		default:
			w.StartList(tag)
		}
		if err = r.EnterContainer(); err != nil {
			return err
		}
		for r.Next() == nil {
			if err = copyElem(w, r.Tag(), r); err != nil {
				return err
			}
		}
		if err = r.ExitContainer(); err != nil {
			return err
		}
		w.EndContainer()
	default:
		return errType
	}
	return err
}

// copyFields writes the fields of the encoded struct raw.
func copyFields(w *tlv.Writer, raw []byte) {
	r := tlv.NewReader(raw)
	if r.Next() != nil || r.EnterContainer() != nil {
		return
	}
	for r.Next() == nil {
		copyElem(w, r.Tag(), r)
	}
}
