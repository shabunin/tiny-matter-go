package unittesting

import (
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Commands and their responses.
const (
	cmdTest                          = 0
	cmdTestNotHandled                = 1
	cmdTestSpecific                  = 2
	cmdTestAddArguments              = 4
	cmdTestStructArgument            = 7
	cmdTestNestedStructArgument      = 8
	cmdTestListStructArgument        = 9
	cmdTestListInt8UArgument         = 10
	cmdTestNestedStructListArgument  = 11
	cmdTestListNestedStructListArg   = 12
	cmdTestListInt8UReverse          = 13
	cmdTestEnums                     = 14
	cmdTestNullableOptional          = 15
	cmdSimpleStructEcho              = 17
	cmdTimedInvoke                   = 18
	cmdTestSimpleOptionalArgument    = 19
	cmdTestEmitTestEvent             = 20
	cmdTestEmitTestFabricScopedEvent = 21
	cmdTestBatchHelper               = 22
	cmdTestSecondBatchHelper         = 23
	cmdStringEcho                    = 24
	cmdGlobalEcho                    = 25
	cmdTestCheckCommandFlags         = 26
	cmdTestDifferentVendorMei        = 0xFFF200AA
	rspTestSpecific                  = 0
	rspTestAddArguments              = 1
	rspTestListInt8UReverse          = 4
	rspTestEnums                     = 5
	rspTestNullableOptional          = 6
	rspBoolean                       = 8
	rspSimpleStruct                  = 9
	rspTestEmitTestEvent             = 10
	rspTestEmitTestFabricScopedEvent = 11
	rspTestBatchHelper               = 12
	rspStringEcho                    = 13
	rspGlobalEcho                    = 14
	rspTestDifferentVendorMei        = 0xFFF200BB
	batchHelperMax                   = 800
	simpleEnumMax                    = 3
)

// fields collects a command's fields as raw elements by tag.
func fields(r *tlv.Reader) (map[uint8]*tlv.Reader, bool) {
	m := map[uint8]*tlv.Reader{}
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		raw, err := r.RawElement()
		if err != nil {
			return err
		}
		fr := tlv.NewReader(raw)
		fr.Next()
		m[tag] = fr
		return nil
	})
	return m, err == nil
}

func (c *Cluster) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	f, ok := fields(r)
	if !ok {
		return im.InvalidCommand
	}
	switch cmd {
	case cmdTest:
		c.reset()
		for _, id := range attrIDs {
			ctx.Node.Changed(ctx.Endpoint, ID, id)
		}
		return im.Success
	case cmdTestNotHandled:
		return im.InvalidCommand
	case cmdTestSpecific:
		resp.Fields(rspTestSpecific).PutUint(tlv.ContextTag(0), 7)
		return im.Success
	case cmdTestAddArguments:
		a, err1 := uint8Field(f, 0)
		b, err2 := uint8Field(f, 1)
		if err1 != nil || err2 != nil {
			return im.InvalidCommand
		}
		if int(a)+int(b) > 255 {
			return im.InvalidCommand
		}
		resp.Fields(rspTestAddArguments).PutUint(tlv.ContextTag(0), uint64(a+b))
		return im.Success
	case cmdTestStructArgument:
		b, ok := structBool(f[0])
		if !ok {
			return im.InvalidCommand
		}
		return boolResponse(resp, b)
	case cmdTestNestedStructArgument:
		b, ok := structBool(field(f[0], 2))
		if !ok {
			return im.InvalidCommand
		}
		return boolResponse(resp, b)
	case cmdTestListStructArgument:
		all, ok := true, true
		eachIn(f[0], func(r *tlv.Reader) {
			b, good := structBool(r)
			all, ok = all && b, ok && good
		})
		if f[0] == nil || !ok {
			return im.InvalidCommand
		}
		return boolResponse(resp, all)
	case cmdTestListInt8UArgument:
		all, ok := true, f[0] != nil
		eachIn(f[0], func(r *tlv.Reader) {
			v, err := r.Uint8()
			all, ok = all && v != 0, ok && err == nil
		})
		if !ok {
			return im.InvalidCommand
		}
		return boolResponse(resp, all)
	case cmdTestNestedStructListArgument:
		all, ok := nestedStructList(f[0])
		if !ok {
			return im.InvalidCommand
		}
		return boolResponse(resp, all)
	case cmdTestListNestedStructListArg:
		all, ok := true, f[0] != nil
		eachIn(f[0], func(r *tlv.Reader) {
			b, good := nestedStructList(r)
			all, ok = all && b, ok && good
		})
		if !ok {
			return im.InvalidCommand
		}
		return boolResponse(resp, all)
	case cmdTestListInt8UReverse:
		var l []uint8
		ok := f[0] != nil
		eachIn(f[0], func(r *tlv.Reader) {
			v, err := r.Uint8()
			l, ok = append(l, v), ok && err == nil
		})
		if !ok {
			return im.InvalidCommand
		}
		w := resp.Fields(rspTestListInt8UReverse)
		w.StartArray(tlv.ContextTag(0))
		for i := len(l) - 1; i >= 0; i-- {
			w.PutUint(tlv.Anonymous, uint64(l[i]))
		}
		w.EndContainer()
		return im.Success
	case cmdTestEnums:
		vendor, err1 := uint16Field(f, 0)
		e, err2 := uint8Field(f, 1)
		if err1 != nil || err2 != nil {
			return im.InvalidCommand
		}
		if e > simpleEnumMax { // the SDK cannot encode an unknown enum value
			return im.Failure
		}
		w := resp.Fields(rspTestEnums)
		w.PutUint(tlv.ContextTag(0), uint64(vendor))
		w.PutUint(tlv.ContextTag(1), uint64(e))
		return im.Success
	case cmdTestNullableOptional:
		w := resp.Fields(rspTestNullableOptional)
		a := f[0]
		w.PutBool(tlv.ContextTag(0), a != nil)
		if a != nil {
			w.PutBool(tlv.ContextTag(1), a.IsNull())
			if a.IsNull() {
				w.PutNull(tlv.ContextTag(3))
			} else {
				v, err := a.Uint8()
				if err != nil {
					return im.InvalidCommand
				}
				w.PutUint(tlv.ContextTag(2), uint64(v))
				w.PutUint(tlv.ContextTag(3), uint64(v))
			}
		}
		return im.Success
	case cmdSimpleStructEcho:
		if f[0] == nil || f[0].Type() != tlv.TypeStruct {
			return im.InvalidCommand
		}
		w := resp.Fields(rspSimpleStruct)
		if copyElem(w, tlv.ContextTag(0), f[0]) != nil {
			return im.InvalidCommand
		}
		return im.Success
	case cmdTimedInvoke:
		if !ctx.Timed {
			return im.NeedsTimedInteraction
		}
		return im.Success
	case cmdTestSimpleOptionalArgument:
		if f[0] == nil {
			return im.ConstraintError // InvalidValue
		}
		return im.Success
	case cmdTestEmitTestEvent:
		a1, err1 := uint8Field(f, 0)
		a2, err2 := uint8Field(f, 1)
		if err1 != nil || err2 != nil || f[2] == nil {
			return im.InvalidCommand
		}
		a3, err := f[2].Bool()
		if err != nil {
			return im.InvalidCommand
		}
		n, ok := ctx.Node.Emit(ctx.Now, im.Event{
			Path:     im.ConcreteEventPath{Endpoint: ctx.Endpoint, Cluster: ID, Event: EventTest},
			Priority: im.PriorityInfo,
			Fields: func(w *tlv.Writer) {
				w.PutUint(tlv.ContextTag(1), uint64(a1))
				w.PutUint(tlv.ContextTag(2), uint64(a2))
				w.PutBool(tlv.ContextTag(3), a3)
				simpleStruct(w, tlv.ContextTag(4))
				w.StartArray(tlv.ContextTag(5))
				w.EndContainer()
				w.StartArray(tlv.ContextTag(6))
				w.EndContainer()
			},
		})
		if !ok {
			return im.Failure
		}
		resp.Fields(rspTestEmitTestEvent).PutUint(tlv.ContextTag(0), n)
		return im.Success
	case cmdTestEmitTestFabricScopedEvent:
		fi, err := uint8Field(f, 0)
		if err != nil {
			return im.InvalidCommand
		}
		n, ok := ctx.Node.Emit(ctx.Now, im.Event{
			Path:     im.ConcreteEventPath{Endpoint: ctx.Endpoint, Cluster: ID, Event: EventTestFabricScoped},
			Priority: im.PriorityInfo,
			Fabric:   fi,
		})
		if !ok {
			return im.Failure
		}
		resp.Fields(rspTestEmitTestFabricScopedEvent).PutUint(tlv.ContextTag(0), n)
		return im.Success
	case cmdTestBatchHelper, cmdTestSecondBatchHelper:
		// The SDK answers after sleepBeforeResponseTimeMs; this one at once.
		size, err1 := uint16Field(f, 1)
		fill, err2 := uint8Field(f, 2)
		if err1 != nil || err2 != nil {
			return im.InvalidCommand
		}
		if size > batchHelperMax {
			return im.ConstraintError
		}
		b := make([]byte, size)
		for i := range b {
			b[i] = fill
		}
		resp.Fields(rspTestBatchHelper).PutBytes(tlv.ContextTag(0), b)
		return im.Success
	case cmdStringEcho:
		if f[0] == nil {
			return im.InvalidCommand
		}
		b, err := f[0].Bytes()
		if err != nil {
			return im.InvalidCommand
		}
		resp.Fields(rspStringEcho).PutBytes(tlv.ContextTag(0), b)
		return im.Success
	case cmdGlobalEcho:
		if f[0] == nil || f[1] == nil {
			return im.InvalidCommand
		}
		w := resp.Fields(rspGlobalEcho)
		if copyElem(w, tlv.ContextTag(0), f[0]) != nil || copyElem(w, tlv.ContextTag(1), f[1]) != nil {
			return im.InvalidCommand
		}
		return im.Success
	case cmdTestCheckCommandFlags:
		if !ctx.Timed {
			return im.NeedsTimedInteraction
		}
		if accessingFabric(ctx) == 0 {
			return im.UnsupportedAccess
		}
		return im.Success
	case cmdTestDifferentVendorMei:
		a, err := uint8Field(f, 0)
		if err != nil {
			return im.InvalidCommand
		}
		n, ok := ctx.Node.Emit(ctx.Now, im.Event{
			Path:     im.ConcreteEventPath{Endpoint: ctx.Endpoint, Cluster: ID, Event: EventTestDifferentVendor},
			Priority: im.PriorityInfo,
			Fields:   func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(1), uint64(a)) },
		})
		if !ok {
			return im.Failure
		}
		w := resp.Fields(rspTestDifferentVendorMei)
		w.PutUint(tlv.ContextTag(0), uint64(a))
		w.PutUint(tlv.ContextTag(1), n)
		return im.Success
	}
	return im.UnsupportedCommand
}

func boolResponse(resp *im.Response, v bool) im.Status {
	resp.Fields(rspBoolean).PutBool(tlv.ContextTag(0), v)
	return im.Success
}

type missingField struct{}

func (missingField) Error() string { return "unittesting: missing field" }

func uint8Field(f map[uint8]*tlv.Reader, tag uint8) (uint8, error) {
	if f[tag] == nil {
		return 0, missingField{}
	}
	return f[tag].Uint8()
}

func uint16Field(f map[uint8]*tlv.Reader, tag uint8) (uint16, error) {
	if f[tag] == nil {
		return 0, missingField{}
	}
	return f[tag].Uint16()
}

// field returns field tag of the struct r is positioned on, or nil.
func field(r *tlv.Reader, tag uint8) *tlv.Reader {
	if r == nil {
		return nil
	}
	m, ok := fields(r)
	if !ok {
		return nil
	}
	return m[tag]
}

// structBool returns field b (1) of the SimpleStruct r is positioned on.
func structBool(r *tlv.Reader) (bool, bool) {
	b := field(r, 1)
	if b == nil {
		return false, false
	}
	v, err := b.Bool()
	return v, err == nil
}

// eachIn calls f with each item of the list r is positioned on.
func eachIn(r *tlv.Reader, f func(r *tlv.Reader)) {
	if r == nil || (r.Type() != tlv.TypeArray && r.Type() != tlv.TypeList) || r.EnterContainer() != nil {
		return
	}
	for r.Next() == nil {
		raw, err := r.RawElement()
		if err != nil {
			return
		}
		ir := tlv.NewReader(raw)
		ir.Next()
		f(ir)
	}
	r.ExitContainer()
}

// nestedStructList reports whether c.b and every d[].b of the
// NestedStructList r is positioned on are true.
func nestedStructList(r *tlv.Reader) (all, ok bool) {
	if r == nil {
		return false, false
	}
	m, good := fields(r)
	if !good || m[2] == nil || m[3] == nil {
		return false, false
	}
	all, ok = structBool(m[2])
	eachIn(m[3], func(r *tlv.Reader) {
		b, good := structBool(r)
		all, ok = all && b, ok && good
	})
	return all, ok
}
