package unittesting

import (
	"bytes"
	"testing"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func setup() (*Cluster, *im.Context) {
	n := im.NewNode(1)
	c := New()
	n.AddCluster(n.AddEndpoint(1), c)
	return c, &im.Context{Node: n, Endpoint: 1, Session: &exchange.Session{FabricIndex: 1}}
}

func reader(put func(w *tlv.Writer)) *tlv.Reader {
	w := tlv.NewWriter(nil)
	put(w)
	r := tlv.NewReader(w.Bytes())
	r.Next()
	return r
}

func write(c *Cluster, ctx *im.Context, id uint32, put func(w *tlv.Writer)) im.Status {
	return c.WriteAttribute(ctx, id, false, reader(put))
}

func uintV(v uint64) func(w *tlv.Writer) { return func(w *tlv.Writer) { w.PutUint(tlv.Anonymous, v) } }
func intV(v int64) func(w *tlv.Writer)   { return func(w *tlv.Writer) { w.PutInt(tlv.Anonymous, v) } }

func read(t *testing.T, c *Cluster, ctx *im.Context, id uint32) *tlv.Reader {
	t.Helper()
	w := tlv.NewWriter(nil)
	if st := c.ReadAttribute(ctx, id, w, tlv.Anonymous); st != im.Success {
		t.Fatalf("read %#x: %#x", id, st)
	}
	r := tlv.NewReader(w.Bytes())
	r.Next()
	return r
}

func TestScalars(t *testing.T) {
	c, ctx := setup()
	if v, _ := read(t, c, ctx, 38).Uint(); v != 70 {
		t.Errorf("rangeRestrictedInt8u default %d", v)
	}
	for _, tc := range []struct {
		id   uint32
		put  func(w *tlv.Writer)
		want im.Status
	}{
		{5, uintV(255), im.Success},              // int8u
		{5, uintV(256), im.ConstraintError},      // too wide
		{0x4005, uintV(255), im.ConstraintError}, // nullable int8u: 255 is null
		{0x4005, uintV(254), im.Success},         //
		{7, uintV(1 << 24), im.ConstraintError},  // int24u
		{0x400D, intV(-128), im.ConstraintError}, // nullable int8s: -128 is null
		{15, intV(-1 << 23), im.Success},         // int24s
		{38, uintV(19), im.ConstraintError},      // range 20..100
		{38, uintV(100), im.Success},             //
		{39, intV(-41), im.ConstraintError},      // range -40..50
		{0x4026, uintV(101), im.ConstraintError}, // nullable range
		{25, func(w *tlv.Writer) { w.PutBytes(tlv.Anonymous, make([]byte, 11)) }, im.ConstraintError},
		{30, func(w *tlv.Writer) { w.PutString(tlv.Anonymous, "0123456789") }, im.Success},
		{0, func(w *tlv.Writer) { w.PutNull(tlv.Anonymous) }, im.InvalidDataType},
		{0x4000, func(w *tlv.Writer) { w.PutNull(tlv.Anonymous) }, im.Success},
		{0, uintV(1), im.InvalidDataType}, // not a boolean
		{attrTimedWriteBoolean, func(w *tlv.Writer) { w.PutBool(tlv.Anonymous, true) }, im.NeedsTimedInteraction},
		{attrGeneralErrorBoolean, func(w *tlv.Writer) { w.PutBool(tlv.Anonymous, true) }, im.InvalidDataType},
		{0xFF, uintV(1), im.UnsupportedAttribute},
	} {
		if st := write(c, ctx, tc.id, tc.put); st != tc.want {
			t.Errorf("write %#x: %#x, want %#x", tc.id, st, tc.want)
		}
	}
	if v, _ := read(t, c, ctx, 38).Uint(); v != 100 {
		t.Errorf("rangeRestrictedInt8u %d after writes", v)
	}
	if !read(t, c, ctx, 0x4000).IsNull() {
		t.Error("nullableBoolean not null")
	}
	if st := c.ReadAttribute(ctx, attrClusterErrorBoolean, tlv.NewWriter(nil), tlv.Anonymous); st != im.Failure {
		t.Errorf("clusterErrorBoolean: %#x", st)
	}

	// The Test command restores the defaults.
	if st := c.Invoke(ctx, cmdTest, reader(func(w *tlv.Writer) { w.StartStruct(tlv.Anonymous); w.EndContainer() }), nil); st != im.Success {
		t.Fatalf("Test: %#x", st)
	}
	if v, _ := read(t, c, ctx, 38).Uint(); v != 70 {
		t.Errorf("rangeRestrictedInt8u %d after Test", v)
	}
}

func TestLists(t *testing.T) {
	c, ctx := setup()
	list := func(vs ...uint64) func(w *tlv.Writer) {
		return func(w *tlv.Writer) {
			w.StartArray(tlv.Anonymous)
			for _, v := range vs {
				w.PutUint(tlv.Anonymous, v)
			}
			w.EndContainer()
		}
	}
	if st := write(c, ctx, attrListInt8u, list(1, 2)); st != im.Success {
		t.Fatal(st)
	}
	if st := c.WriteAttribute(ctx, attrListInt8u, true, reader(uintV(3))); st != im.Success {
		t.Fatal(st)
	}
	if !bytes.Equal(c.listInt8u, []byte{1, 2, 3}) {
		t.Fatalf("list %v", c.listInt8u)
	}
	if st := write(c, ctx, attrListInt8u, list(1, 2, 3, 4, 5)); st != im.Failure || len(c.listInt8u) != 3 {
		t.Fatalf("5 items: %#x, list %v", st, c.listInt8u)
	}

	// listFabricScoped: each fabric replaces its own entries; others see
	// only the fabric index.
	entry := func(v uint64) func(w *tlv.Writer) {
		return func(w *tlv.Writer) {
			w.StartArray(tlv.Anonymous)
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), v)
			w.PutUint(tlv.ContextTag(254), 9) // ignored
			w.EndContainer()
			w.EndContainer()
		}
	}
	ctx2 := *ctx
	ctx2.Session = &exchange.Session{FabricIndex: 2}
	write(c, ctx, attrListFabricScoped, entry(11))
	write(c, &ctx2, attrListFabricScoped, entry(22))
	write(c, ctx, attrListFabricScoped, entry(12))
	r := read(t, c, ctx, attrListFabricScoped)
	r.EnterContainer()
	var got []string
	for r.Next() == nil {
		var v, fi uint64
		im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 1:
				v, err = r.Uint()
			case 254:
				fi, err = r.Uint()
			}
			return err
		})
		got = append(got, string(rune('0'+fi))+":"+string(rune('0'+v%10)))
	}
	if want := []string{"2:0", "1:2"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("listFabricScoped %v, want %v", got, want)
	}
	c.RemoveFabric(2)
	if len(c.fabricScoped) != 1 {
		t.Fatal("RemoveFabric kept the fabric's entries")
	}
}

func TestCommands(t *testing.T) {
	c, ctx := setup()
	invoke := func(cmd uint32, put func(w *tlv.Writer)) (im.Status, *tlv.Reader) {
		w := tlv.NewWriter(nil)
		resp := im.NewResponse(w, im.CommandPath{Endpoint: 1, Cluster: ID, Command: cmd})
		st := c.Invoke(ctx, cmd, reader(func(w *tlv.Writer) {
			w.StartStruct(tlv.Anonymous)
			put(w)
			w.EndContainer()
		}), resp)
		if w.Len() == 0 {
			return st, nil
		}
		for w.Depth() > 0 {
			w.EndContainer()
		}
		r := tlv.NewReader(w.Bytes())
		r.Next()
		return st, field(field(r, 0), 1) // CommandDataIB, CommandFields
	}
	add := func(a, b uint64) func(w *tlv.Writer) {
		return func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), a)
			w.PutUint(tlv.ContextTag(1), b)
		}
	}
	st, r := invoke(cmdTestAddArguments, add(3, 4))
	sum := field(r, 0)
	if st != im.Success || sum == nil {
		t.Fatalf("add: %#x", st)
	}
	if v, _ := sum.Uint(); v != 7 {
		t.Fatalf("3+4 = %d", v)
	}
	if st, _ := invoke(cmdTestAddArguments, add(200, 100)); st != im.InvalidCommand {
		t.Fatalf("overflow: %#x", st)
	}
	if st, _ := invoke(cmdTestEnums, add(0x4E23, 4)); st != im.Failure {
		t.Fatalf("unknown enum echoed: %#x", st)
	}
	st, r = invoke(cmdTestListInt8UReverse, func(w *tlv.Writer) {
		w.StartArray(tlv.ContextTag(0))
		for _, v := range []uint64{1, 2, 3} {
			w.PutUint(tlv.Anonymous, v)
		}
		w.EndContainer()
	})
	var rev []uint64
	eachIn(field(r, 0), func(r *tlv.Reader) {
		v, _ := r.Uint()
		rev = append(rev, v)
	})
	if st != im.Success || len(rev) != 3 || rev[0] != 3 || rev[2] != 1 {
		t.Fatalf("reverse: %#x %v", st, rev)
	}
	if st, _ := invoke(cmdTimedInvoke, func(*tlv.Writer) {}); st != im.NeedsTimedInteraction {
		t.Fatalf("untimed TimedInvokeRequest: %#x", st)
	}
	if st, _ := invoke(3, func(*tlv.Writer) {}); st != im.UnsupportedCommand {
		t.Fatalf("TestUnknownCommand: %#x", st)
	}
}
