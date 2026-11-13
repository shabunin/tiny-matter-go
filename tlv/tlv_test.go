package tlv

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// node is a generic decoded element, used only by tests.
type node struct {
	Tag      Tag
	Type     Type
	Value    any // uint64, int64, bool, float64, string, []byte, nil
	Children []node
}

func decodeAll(r *Reader) ([]node, error) {
	var out []node
	for {
		err := r.Next()
		if err == io.EOF || err == ErrEndOfContainer {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		n := node{Tag: r.Tag(), Type: r.Type()}
		switch r.Type() {
		case TypeUint:
			n.Value, _ = r.Uint()
		case TypeInt:
			n.Value, _ = r.Int()
		case TypeBool:
			n.Value, _ = r.Bool()
		case TypeFloat32, TypeFloat64:
			n.Value, _ = r.Float()
		case TypeUTF8:
			n.Value, _ = r.String()
		case TypeBytes:
			b, _ := r.Bytes()
			n.Value = append([]byte{}, b...)
		case TypeStruct, TypeArray, TypeList:
			if err := r.EnterContainer(); err != nil {
				return nil, err
			}
			if n.Children, err = decodeAll(r); err != nil {
				return nil, err
			}
			if n.Children == nil {
				n.Children = []node{}
			}
			if err := r.ExitContainer(); err != nil {
				return nil, err
			}
		}
		out = append(out, n)
	}
}

func encodeAll(w *Writer, nodes []node) {
	for _, n := range nodes {
		switch n.Type {
		case TypeUint:
			w.PutUint(n.Tag, n.Value.(uint64))
		case TypeInt:
			w.PutInt(n.Tag, n.Value.(int64))
		case TypeBool:
			w.PutBool(n.Tag, n.Value.(bool))
		case TypeFloat32:
			w.PutFloat32(n.Tag, float32(n.Value.(float64)))
		case TypeFloat64:
			w.PutFloat64(n.Tag, n.Value.(float64))
		case TypeUTF8:
			w.PutString(n.Tag, n.Value.(string))
		case TypeBytes:
			w.PutBytes(n.Tag, n.Value.([]byte))
		case TypeNull:
			w.PutNull(n.Tag)
		case TypeStruct, TypeArray, TypeList:
			switch n.Type {
			case TypeStruct:
				w.StartStruct(n.Tag)
			case TypeArray:
				w.StartArray(n.Tag)
			default:
				w.StartList(n.Tag)
			}
			encodeAll(w, n.Children)
			w.EndContainer()
		}
	}
}

var (
	anon = Anonymous
	c0   = ContextTag(0)
	c1   = ContextTag(1)
)

func u(tag Tag, v uint64) node { return node{Tag: tag, Type: TypeUint, Value: v} }
func i(tag Tag, v int64) node  { return node{Tag: tag, Type: TypeInt, Value: v} }
func f32(v float32) node       { return node{Tag: anon, Type: TypeFloat32, Value: float64(v)} }
func f64(v float64) node       { return node{Tag: anon, Type: TypeFloat64, Value: v} }
func str(v string) node        { return node{Tag: anon, Type: TypeUTF8, Value: v} }
func ctr(t Type, tag Tag, ch ...node) node {
	if ch == nil {
		ch = []node{}
	}
	return node{Tag: tag, Type: t, Children: ch}
}

// Examples from Matter Core Specification, Appendix A.12 ("TLV Encoding
// Examples"). minimal marks encodings our writer must reproduce byte for byte.
var specVectors = []struct {
	name    string
	hex     string
	want    node
	minimal bool
}{
	{"false", "08", node{Tag: anon, Type: TypeBool, Value: false}, true},
	{"true", "09", node{Tag: anon, Type: TypeBool, Value: true}, true},
	{"int8 42", "00 2a", i(anon, 42), true},
	{"int8 -17", "00 ef", i(anon, -17), true},
	{"uint8 42", "04 2a", u(anon, 42), true},
	{"int16 42", "01 2a 00", i(anon, 42), false},
	{"int32 -170000", "02 f0 67 fd ff", i(anon, -170000), true},
	{"int64 40000000000", "03 00 90 2f 50 09 00 00 00", i(anon, 40000000000), true},
	{"utf8 Hello!", "0c 06 48 65 6c 6c 6f 21", str("Hello!"), true},
	{"utf8 Tschüs", "0c 07 54 73 63 68 c3 bc 73", str("Tschüs"), true},
	{"bytes", "10 05 00 01 02 03 04", node{Tag: anon, Type: TypeBytes, Value: []byte{0, 1, 2, 3, 4}}, true},
	{"null", "14", node{Tag: anon, Type: TypeNull}, true},
	{"float 0", "0a 00 00 00 00", f32(0), true},
	{"float 1/3", "0a ab aa aa 3e", f32(1.0 / 3), true},
	{"float 17.9", "0a 33 33 8f 41", f32(17.9), true},
	{"float +inf", "0a 00 00 80 7f", f32(float32(math.Inf(1))), true},
	{"float -inf", "0a 00 00 80 ff", f32(float32(math.Inf(-1))), true},
	{"double 0", "0b 00 00 00 00 00 00 00 00", f64(0), true},
	{"double 1/3", "0b 55 55 55 55 55 55 d5 3f", f64(1.0 / 3), true},
	{"double 17.9", "0b 66 66 66 66 66 e6 31 40", f64(17.9), true},
	{"double +inf", "0b 00 00 00 00 00 00 f0 7f", f64(math.Inf(1)), true},
	{"double -inf", "0b 00 00 00 00 00 00 f0 ff", f64(math.Inf(-1)), true},
	{"empty struct", "15 18", ctr(TypeStruct, anon), true},
	{"empty array", "16 18", ctr(TypeArray, anon), true},
	{"empty list", "17 18", ctr(TypeList, anon), true},
	{"struct {0=42,1=-17}", "15 20 00 2a 20 01 ef 18",
		ctr(TypeStruct, anon, i(c0, 42), i(c1, -17)), true},
	{"array [0..4]", "16 00 00 00 01 00 02 00 03 00 04 18",
		ctr(TypeArray, anon, i(anon, 0), i(anon, 1), i(anon, 2), i(anon, 3), i(anon, 4)), true},
	{"list mixed tags", "17 00 01 20 00 2a 00 02 00 03 20 00 ef 18",
		ctr(TypeList, anon, i(anon, 1), i(c0, 42), i(anon, 2), i(anon, 3), i(c0, -17)), true},
	{"array mixed types", "16 00 2a 02 f0 67 fd ff 15 18 0a 33 33 8f 41 0c 06 48 65 6c 6c 6f 21 18",
		ctr(TypeArray, anon, i(anon, 42), i(anon, -170000), ctr(TypeStruct, anon), f32(17.9), str("Hello!")), true},
	{"context tag 1", "24 01 2a", u(c1, 42), true},
	{"common profile 2-octet", "44 01 00 2a", u(CommonProfileTag(1), 42), true},
	{"common profile 4-octet", "64 a0 86 01 00 2a", u(CommonProfileTag(100000), 42), true},
	{"implicit profile 2-octet", "84 01 00 2a", u(ImplicitProfileTag(1), 42), true},
	{"implicit profile 4-octet", "a4 a0 86 01 00 2a", u(ImplicitProfileTag(100000), 42), true},
	{"fully qualified 6-octet", "c4 f1 ff ed de 01 00 2a", u(FullyQualifiedTag(0xFFF1, 0xDEED, 1), 42), true},
	{"fully qualified 8-octet", "e4 f1 ff ed de ed fe 55 aa 2a", u(FullyQualifiedTag(0xFFF1, 0xDEED, 0xAA55FEED), 42), true},
	{"fq struct", "d5 f1 ff ed de 01 00 c4 f1 ff ed de 55 aa 2a 18",
		ctr(TypeStruct, FullyQualifiedTag(0xFFF1, 0xDEED, 1), u(FullyQualifiedTag(0xFFF1, 0xDEED, 0xAA55), 42)), true},
}

func TestSpecVectors(t *testing.T) {
	for _, tc := range specVectors {
		t.Run(tc.name, func(t *testing.T) {
			data := unhex(t, tc.hex)
			got, err := decodeAll(NewReader(data))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(got) != 1 || !reflect.DeepEqual(got[0], tc.want) {
				t.Fatalf("decode = %+v, want %+v", got, tc.want)
			}
			w := NewWriter(nil)
			encodeAll(w, []node{tc.want})
			if err := w.Err(); err != nil {
				t.Fatal(err)
			}
			if tc.minimal && !bytes.Equal(w.Bytes(), data) {
				t.Fatalf("encode = % x, want % x", w.Bytes(), data)
			}
		})
	}
}

func TestIntegerWidths(t *testing.T) {
	for _, v := range []int64{0, 127, -128, 128, -129, 32767, -32768, 32768, -32769,
		math.MaxInt32, math.MinInt32, math.MaxInt32 + 1, math.MinInt32 - 1, math.MaxInt64, math.MinInt64} {
		w := NewWriter(nil)
		w.PutInt(anon, v)
		r := NewReader(w.Bytes())
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if got, err := r.Int(); err != nil || got != v {
			t.Errorf("int %d: got %d, %v", v, got, err)
		}
	}
	for _, v := range []uint64{0, 255, 256, 65535, 65536, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64} {
		w := NewWriter(nil)
		w.PutUint(c1, v)
		r := NewReader(w.Bytes())
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if got, err := r.Uint(); err != nil || got != v {
			t.Errorf("uint %d: got %d, %v", v, got, err)
		}
	}
}

func TestRangeChecks(t *testing.T) {
	r := NewReader(unhex(t, "05 00 01")) // uint16 256
	r.Next()
	if _, err := r.Uint8(); err != ErrOverflow {
		t.Errorf("Uint8(256) err = %v", err)
	}
	if v, err := r.Uint16(); err != nil || v != 256 {
		t.Errorf("Uint16 = %d, %v", v, err)
	}
	if _, err := r.Int(); err != ErrType {
		t.Errorf("Int on uint err = %v", err)
	}
	r = NewReader(unhex(t, "01 00 ff")) // int16 -256
	r.Next()
	if _, err := r.Int8(); err != ErrOverflow {
		t.Errorf("Int8(-256) err = %v", err)
	}
	if v, err := r.Int16(); err != nil || v != -256 {
		t.Errorf("Int16 = %d, %v", v, err)
	}
}

func TestSkipAndRaw(t *testing.T) {
	// {1 = {0 = [1, 2], 1 = "x"}, 2 = 7}
	w := NewWriter(nil)
	w.StartStruct(anon)
	w.StartStruct(c1)
	w.StartArray(c0)
	w.PutUint(anon, 1)
	w.PutUint(anon, 2)
	w.EndContainer()
	w.PutString(c1, "x")
	w.EndContainer()
	w.PutUint(ContextTag(2), 7)
	w.EndContainer()
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(w.Bytes())
	r.Next()
	r.EnterContainer()
	r.Next() // 1 = {...}, not entered
	raw, err := r.RawElement()
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "35 01 36 00 04 01 04 02 18 2c 01 01 78 18"); !bytes.Equal(raw, want) {
		t.Fatalf("raw = % x, want % x", raw, want)
	}
	if err := r.Next(); err != nil { // skips the nested struct
		t.Fatal(err)
	}
	if !r.Tag().IsContext(2) {
		t.Fatalf("tag = %+v", r.Tag())
	}
	if v, _ := r.Uint(); v != 7 {
		t.Fatalf("v = %d", v)
	}
	if err := r.Next(); err != ErrEndOfContainer {
		t.Fatalf("err = %v", err)
	}
	if err := r.ExitContainer(); err != nil {
		t.Fatal(err)
	}
	if err := r.Next(); err != io.EOF {
		t.Fatalf("err = %v", err)
	}

	// ExitContainer from the middle of a partially read container.
	r = NewReader(w.Bytes())
	r.Next()
	r.EnterContainer()
	r.Next()
	r.EnterContainer()
	r.Next() // array, not entered
	if err := r.ExitContainer(); err != nil {
		t.Fatal(err)
	}
	r.Next()
	if v, _ := r.Uint(); v != 7 || r.Depth() != 1 {
		t.Fatalf("v = %d depth = %d", v, r.Depth())
	}

	// PutRaw re-embeds the raw element.
	w2 := NewWriter(nil)
	w2.StartStruct(anon)
	w2.PutRaw(raw)
	w2.EndContainer()
	if want := append(append([]byte{0x15}, raw...), 0x18); !bytes.Equal(w2.Bytes(), want) {
		t.Fatalf("PutRaw = % x", w2.Bytes())
	}
}

func TestMalformed(t *testing.T) {
	for _, tc := range []struct {
		hex  string
		want error
	}{
		{"18", ErrInvalid},                           // end of container at top level
		{"19", ErrInvalid},                           // reserved element type
		{"38", ErrInvalid},                           // end of container with a tag
		{"04", ErrTruncated},                         // missing value
		{"24", ErrTruncated},                         // missing tag
		{"0c 05 41", ErrTruncated},                   // string shorter than its length
		{"13 ff ff ff ff ff ff ff ff", ErrTruncated}, // 8-octet length overflow
		{"15 04 01", ErrTruncated},                   // unterminated struct
		{"15 15 18", ErrTruncated},                   // unterminated outer struct
	} {
		_, err := decodeAll(NewReader(unhex(t, tc.hex)))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.hex, err, tc.want)
		}
	}
}

func TestWriterMisuse(t *testing.T) {
	w := NewWriter(nil)
	w.EndContainer()
	if w.Err() == nil {
		t.Error("EndContainer without Start not reported")
	}
	w = NewWriter(nil)
	w.StartList(anon)
	if w.Err() == nil {
		t.Error("open container not reported")
	}
	w = NewWriter(nil)
	w.PutUint(Tag{Kind: TagContext, Number: 256}, 1)
	if w.Err() == nil {
		t.Error("context tag > 255 not reported")
	}
}

func TestZeroAllocRead(t *testing.T) {
	data := unhex(t, "15 20 00 2a 2c 01 02 68 69 18")
	r := NewReader(nil)
	allocs := testing.AllocsPerRun(100, func() {
		r.Reset(data)
		r.Next()
		r.EnterContainer()
		for r.Next() == nil {
		}
		r.ExitContainer()
	})
	if allocs != 0 {
		t.Errorf("reader allocates %v times per run", allocs)
	}
}

func FuzzRoundTrip(f *testing.F) {
	for _, tc := range specVectors {
		f.Add(unhex(f, tc.hex))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		nodes, err := decodeAll(NewReader(data))
		if err != nil {
			return
		}
		w := NewWriter(nil)
		encodeAll(w, nodes)
		if err := w.Err(); err != nil {
			t.Fatal(err)
		}
		again, err := decodeAll(NewReader(w.Bytes()))
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		// NaN != NaN breaks DeepEqual; compare encodings instead.
		w2 := NewWriter(nil)
		encodeAll(w2, again)
		if !bytes.Equal(w.Bytes(), w2.Bytes()) {
			t.Fatalf("unstable round trip:\n% x\n% x", w.Bytes(), w2.Bytes())
		}
	})
}
