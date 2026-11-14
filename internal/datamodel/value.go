package datamodel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/shabunin/tiny-matter-go/tlv"
)

// Format formats a TLV element as a value of field f (nil: of unknown
// type). Struct fields, enum values and bitmap bits are named.
func Format(data []byte, f *Field) string {
	r := tlv.NewReader(data)
	if err := r.Next(); err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	var b strings.Builder
	if f == nil {
		formatValue(&b, r, nil, false)
	} else {
		formatValue(&b, r, f.Type, f.List)
	}
	return b.String()
}

// FormatFields formats the fields structure of a command or event.
func FormatFields(data []byte, fields []*Field) string {
	return Format(data, &Field{Type: &Type{Kind: KindStruct, Fields: fields}})
}

func formatValue(b *strings.Builder, r *tlv.Reader, t *Type, list bool) {
	if r.IsNull() {
		b.WriteString("null")
		return
	}
	typ := r.Type()
	if list && (typ == tlv.TypeArray || typ == tlv.TypeList) {
		formatContainer(b, r, "[", "]", func(r *tlv.Reader) {
			formatValue(b, r, t, false)
		})
		return
	}
	switch {
	case t == nil:
	case t.Kind == KindStruct && typ == tlv.TypeStruct:
		formatContainer(b, r, "{", "}", func(r *tlv.Reader) {
			var f *Field
			if r.Tag().Kind == tlv.TagContext {
				for _, sf := range t.Fields {
					if sf.ID == r.Tag().Number {
						f = sf
					}
				}
			}
			if f == nil {
				b.WriteString(tagString(r.Tag()))
				b.WriteString(": ")
				formatValue(b, r, nil, false)
				return
			}
			b.WriteString(f.Name)
			b.WriteString(": ")
			formatValue(b, r, f.Type, f.List)
		})
		return
	case t.Kind == KindEnum && typ == tlv.TypeUint:
		v, _ := r.Uint()
		b.WriteString(strconv.FormatUint(v, 10))
		for _, it := range t.Items {
			if it.Value == v {
				b.WriteString(" (" + it.Name + ")")
				break
			}
		}
		return
	case t.Kind == KindBitmap && typ == tlv.TypeUint:
		v, _ := r.Uint()
		fmt.Fprintf(b, "%#x", v)
		var names []string
		rest := v
		for _, it := range t.Items {
			if it.Value != 0 && v&it.Value == it.Value {
				names = append(names, it.Name)
				rest &^= it.Value
			}
		}
		if rest != 0 && len(names) > 0 {
			names = append(names, fmt.Sprintf("%#x", rest))
		}
		if len(names) > 0 {
			b.WriteString(" (" + strings.Join(names, "|") + ")")
		}
		return
	}
	switch typ {
	case tlv.TypeUint:
		v, _ := r.Uint()
		if t != nil && hexType(t.Name) {
			fmt.Fprintf(b, "%#x", v)
		} else {
			b.WriteString(strconv.FormatUint(v, 10))
		}
	case tlv.TypeInt:
		v, _ := r.Int()
		b.WriteString(strconv.FormatInt(v, 10))
	case tlv.TypeBool:
		v, _ := r.Bool()
		b.WriteString(strconv.FormatBool(v))
	case tlv.TypeFloat32:
		v, _ := r.Float()
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 32))
	case tlv.TypeFloat64:
		v, _ := r.Float()
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	case tlv.TypeUTF8:
		v, _ := r.String()
		b.WriteString(strconv.Quote(v))
	case tlv.TypeBytes:
		v, _ := r.Bytes()
		b.WriteString("hex:" + hex.EncodeToString(v))
	case tlv.TypeStruct:
		formatContainer(b, r, "{", "}", func(r *tlv.Reader) {
			b.WriteString(tagString(r.Tag()) + ": ")
			formatValue(b, r, nil, false)
		})
	case tlv.TypeArray, tlv.TypeList:
		formatContainer(b, r, "[", "]", func(r *tlv.Reader) {
			if r.Tag().Kind != tlv.TagAnonymous {
				b.WriteString(tagString(r.Tag()) + ": ")
			}
			formatValue(b, r, nil, false)
		})
	default:
		b.WriteString("?")
	}
}

func formatContainer(b *strings.Builder, r *tlv.Reader, open, close string, elem func(r *tlv.Reader)) {
	b.WriteString(open)
	if err := r.EnterContainer(); err != nil {
		b.WriteString("<" + err.Error() + ">" + close)
		return
	}
	for i := 0; ; i++ {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			b.WriteString("<" + err.Error() + ">")
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		elem(r)
	}
	r.ExitContainer()
	b.WriteString(close)
}

func tagString(t tlv.Tag) string {
	switch t.Kind {
	case tlv.TagAnonymous:
		return "_"
	case tlv.TagContext:
		return strconv.FormatUint(uint64(t.Number), 10)
	case tlv.TagFullyQualified:
		return fmt.Sprintf("%#04x:%#04x:%d", t.Vendor, t.Profile, t.Number)
	}
	return fmt.Sprintf("profile:%d", t.Number)
}

// hexType reports whether values of a primitive read best in hex.
func hexType(name string) bool {
	switch name {
	case "vendor_id", "cluster_id", "attrib_id", "command_id", "event_id", "devtype_id", "field_id", "fabric_id", "node_id",
		"bitmap8", "bitmap16", "bitmap32", "bitmap64":
		return true
	}
	return false
}

// Encode writes value s, as written by a person, as field f with the
// given tag. Scalars are written plainly: 42, 0x2a, -1, true, on, 1.5,
// text, an enum or bitmap item name (bitmaps joined with |), hex for
// octet strings, null. Lists and structs are JSON, with struct fields
// named or numbered. With f nil the type is guessed: a number, true or
// false, null, "hex:..." for bytes, JSON for containers, or a string.
func Encode(w *tlv.Writer, tag tlv.Tag, f *Field, s string) error {
	if f == nil {
		return encodeGuess(w, tag, s)
	}
	if f.List || f.Type.Kind == KindStruct {
		v, err := decodeJSON(s)
		if err != nil {
			return fmt.Errorf("%s: want JSON: %v", f.Name, err)
		}
		return encodeJSON(w, tag, f.Type, f.List, v)
	}
	if s == "null" {
		w.PutNull(tag)
		return nil
	}
	return encodeScalar(w, tag, f.Type, s)
}

func decodeJSON(s string) (any, error) {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

func encodeGuess(w *tlv.Writer, tag tlv.Tag, s string) error {
	switch {
	case s == "null":
		w.PutNull(tag)
	case s == "true" || s == "false":
		w.PutBool(tag, s == "true")
	case strings.HasPrefix(s, "hex:"):
		b, err := hex.DecodeString(s[4:])
		if err != nil {
			return err
		}
		w.PutBytes(tag, b)
	case strings.HasPrefix(s, "[") || strings.HasPrefix(s, "{"):
		v, err := decodeJSON(s)
		if err != nil {
			return err
		}
		return encodeJSON(w, tag, nil, false, v)
	default:
		if u, err := parseUint(s); err == nil {
			w.PutUint(tag, u)
		} else if i, err := parseInt(s); err == nil {
			w.PutInt(tag, i)
		} else if f, err := strconv.ParseFloat(s, 64); err == nil {
			w.PutFloat64(tag, f)
		} else {
			w.PutString(tag, s)
		}
	}
	return nil
}

func encodeScalar(w *tlv.Writer, tag tlv.Tag, t *Type, s string) error {
	switch t.Kind {
	case KindBool:
		switch strings.ToLower(s) {
		case "true", "1", "on", "yes":
			w.PutBool(tag, true)
		case "false", "0", "off", "no":
			w.PutBool(tag, false)
		default:
			return fmt.Errorf("%q is not a boolean", s)
		}
	case KindUint, KindEnum:
		v, err := parseUint(s)
		if err != nil {
			it, ok := t.Item(s)
			if !ok {
				return fmt.Errorf("%q is not a number%s", s, itemsHint(t))
			}
			v = it.Value
		}
		w.PutUint(tag, v)
	case KindBitmap:
		var v uint64
		for _, part := range strings.Split(s, "|") {
			part = strings.TrimSpace(part)
			if n, err := parseUint(part); err == nil {
				v |= n
			} else if it, ok := t.Item(part); ok {
				v |= it.Value
			} else {
				return fmt.Errorf("%q is not a number or bit%s", part, itemsHint(t))
			}
		}
		w.PutUint(tag, v)
	case KindInt:
		v, err := parseInt(s)
		if err != nil {
			return fmt.Errorf("%q is not an integer", s)
		}
		w.PutInt(tag, v)
	case KindFloat, KindDouble:
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("%q is not a number", s)
		}
		if t.Kind == KindFloat {
			w.PutFloat32(tag, float32(v))
		} else {
			w.PutFloat64(tag, v)
		}
	case KindString:
		w.PutString(tag, s)
	case KindBytes:
		b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "hex:"), "0x"))
		if err != nil {
			return fmt.Errorf("%q is not hex", s)
		}
		w.PutBytes(tag, b)
	default:
		return encodeGuess(w, tag, s)
	}
	return nil
}

func itemsHint(t *Type) string {
	if len(t.Items) == 0 {
		return ""
	}
	names := make([]string, len(t.Items))
	for i, it := range t.Items {
		names[i] = it.Name
	}
	return " or one of " + strings.Join(names, ", ")
}

// encodeJSON writes a JSON value as type t (nil: guessed).
func encodeJSON(w *tlv.Writer, tag tlv.Tag, t *Type, list bool, v any) error {
	if v == nil {
		w.PutNull(tag)
		return nil
	}
	if list {
		items, ok := v.([]any)
		if !ok {
			return fmt.Errorf("want a list, have %v", v)
		}
		w.StartArray(tag)
		for _, it := range items {
			if err := encodeJSON(w, tlv.Anonymous, t, false, it); err != nil {
				return err
			}
		}
		w.EndContainer()
		return nil
	}
	switch v := v.(type) {
	case map[string]any:
		if t != nil && t.Kind != KindStruct {
			return fmt.Errorf("want a %s, have a struct", t.Name)
		}
		type member struct {
			id    uint32
			f     *Field
			value any
		}
		var ms []member
		for k, val := range v {
			var f *Field
			var id uint64
			if t != nil {
				if f = t.Field(k); f == nil {
					return fmt.Errorf("%s has no field %q", t.Name, k)
				}
				id = uint64(f.ID)
			} else {
				var err error
				if id, err = parseUint(k); err != nil || id > math.MaxUint8 {
					return fmt.Errorf("struct field %q: want a number", k)
				}
			}
			ms = append(ms, member{uint32(id), f, val})
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].id < ms[j].id })
		w.StartStruct(tag)
		for _, m := range ms {
			var err error
			if m.f != nil {
				err = encodeJSON(w, tlv.ContextTag(uint8(m.id)), m.f.Type, m.f.List, m.value)
			} else {
				err = encodeJSON(w, tlv.ContextTag(uint8(m.id)), nil, false, m.value)
			}
			if err != nil {
				return err
			}
		}
		w.EndContainer()
		return nil
	case []any:
		if t != nil {
			return fmt.Errorf("want a %s, have a list", t.Name)
		}
		return encodeJSON(w, tag, nil, true, v)
	case json.Number:
		if t != nil {
			return encodeScalar(w, tag, t, v.String())
		}
		return encodeGuess(w, tag, v.String())
	case bool:
		if t != nil && t.Kind != KindBool {
			return fmt.Errorf("want a %s, have a boolean", t.Name)
		}
		w.PutBool(tag, v)
		return nil
	case string:
		if t == nil {
			if b, ok := strings.CutPrefix(v, "hex:"); ok {
				raw, err := hex.DecodeString(b)
				if err != nil {
					return err
				}
				w.PutBytes(tag, raw)
			} else {
				w.PutString(tag, v)
			}
			return nil
		}
		return encodeScalar(w, tag, t, v)
	}
	return fmt.Errorf("unsupported value %v", v)
}

// EncodeFields writes command fields from arguments: name=value pairs,
// or values in field order. It reports mandatory fields left out.
func EncodeFields(w *tlv.Writer, req *Type, args []string) error {
	values := map[uint32]string{}
	var fields []*Field
	if req != nil {
		fields = req.Fields
	}
	next := 0
	for _, a := range args {
		name, value, named := strings.Cut(a, "=")
		var f *Field
		switch {
		case named && req != nil:
			if f = req.Field(name); f == nil {
				return fmt.Errorf("no field %q; fields: %s", name, fieldList(fields))
			}
		case named:
			id, err := parseUint(name)
			if err != nil || id > math.MaxUint8 {
				return fmt.Errorf("field %q: want a field number", name)
			}
			values[uint32(id)] = value
			continue
		default:
			if next >= len(fields) {
				return fmt.Errorf("too many values; fields: %s", fieldList(fields))
			}
			f, value = fields[next], a
			next++
		}
		if _, dup := values[f.ID]; dup {
			return fmt.Errorf("field %s given twice", f.Name)
		}
		values[f.ID] = value
	}
	var missing []string
	for _, f := range fields {
		if _, ok := values[f.ID]; !ok && !f.Optional {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s; fields: %s", strings.Join(missing, ", "), fieldList(fields))
	}
	ids := make([]uint32, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if id > math.MaxUint8 {
			return fmt.Errorf("field number %d out of range", id)
		}
		var f *Field
		if req != nil {
			for _, rf := range fields {
				if rf.ID == id {
					f = rf
				}
			}
		}
		if err := Encode(w, tlv.ContextTag(uint8(id)), f, values[id]); err != nil {
			if f != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
			return err
		}
	}
	return nil
}

func fieldList(fields []*Field) string {
	if len(fields) == 0 {
		return "none"
	}
	var b bytes.Buffer
	for i, f := range fields {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(f.Name + " " + f.TypeString())
	}
	return b.String()
}

// parseUint parses a decimal or 0x-prefixed hexadecimal number.
func parseUint(s string) (uint64, error) {
	if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		return strconv.ParseUint(h, 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// parseInt parses a signed decimal or 0x-prefixed hexadecimal number.
func parseInt(s string) (int64, error) {
	neg := strings.HasPrefix(s, "-")
	u, err := parseUint(strings.TrimPrefix(s, "-"))
	if err != nil || u > math.MaxInt64+uint64(btoi(neg)) {
		return 0, strconv.ErrSyntax
	}
	if neg {
		return -int64(u-1) - 1, nil
	}
	return int64(u), nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
