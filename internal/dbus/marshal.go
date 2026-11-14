package dbus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
)

// ObjectPath is a D-Bus object path (type o).
type ObjectPath string

// Signature is a D-Bus type signature (type g).
type Signature string

// Variant is a value together with its type (type v).
type Variant struct {
	Sig   Signature
	Value any
}

// MakeVariant returns a variant of a string, bool, byte slice, string
// slice, integer or float64, with the matching signature.
func MakeVariant(v any) Variant {
	switch v.(type) {
	case string:
		return Variant{"s", v}
	case bool:
		return Variant{"b", v}
	case []byte:
		return Variant{"ay", v}
	case []string:
		return Variant{"as", v}
	case byte:
		return Variant{"y", v}
	case int16:
		return Variant{"n", v}
	case uint16:
		return Variant{"q", v}
	case int32:
		return Variant{"i", v}
	case uint32:
		return Variant{"u", v}
	case int64:
		return Variant{"x", v}
	case uint64:
		return Variant{"t", v}
	case float64:
		return Variant{"d", v}
	case ObjectPath:
		return Variant{"o", v}
	}
	panic(fmt.Sprintf("dbus: no variant signature for %T", v))
}

var errSignature = errors.New("dbus: bad signature")

const maxDepth = 32

// splitType splits the first complete type off a signature.
func splitType(sig string) (one, rest string, err error) {
	n, err := typeLen(sig, 0)
	if err != nil {
		return "", "", err
	}
	return sig[:n], sig[n:], nil
}

func typeLen(sig string, depth int) (int, error) {
	if sig == "" || depth > maxDepth {
		return 0, errSignature
	}
	switch sig[0] {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 'h', 's', 'o', 'g', 'v':
		return 1, nil
	case 'a':
		n, err := typeLen(sig[1:], depth+1)
		return n + 1, err
	case '(', '{':
		end := byte(')')
		if sig[0] == '{' {
			end = '}'
		}
		i, fields := 1, 0
		for i < len(sig) && sig[i] != end {
			n, err := typeLen(sig[i:], depth+1)
			if err != nil {
				return 0, err
			}
			i += n
			fields++
		}
		if i == len(sig) || fields == 0 || sig[0] == '{' && fields != 2 {
			return 0, errSignature
		}
		return i + 1, nil
	}
	return 0, errSignature
}

func alignment(c byte) int {
	switch c {
	case 'n', 'q':
		return 2
	case 'b', 'i', 'u', 'h', 's', 'o', 'a':
		return 4
	case 'x', 't', 'd', '(', '{':
		return 8
	}
	return 1 // y, g, v
}

// encoder appends little-endian D-Bus values; offsets are relative to the
// start of the message, which b starts at.
type encoder struct{ b []byte }

func (e *encoder) align(n int) {
	for len(e.b)%n != 0 {
		e.b = append(e.b, 0)
	}
}

func (e *encoder) u32(v uint32) {
	e.align(4)
	e.b = binary.LittleEndian.AppendUint32(e.b, v)
}

func (e *encoder) str(s string) {
	e.u32(uint32(len(s)))
	e.b = append(e.b, s...)
	e.b = append(e.b, 0)
}

func (e *encoder) sig(s string) {
	e.b = append(e.b, byte(len(s)))
	e.b = append(e.b, s...)
	e.b = append(e.b, 0)
}

// args encodes values for a whole signature.
func (e *encoder) args(sig string, vals []any) error {
	for i, v := range vals {
		one, rest, err := splitType(sig)
		if err != nil {
			return fmt.Errorf("dbus: argument %d: %w", i, err)
		}
		if err := e.value(one, v, 0); err != nil {
			return fmt.Errorf("dbus: argument %d (%s): %w", i, one, err)
		}
		sig = rest
	}
	if sig != "" {
		return fmt.Errorf("dbus: %d arguments for signature with more", len(vals))
	}
	return nil
}

func (e *encoder) value(sig string, v any, depth int) error {
	if depth > maxDepth {
		return errSignature
	}
	rv := reflect.ValueOf(v)
	switch sig[0] {
	case 'y':
		n, err := toUint(rv, math.MaxUint8)
		e.b = append(e.b, byte(n))
		return err
	case 'b':
		if rv.Kind() != reflect.Bool {
			return typeError(sig, v)
		}
		var n uint32
		if rv.Bool() {
			n = 1
		}
		e.u32(n)
	case 'n', 'q':
		var n uint64
		var err error
		if sig[0] == 'n' {
			var i int64
			i, err = toInt(rv, math.MinInt16, math.MaxInt16)
			n = uint64(i)
		} else {
			n, err = toUint(rv, math.MaxUint16)
		}
		e.align(2)
		e.b = binary.LittleEndian.AppendUint16(e.b, uint16(n))
		return err
	case 'i':
		i, err := toInt(rv, math.MinInt32, math.MaxInt32)
		e.u32(uint32(i))
		return err
	case 'u', 'h':
		n, err := toUint(rv, math.MaxUint32)
		e.u32(uint32(n))
		return err
	case 'x':
		i, err := toInt(rv, math.MinInt64, math.MaxInt64)
		e.align(8)
		e.b = binary.LittleEndian.AppendUint64(e.b, uint64(i))
		return err
	case 't':
		n, err := toUint(rv, math.MaxUint64)
		e.align(8)
		e.b = binary.LittleEndian.AppendUint64(e.b, n)
		return err
	case 'd':
		if rv.Kind() != reflect.Float64 && rv.Kind() != reflect.Float32 {
			return typeError(sig, v)
		}
		e.align(8)
		e.b = binary.LittleEndian.AppendUint64(e.b, math.Float64bits(rv.Float()))
	case 's', 'o':
		if rv.Kind() != reflect.String {
			return typeError(sig, v)
		}
		e.str(rv.String())
	case 'g':
		if rv.Kind() != reflect.String || rv.Len() > 255 {
			return typeError(sig, v)
		}
		e.sig(rv.String())
	case 'v':
		vv, ok := v.(Variant)
		if !ok {
			return typeError(sig, v)
		}
		one, rest, err := splitType(string(vv.Sig))
		if err != nil || rest != "" {
			return errSignature
		}
		e.sig(one)
		return e.value(one, vv.Value, depth+1)
	case '(':
		fields, ok := v.([]any)
		if !ok {
			return typeError(sig, v)
		}
		e.align(8)
		inner := sig[1 : len(sig)-1]
		for _, f := range fields {
			one, rest, err := splitType(inner)
			if err != nil {
				return fmt.Errorf("dbus: %d fields for %s", len(fields), sig)
			}
			if err := e.value(one, f, depth+1); err != nil {
				return err
			}
			inner = rest
		}
		if inner != "" {
			return fmt.Errorf("dbus: %d fields for %s", len(fields), sig)
		}
	case 'a':
		return e.array(sig[1:], v, rv, depth)
	default:
		return errSignature
	}
	return nil
}

func (e *encoder) array(elem string, v any, rv reflect.Value, depth int) error {
	e.u32(0)
	lenAt := len(e.b) - 4
	e.align(alignment(elem[0])) // padding before the first element is not counted
	start := len(e.b)
	switch {
	case elem == "y" && rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() == reflect.Uint8:
		e.b = append(e.b, rv.Bytes()...)
	case elem[0] == '{':
		if rv.Kind() != reflect.Map {
			return typeError("a"+elem, v)
		}
		kt, rest, err := splitType(elem[1 : len(elem)-1])
		if err != nil {
			return err
		}
		keys := rv.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			e.align(8)
			if err := e.value(kt, k.Interface(), depth+1); err != nil {
				return err
			}
			if err := e.value(rest, rv.MapIndex(k).Interface(), depth+1); err != nil {
				return err
			}
		}
	default:
		if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
			return typeError("a"+elem, v)
		}
		for i := range rv.Len() {
			if err := e.value(elem, rv.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}
	}
	n := len(e.b) - start
	if n > 1<<26 {
		return errors.New("dbus: array too long")
	}
	binary.LittleEndian.PutUint32(e.b[lenAt:], uint32(n))
	return nil
}

func typeError(sig string, v any) error { return fmt.Errorf("dbus: cannot encode %T as %s", v, sig) }

func toUint(rv reflect.Value, max uint64) (uint64, error) {
	switch rv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if rv.Uint() <= max {
			return rv.Uint(), nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if rv.Int() >= 0 && uint64(rv.Int()) <= max {
			return uint64(rv.Int()), nil
		}
	}
	return 0, fmt.Errorf("dbus: %v is not an unsigned integer up to %d", rv, max)
}

func toInt(rv reflect.Value, min, max int64) (int64, error) {
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if rv.Int() >= min && rv.Int() <= max {
			return rv.Int(), nil
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if rv.Uint() <= uint64(max) {
			return int64(rv.Uint()), nil
		}
	}
	return 0, fmt.Errorf("dbus: %v is not an integer in [%d, %d]", rv, min, max)
}

// decoder reads D-Bus values; off is relative to the start of the message.
type decoder struct {
	b     []byte
	off   int
	order binary.ByteOrder
}

var errShort = errors.New("dbus: truncated message")

func (d *decoder) align(n int) error {
	pad := (n - d.off%n) % n
	if d.off+pad > len(d.b) {
		return errShort
	}
	d.off += pad
	return nil
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || d.off+n > len(d.b) {
		return nil, errShort
	}
	b := d.b[d.off : d.off+n]
	d.off += n
	return b, nil
}

func (d *decoder) u32() (uint32, error) {
	if err := d.align(4); err != nil {
		return 0, err
	}
	b, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return d.order.Uint32(b), nil
}

func (d *decoder) str() (string, error) {
	n, err := d.u32()
	if err != nil {
		return "", err
	}
	b, err := d.take(int(n) + 1)
	if err != nil {
		return "", err
	}
	return string(b[:n]), nil
}

func (d *decoder) sig() (string, error) {
	n, err := d.take(1)
	if err != nil {
		return "", err
	}
	b, err := d.take(int(n[0]) + 1)
	if err != nil {
		return "", err
	}
	return string(b[:n[0]]), nil
}

// args decodes the values of a whole signature.
func (d *decoder) args(sig string) ([]any, error) {
	var out []any
	for sig != "" {
		one, rest, err := splitType(sig)
		if err != nil {
			return nil, err
		}
		v, err := d.value(one, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		sig = rest
	}
	return out, nil
}

// value decodes one complete type. Arrays of bytes become []byte, other
// arrays []any, dictionaries map[string]any (string, object path or
// signature keys) or map[any]any, structures []any and variants Variant.
func (d *decoder) value(sig string, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errSignature
	}
	switch sig[0] {
	case 'y':
		b, err := d.take(1)
		if err != nil {
			return nil, err
		}
		return b[0], nil
	case 'b':
		n, err := d.u32()
		if err != nil {
			return nil, err
		}
		if n > 1 {
			return nil, errors.New("dbus: bad boolean")
		}
		return n == 1, nil
	case 'n', 'q':
		if err := d.align(2); err != nil {
			return nil, err
		}
		b, err := d.take(2)
		if err != nil {
			return nil, err
		}
		if sig[0] == 'n' {
			return int16(d.order.Uint16(b)), nil
		}
		return d.order.Uint16(b), nil
	case 'i':
		n, err := d.u32()
		return int32(n), err
	case 'u', 'h':
		return d.u32()
	case 'x', 't', 'd':
		if err := d.align(8); err != nil {
			return nil, err
		}
		b, err := d.take(8)
		if err != nil {
			return nil, err
		}
		n := d.order.Uint64(b)
		switch sig[0] {
		case 'x':
			return int64(n), nil
		case 'd':
			return math.Float64frombits(n), nil
		}
		return n, nil
	case 's':
		return d.str()
	case 'o':
		s, err := d.str()
		return ObjectPath(s), err
	case 'g':
		s, err := d.sig()
		return Signature(s), err
	case 'v':
		s, err := d.sig()
		if err != nil {
			return nil, err
		}
		one, rest, err := splitType(s)
		if err != nil || rest != "" {
			return nil, errSignature
		}
		v, err := d.value(one, depth+1)
		return Variant{Signature(one), v}, err
	case '(':
		if err := d.align(8); err != nil {
			return nil, err
		}
		var fields []any
		inner := sig[1 : len(sig)-1]
		for inner != "" {
			one, rest, err := splitType(inner)
			if err != nil {
				return nil, err
			}
			f, err := d.value(one, depth+1)
			if err != nil {
				return nil, err
			}
			fields = append(fields, f)
			inner = rest
		}
		return fields, nil
	case 'a':
		return d.array(sig[1:], depth)
	}
	return nil, errSignature
}

func (d *decoder) array(elem string, depth int) (any, error) {
	n, err := d.u32()
	if err != nil {
		return nil, err
	}
	if err := d.align(alignment(elem[0])); err != nil {
		return nil, err
	}
	if n > 1<<26 || d.off+int(n) > len(d.b) {
		return nil, errShort
	}
	end := d.off + int(n)
	if elem == "y" {
		b, _ := d.take(int(n))
		return append([]byte(nil), b...), nil
	}
	if elem[0] == '{' {
		kt, vt, err := splitType(elem[1 : len(elem)-1])
		if err != nil {
			return nil, err
		}
		stringKeys := kt == "s" || kt == "o" || kt == "g"
		sm, am := map[string]any{}, map[any]any{}
		for d.off < end {
			if err := d.align(8); err != nil {
				return nil, err
			}
			k, err := d.value(kt, depth+1)
			if err != nil {
				return nil, err
			}
			v, err := d.value(vt, depth+1)
			if err != nil {
				return nil, err
			}
			if stringKeys {
				sm[fmt.Sprint(k)] = v
			} else {
				am[k] = v
			}
		}
		if d.off != end {
			return nil, errors.New("dbus: array length mismatch")
		}
		if stringKeys {
			return sm, nil
		}
		return am, nil
	}
	var out []any
	for d.off < end {
		v, err := d.value(elem, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if d.off != end {
		return nil, errors.New("dbus: array length mismatch")
	}
	return out, nil
}
