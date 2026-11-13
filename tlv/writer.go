package tlv

import (
	"encoding/binary"
	"errors"
	"math"
)

// Writer appends TLV elements to a byte slice. Integers are written in their
// shortest form. A Writer never fails on input values; misuse of containers is
// reported by Err.
type Writer struct {
	buf   []byte
	depth int
	err   error
}

// NewWriter returns a Writer that appends to buf. Pass buf[:0] of a
// preallocated slice to encode without allocating.
func NewWriter(buf []byte) *Writer { return &Writer{buf: buf} }

// Reset discards the writer state and starts appending to buf.
func (w *Writer) Reset(buf []byte) { *w = Writer{buf: buf} }

// Bytes returns the encoded data.
func (w *Writer) Bytes() []byte { return w.buf }

// Len returns the number of encoded bytes.
func (w *Writer) Len() int { return len(w.buf) }

// Depth returns the number of open containers.
func (w *Writer) Depth() int { return w.depth }

// Err returns the first container misuse error, if any, including containers
// left open.
func (w *Writer) Err() error {
	if w.err == nil && w.depth != 0 {
		return errors.New("tlv: unterminated container")
	}
	return w.err
}

func (w *Writer) header(tag Tag, elem byte) {
	switch tag.Kind {
	case TagAnonymous:
		w.buf = append(w.buf, elem)
	case TagContext:
		if tag.Number > 0xFF {
			w.fail(errors.New("tlv: context tag number exceeds 255"))
		}
		w.buf = append(w.buf, 0x20|elem, byte(tag.Number))
	case TagCommonProfile, TagImplicitProfile:
		ctl := byte(tag.Kind) << 5 // 0x40 / 0x80: 2-octet forms
		if tag.Number <= 0xFFFF {
			w.buf = append(w.buf, ctl|elem)
			w.buf = binary.LittleEndian.AppendUint16(w.buf, uint16(tag.Number))
		} else {
			w.buf = append(w.buf, ctl|0x20|elem) // 0x60 / 0xA0: 4-octet forms
			w.buf = binary.LittleEndian.AppendUint32(w.buf, tag.Number)
		}
	case TagFullyQualified:
		if tag.Number <= 0xFFFF {
			w.buf = append(w.buf, 0xC0|elem)
		} else {
			w.buf = append(w.buf, 0xE0|elem)
		}
		w.buf = binary.LittleEndian.AppendUint16(w.buf, tag.Vendor)
		w.buf = binary.LittleEndian.AppendUint16(w.buf, tag.Profile)
		if tag.Number <= 0xFFFF {
			w.buf = binary.LittleEndian.AppendUint16(w.buf, uint16(tag.Number))
		} else {
			w.buf = binary.LittleEndian.AppendUint32(w.buf, tag.Number)
		}
	default:
		w.fail(errors.New("tlv: invalid tag kind"))
	}
}

func (w *Writer) fail(err error) {
	if w.err == nil {
		w.err = err
	}
}

// PutUint writes an unsigned integer.
func (w *Writer) PutUint(tag Tag, v uint64) {
	switch {
	case v <= math.MaxUint8:
		w.header(tag, elemUint8)
		w.buf = append(w.buf, byte(v))
	case v <= math.MaxUint16:
		w.header(tag, elemUint16)
		w.buf = binary.LittleEndian.AppendUint16(w.buf, uint16(v))
	case v <= math.MaxUint32:
		w.header(tag, elemUint32)
		w.buf = binary.LittleEndian.AppendUint32(w.buf, uint32(v))
	default:
		w.header(tag, elemUint64)
		w.buf = binary.LittleEndian.AppendUint64(w.buf, v)
	}
}

// PutInt writes a signed integer.
func (w *Writer) PutInt(tag Tag, v int64) {
	switch {
	case v >= math.MinInt8 && v <= math.MaxInt8:
		w.header(tag, elemInt8)
		w.buf = append(w.buf, byte(v))
	case v >= math.MinInt16 && v <= math.MaxInt16:
		w.header(tag, elemInt16)
		w.buf = binary.LittleEndian.AppendUint16(w.buf, uint16(v))
	case v >= math.MinInt32 && v <= math.MaxInt32:
		w.header(tag, elemInt32)
		w.buf = binary.LittleEndian.AppendUint32(w.buf, uint32(v))
	default:
		w.header(tag, elemInt64)
		w.buf = binary.LittleEndian.AppendUint64(w.buf, uint64(v))
	}
}

// PutBool writes a boolean.
func (w *Writer) PutBool(tag Tag, v bool) {
	if v {
		w.header(tag, elemTrue)
	} else {
		w.header(tag, elemFalse)
	}
}

// PutFloat32 writes a single-precision float.
func (w *Writer) PutFloat32(tag Tag, v float32) {
	w.header(tag, elemFloat32)
	w.buf = binary.LittleEndian.AppendUint32(w.buf, math.Float32bits(v))
}

// PutFloat64 writes a double-precision float.
func (w *Writer) PutFloat64(tag Tag, v float64) {
	w.header(tag, elemFloat64)
	w.buf = binary.LittleEndian.AppendUint64(w.buf, math.Float64bits(v))
}

func (w *Writer) putLen(tag Tag, base byte, n int) {
	switch {
	case n <= math.MaxUint8:
		w.header(tag, base)
		w.buf = append(w.buf, byte(n))
	case n <= math.MaxUint16:
		w.header(tag, base+1)
		w.buf = binary.LittleEndian.AppendUint16(w.buf, uint16(n))
	default:
		// A slice length always fits in 32 bits on the targets we care about,
		// and Matter messages are far smaller.
		w.header(tag, base+2)
		w.buf = binary.LittleEndian.AppendUint32(w.buf, uint32(n))
	}
}

// PutString writes a UTF-8 string. The caller is responsible for s being
// valid UTF-8.
func (w *Writer) PutString(tag Tag, s string) {
	w.putLen(tag, elemUTF8_1, len(s))
	w.buf = append(w.buf, s...)
}

// PutBytes writes an octet string.
func (w *Writer) PutBytes(tag Tag, b []byte) {
	w.putLen(tag, elemBytes1, len(b))
	w.buf = append(w.buf, b...)
}

// PutNull writes a null.
func (w *Writer) PutNull(tag Tag) { w.header(tag, elemNull) }

// StartStruct opens a structure; close it with EndContainer.
func (w *Writer) StartStruct(tag Tag) { w.start(tag, elemStruct) }

// StartArray opens an array; close it with EndContainer.
func (w *Writer) StartArray(tag Tag) { w.start(tag, elemArray) }

// StartList opens a list; close it with EndContainer.
func (w *Writer) StartList(tag Tag) { w.start(tag, elemList) }

func (w *Writer) start(tag Tag, elem byte) {
	w.header(tag, elem)
	w.depth++
}

// EndContainer closes the innermost open container.
func (w *Writer) EndContainer() {
	if w.depth == 0 {
		w.fail(errors.New("tlv: EndContainer without open container"))
		return
	}
	w.depth--
	w.buf = append(w.buf, elemEndOfContainer)
}

// PutRaw appends an already encoded element verbatim, such as one returned by
// Reader.RawElement. The element's own tag is kept.
func (w *Writer) PutRaw(elem []byte) { w.buf = append(w.buf, elem...) }

// Checkpoint is a writer position to roll back to.
type Checkpoint struct{ n, depth int }

// Checkpoint returns the current position.
func (w *Writer) Checkpoint() Checkpoint { return Checkpoint{len(w.buf), w.depth} }

// Rollback discards everything written since c.
func (w *Writer) Rollback(c Checkpoint) { w.buf, w.depth = w.buf[:c.n], c.depth }
