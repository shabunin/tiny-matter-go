package tlv

import (
	"encoding/binary"
	"io"
	"math"
)

// Reader decodes TLV from a byte slice without copying.
//
// Typical use:
//
//	r := tlv.NewReader(data)
//	if err := r.Next(); err != nil { ... }         // the outer struct
//	if err := r.EnterContainer(); err != nil { ... }
//	for {
//		err := r.Next()
//		if err == tlv.ErrEndOfContainer { break }
//		if err != nil { ... }
//		switch {
//		case r.Tag().IsContext(1): v, err := r.Uint()
//		...
//		}
//	}
//	err = r.ExitContainer()
//
// Next skips over containers the caller did not enter. At the top level, Next
// returns io.EOF when the input is exhausted.
type Reader struct {
	buf   []byte
	pos   int // offset of the next unread octet
	depth int

	// Current element.
	has   bool
	start int // offset of the current element's control octet
	typ   Type
	tag   Tag
	num   uint64 // integer value, bool (0/1) or float bits
	val   []byte // string payload

	pendingSkip bool // current element is a container that was not entered
}

// NewReader returns a Reader over b.
func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Reset makes the reader decode b from the beginning.
func (r *Reader) Reset(b []byte) { *r = Reader{buf: b} }

// Depth returns the number of entered containers.
func (r *Reader) Depth() int { return r.depth }

// Remaining returns the input after the current position.
func (r *Reader) Remaining() []byte { return r.buf[r.pos:] }

// Type returns the type of the current element.
func (r *Reader) Type() Type { return r.typ }

// Tag returns the tag of the current element.
func (r *Reader) Tag() Tag { return r.tag }

// Next advances to the next element in the current container. It returns
// ErrEndOfContainer when the container has no more elements, and io.EOF at
// the end of top-level input.
func (r *Reader) Next() error {
	if r.pendingSkip {
		end, err := skipContainerBody(r.buf, r.pos)
		if err != nil {
			r.has = false
			return err
		}
		r.pos = end
		r.pendingSkip = false
	}
	r.has = false
	if r.pos >= len(r.buf) {
		if r.depth == 0 {
			return io.EOF
		}
		return ErrTruncated
	}
	if r.buf[r.pos] == elemEndOfContainer {
		if r.depth == 0 {
			return ErrInvalid
		}
		return ErrEndOfContainer
	}
	e, next, err := parseElement(r.buf, r.pos)
	if err != nil {
		return err
	}
	r.start = r.pos
	r.pos = next
	r.has = true
	r.typ, r.tag, r.num, r.val = e.typ, e.tag, e.num, e.val
	r.pendingSkip = e.typ.IsContainer()
	return nil
}

// EnterContainer descends into the current element, which must be a
// container that has not been skipped.
func (r *Reader) EnterContainer() error {
	if !r.has || !r.pendingSkip {
		return ErrNotContainer
	}
	r.pendingSkip = false
	r.has = false
	r.depth++
	return nil
}

// ExitContainer skips any remaining elements of the innermost entered
// container and moves past its end.
func (r *Reader) ExitContainer() error {
	if r.depth == 0 {
		return ErrNotContainer
	}
	for {
		err := r.Next()
		if err == ErrEndOfContainer {
			break
		}
		if err != nil {
			return err
		}
	}
	r.pos++ // the end-of-container octet
	r.depth--
	r.has = false
	return nil
}

// RawElement returns the complete encoding of the current element, including
// its tag and, for containers, all contents. It does not move the reader.
func (r *Reader) RawElement() ([]byte, error) {
	if !r.has {
		return nil, ErrNoElement
	}
	if !r.pendingSkip {
		return r.buf[r.start:r.pos], nil
	}
	end, err := skipContainerBody(r.buf, r.pos)
	if err != nil {
		return nil, err
	}
	return r.buf[r.start:end], nil
}

// Uint returns the current unsigned integer.
func (r *Reader) Uint() (uint64, error) {
	if !r.has {
		return 0, ErrNoElement
	}
	if r.typ != TypeUint {
		return 0, ErrType
	}
	return r.num, nil
}

// Int returns the current signed integer.
func (r *Reader) Int() (int64, error) {
	if !r.has {
		return 0, ErrNoElement
	}
	if r.typ != TypeInt {
		return 0, ErrType
	}
	return int64(r.num), nil
}

// Uint8 returns the current unsigned integer, which must fit in 8 bits.
func (r *Reader) Uint8() (uint8, error) {
	v, err := r.uintMax(math.MaxUint8)
	return uint8(v), err
}

// Uint16 returns the current unsigned integer, which must fit in 16 bits.
func (r *Reader) Uint16() (uint16, error) {
	v, err := r.uintMax(math.MaxUint16)
	return uint16(v), err
}

// Uint32 returns the current unsigned integer, which must fit in 32 bits.
func (r *Reader) Uint32() (uint32, error) {
	v, err := r.uintMax(math.MaxUint32)
	return uint32(v), err
}

func (r *Reader) uintMax(max uint64) (uint64, error) {
	v, err := r.Uint()
	if err == nil && v > max {
		err = ErrOverflow
	}
	return v, err
}

// Int8 returns the current signed integer, which must fit in 8 bits.
func (r *Reader) Int8() (int8, error) {
	v, err := r.intRange(math.MinInt8, math.MaxInt8)
	return int8(v), err
}

// Int16 returns the current signed integer, which must fit in 16 bits.
func (r *Reader) Int16() (int16, error) {
	v, err := r.intRange(math.MinInt16, math.MaxInt16)
	return int16(v), err
}

// Int32 returns the current signed integer, which must fit in 32 bits.
func (r *Reader) Int32() (int32, error) {
	v, err := r.intRange(math.MinInt32, math.MaxInt32)
	return int32(v), err
}

func (r *Reader) intRange(min, max int64) (int64, error) {
	v, err := r.Int()
	if err == nil && (v < min || v > max) {
		err = ErrOverflow
	}
	return v, err
}

// Bool returns the current boolean.
func (r *Reader) Bool() (bool, error) {
	if !r.has {
		return false, ErrNoElement
	}
	if r.typ != TypeBool {
		return false, ErrType
	}
	return r.num != 0, nil
}

// Float returns the current float of either precision.
func (r *Reader) Float() (float64, error) {
	if !r.has {
		return 0, ErrNoElement
	}
	switch r.typ {
	case TypeFloat32:
		return float64(math.Float32frombits(uint32(r.num))), nil
	case TypeFloat64:
		return math.Float64frombits(r.num), nil
	}
	return 0, ErrType
}

// Bytes returns the current octet string. The slice aliases the input.
func (r *Reader) Bytes() ([]byte, error) {
	if !r.has {
		return nil, ErrNoElement
	}
	if r.typ != TypeBytes {
		return nil, ErrType
	}
	return r.val, nil
}

// UTF8 returns the current UTF-8 string's bytes. The slice aliases the input.
func (r *Reader) UTF8() ([]byte, error) {
	if !r.has {
		return nil, ErrNoElement
	}
	if r.typ != TypeUTF8 {
		return nil, ErrType
	}
	return r.val, nil
}

// String returns a copy of the current UTF-8 string.
func (r *Reader) String() (string, error) {
	b, err := r.UTF8()
	return string(b), err
}

// IsNull reports whether the current element is null.
func (r *Reader) IsNull() bool { return r.has && r.typ == TypeNull }

type element struct {
	typ Type
	tag Tag
	num uint64
	val []byte
}

// parseElement decodes the element whose control octet is at b[pos]. For
// containers it consumes only the control octet and tag.
func parseElement(b []byte, pos int) (e element, next int, err error) {
	ctl := b[pos]
	pos++
	elem := ctl & 0x1F
	if elem >= elemEndOfContainer { // end-of-container in element position, or reserved
		return e, 0, ErrInvalid
	}

	// Tag.
	var tagLen int
	switch ctl >> 5 {
	case 0:
		e.tag.Kind = TagAnonymous
	case 1:
		e.tag.Kind, tagLen = TagContext, 1
	case 2:
		e.tag.Kind, tagLen = TagCommonProfile, 2
	case 3:
		e.tag.Kind, tagLen = TagCommonProfile, 4
	case 4:
		e.tag.Kind, tagLen = TagImplicitProfile, 2
	case 5:
		e.tag.Kind, tagLen = TagImplicitProfile, 4
	case 6:
		e.tag.Kind, tagLen = TagFullyQualified, 6
	case 7:
		e.tag.Kind, tagLen = TagFullyQualified, 8
	}
	if len(b)-pos < tagLen {
		return e, 0, ErrTruncated
	}
	t := b[pos : pos+tagLen]
	switch tagLen {
	case 1:
		e.tag.Number = uint32(t[0])
	case 2:
		e.tag.Number = uint32(binary.LittleEndian.Uint16(t))
	case 4:
		e.tag.Number = binary.LittleEndian.Uint32(t)
	case 6:
		e.tag.Vendor = binary.LittleEndian.Uint16(t)
		e.tag.Profile = binary.LittleEndian.Uint16(t[2:])
		e.tag.Number = uint32(binary.LittleEndian.Uint16(t[4:]))
	case 8:
		e.tag.Vendor = binary.LittleEndian.Uint16(t)
		e.tag.Profile = binary.LittleEndian.Uint16(t[2:])
		e.tag.Number = binary.LittleEndian.Uint32(t[4:])
	}
	pos += tagLen

	// Value.
	switch {
	case elem <= elemUint64:
		e.typ = TypeInt
		if elem >= elemUint8 {
			e.typ = TypeUint
		}
		n := 1 << (elem & 3)
		if len(b)-pos < n {
			return e, 0, ErrTruncated
		}
		v := b[pos : pos+n]
		switch n {
		case 1:
			e.num = uint64(v[0])
			if e.typ == TypeInt {
				e.num = uint64(int64(int8(v[0])))
			}
		case 2:
			e.num = uint64(binary.LittleEndian.Uint16(v))
			if e.typ == TypeInt {
				e.num = uint64(int64(int16(e.num)))
			}
		case 4:
			e.num = uint64(binary.LittleEndian.Uint32(v))
			if e.typ == TypeInt {
				e.num = uint64(int64(int32(e.num)))
			}
		case 8:
			e.num = binary.LittleEndian.Uint64(v)
		}
		pos += n
	case elem == elemFalse || elem == elemTrue:
		e.typ = TypeBool
		e.num = uint64(elem - elemFalse)
	case elem == elemFloat32:
		if len(b)-pos < 4 {
			return e, 0, ErrTruncated
		}
		e.typ = TypeFloat32
		e.num = uint64(binary.LittleEndian.Uint32(b[pos:]))
		pos += 4
	case elem == elemFloat64:
		if len(b)-pos < 8 {
			return e, 0, ErrTruncated
		}
		e.typ = TypeFloat64
		e.num = binary.LittleEndian.Uint64(b[pos:])
		pos += 8
	case elem >= elemUTF8_1 && elem < elemNull:
		e.typ = TypeUTF8
		if elem >= elemBytes1 {
			e.typ = TypeBytes
		}
		n := 1 << (elem & 3)
		if len(b)-pos < n {
			return e, 0, ErrTruncated
		}
		var l uint64
		switch n {
		case 1:
			l = uint64(b[pos])
		case 2:
			l = uint64(binary.LittleEndian.Uint16(b[pos:]))
		case 4:
			l = uint64(binary.LittleEndian.Uint32(b[pos:]))
		case 8:
			l = binary.LittleEndian.Uint64(b[pos:])
		}
		pos += n
		if l > uint64(len(b)-pos) {
			return e, 0, ErrTruncated
		}
		e.val = b[pos : pos+int(l) : pos+int(l)]
		pos += int(l)
	case elem == elemNull:
		e.typ = TypeNull
	case elem == elemStruct:
		e.typ = TypeStruct
	case elem == elemArray:
		e.typ = TypeArray
	case elem == elemList:
		e.typ = TypeList
	default: // end-of-container in element position, or reserved types
		return e, 0, ErrInvalid
	}
	return e, pos, nil
}

// skipContainerBody returns the offset just past the end-of-container octet
// that closes a container whose contents start at pos.
func skipContainerBody(b []byte, pos int) (int, error) {
	nesting := 1
	for {
		if pos >= len(b) {
			return 0, ErrTruncated
		}
		if b[pos] == elemEndOfContainer {
			pos++
			nesting--
			if nesting == 0 {
				return pos, nil
			}
			continue
		}
		e, next, err := parseElement(b, pos)
		if err != nil {
			return 0, err
		}
		if e.typ.IsContainer() {
			nesting++
		}
		pos = next
	}
}
