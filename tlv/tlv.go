// Package tlv implements Matter TLV encoding (Matter Core Specification,
// Appendix A).
//
// It is written for TinyGo on 32-bit microcontrollers: no reflection, no
// fmt, explicit integer widths, and a Reader that returns slices into the
// input instead of copying.
package tlv

import "errors"

// Type is a TLV element type, with integer, string and float widths folded
// together (the width is an encoding detail).
type Type uint8

const (
	TypeInvalid Type = iota
	TypeInt
	TypeUint
	TypeBool
	TypeFloat32
	TypeFloat64
	TypeUTF8
	TypeBytes
	TypeNull
	TypeStruct
	TypeArray
	TypeList
)

func (t Type) String() string {
	switch t {
	case TypeInt:
		return "int"
	case TypeUint:
		return "uint"
	case TypeBool:
		return "bool"
	case TypeFloat32:
		return "float32"
	case TypeFloat64:
		return "float64"
	case TypeUTF8:
		return "utf8"
	case TypeBytes:
		return "bytes"
	case TypeNull:
		return "null"
	case TypeStruct:
		return "struct"
	case TypeArray:
		return "array"
	case TypeList:
		return "list"
	}
	return "invalid"
}

// IsContainer reports whether t is a structure, array or list.
func (t Type) IsContainer() bool { return t == TypeStruct || t == TypeArray || t == TypeList }

// Raw element type codes (lower 5 bits of the control octet).
const (
	elemInt8           = 0x00
	elemInt16          = 0x01
	elemInt32          = 0x02
	elemInt64          = 0x03
	elemUint8          = 0x04
	elemUint16         = 0x05
	elemUint32         = 0x06
	elemUint64         = 0x07
	elemFalse          = 0x08
	elemTrue           = 0x09
	elemFloat32        = 0x0A
	elemFloat64        = 0x0B
	elemUTF8_1         = 0x0C
	elemBytes1         = 0x10
	elemNull           = 0x14
	elemStruct         = 0x15
	elemArray          = 0x16
	elemList           = 0x17
	elemEndOfContainer = 0x18
)

// TagKind is the form of a tag (upper 3 bits of the control octet).
type TagKind uint8

const (
	TagAnonymous       TagKind = 0
	TagContext         TagKind = 1
	TagCommonProfile   TagKind = 2 // 2- or 4-octet tag number
	TagImplicitProfile TagKind = 4 // 2- or 4-octet tag number
	TagFullyQualified  TagKind = 6 // 6- or 8-octet form
)

// Tag identifies an element within its container.
type Tag struct {
	Kind    TagKind
	Vendor  uint16 // fully qualified tags only
	Profile uint16 // fully qualified tags only
	Number  uint32 // 0..255 for context tags
}

// Anonymous is the anonymous tag.
var Anonymous = Tag{}

// ContextTag returns a context-specific tag.
func ContextTag(n uint8) Tag { return Tag{Kind: TagContext, Number: uint32(n)} }

// CommonProfileTag returns a tag in the Matter common profile.
func CommonProfileTag(n uint32) Tag { return Tag{Kind: TagCommonProfile, Number: n} }

// ImplicitProfileTag returns a tag in the implicit profile.
func ImplicitProfileTag(n uint32) Tag { return Tag{Kind: TagImplicitProfile, Number: n} }

// FullyQualifiedTag returns a vendor/profile-qualified tag.
func FullyQualifiedTag(vendor, profile uint16, n uint32) Tag {
	return Tag{Kind: TagFullyQualified, Vendor: vendor, Profile: profile, Number: n}
}

// IsContext reports whether t is the context tag n.
func (t Tag) IsContext(n uint8) bool { return t.Kind == TagContext && t.Number == uint32(n) }

var (
	ErrTruncated      = errors.New("tlv: truncated input")
	ErrInvalid        = errors.New("tlv: malformed element")
	ErrEndOfContainer = errors.New("tlv: end of container")
	ErrType           = errors.New("tlv: unexpected element type")
	ErrOverflow       = errors.New("tlv: value out of range")
	ErrNotContainer   = errors.New("tlv: element is not a container")
	ErrNoElement      = errors.New("tlv: no current element")
	ErrTooLong        = errors.New("tlv: length does not fit in memory")
)
