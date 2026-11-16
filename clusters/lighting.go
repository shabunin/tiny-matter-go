package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Helpers shared by the lighting clusters (On/Off, Level Control, Color
// Control, Scenes Management).

// Device types of lights (Matter Device Library).
var (
	DeviceTypeDimmableLight         = im.DeviceType{ID: 0x0101, Revision: 3}
	DeviceTypeColorTemperatureLight = im.DeviceType{ID: 0x010C, Revision: 4}
	DeviceTypeExtendedColorLight    = im.DeviceType{ID: 0x010D, Revision: 4}
)

// numFields are the decoded top-level fields (context tags 0-7) of a
// command: integers, signed or not, and which were present or null.
type numFields struct {
	v    [8]int64
	has  uint8
	null uint8
}

// decodeNumFields reads a command's integer fields. A field of another type
// is an error.
func decodeNumFields(r *tlv.Reader) (f numFields, ok bool) {
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		if tag >= 8 {
			return nil
		}
		f.has |= 1 << tag
		switch r.Type() {
		case tlv.TypeNull:
			f.null |= 1 << tag
		case tlv.TypeUint:
			v, err := r.Uint()
			if err != nil || v > 1<<62 {
				return im.InvalidCommand
			}
			f.v[tag] = int64(v)
		case tlv.TypeInt:
			v, err := r.Int()
			if err != nil {
				return err
			}
			f.v[tag] = v
		default:
			return im.InvalidCommand
		}
		return nil
	})
	return f, err == nil
}

// present reports whether all of the tags are present (null or not).
func (f *numFields) present(tags ...uint8) bool {
	for _, t := range tags {
		if f.has&(1<<t) == 0 {
			return false
		}
	}
	return true
}

func (f *numFields) isNull(tag uint8) bool { return f.null&(1<<tag) != 0 }

// u returns field tag as an unsigned value, false if it is negative or
// above max.
func (f *numFields) u(tag uint8, max int64) (uint64, bool) {
	v := f.v[tag]
	return uint64(v), v >= 0 && v <= max && !f.isNull(tag)
}

// executeIfOff applies the ExecuteIfOff rule (Level Control and Color
// Control options): a command runs while the light is off only if the
// effective ExecuteIfOff bit is set. The command's OptionsMask and
// OptionsOverride fields (tags maskTag and maskTag+1) override the
// Options attribute bit by bit.
func executeIfOff(onOff *OnOff, options uint8, f *numFields, maskTag uint8) bool {
	if onOff == nil || onOff.On {
		return true
	}
	bit := options & 1
	if f.present(maskTag, maskTag+1) {
		mask, override := uint8(f.v[maskTag]), uint8(f.v[maskTag+1])
		if mask&1 != 0 {
			bit = override & 1
		}
	}
	return bit != 0
}

// nullU8 and nullU16 are nullable attribute values.
type nullU8 struct {
	v     uint8
	valid bool
}

type nullU16 struct {
	v     uint16
	valid bool
}

func (n nullU8) put(w *tlv.Writer, tag tlv.Tag) {
	if n.valid {
		w.PutUint(tag, uint64(n.v))
	} else {
		w.PutNull(tag)
	}
}

func (n nullU16) put(w *tlv.Writer, tag tlv.Tag) {
	if n.valid {
		w.PutUint(tag, uint64(n.v))
	} else {
		w.PutNull(tag)
	}
}

// readNullU8 reads a nullable u8 with a maximum.
func readNullU8(r *tlv.Reader, max uint8) (nullU8, im.Status) {
	if r.IsNull() {
		return nullU8{}, im.Success
	}
	v, err := r.Uint()
	if err != nil {
		return nullU8{}, im.InvalidDataType
	}
	if v > uint64(max) {
		return nullU8{}, im.ConstraintError
	}
	return nullU8{uint8(v), true}, im.Success
}

func readNullU16(r *tlv.Reader, max uint16) (nullU16, im.Status) {
	if r.IsNull() {
		return nullU16{}, im.Success
	}
	v, err := r.Uint()
	if err != nil {
		return nullU16{}, im.InvalidDataType
	}
	if v > uint64(max) {
		return nullU16{}, im.ConstraintError
	}
	return nullU16{uint16(v), true}, im.Success
}

// readU16 reads a u16 attribute value with a maximum.
func readU16(r *tlv.Reader, max uint16) (uint16, im.Status) {
	v, err := r.Uint()
	if err != nil {
		return 0, im.InvalidDataType
	}
	if v > uint64(max) {
		return 0, im.ConstraintError
	}
	return uint16(v), im.Success
}

// deciseconds is a transition time in tenths of a second.
func deciseconds(ds uint16) time.Duration { return time.Duration(ds) * 100 * time.Millisecond }

// remainingDS returns the tenths of a second left until end, rounded up
// (so it reads zero only when the transition is over).
func remainingDS(now, end time.Time) uint64 {
	if !now.Before(end) {
		return 0
	}
	ds := (end.Sub(now) + 100*time.Millisecond - 1) / (100 * time.Millisecond)
	return uint64(min(ds, 0xFFFE))
}

// quietReport reports whether a value changing during a transition of
// length total should be reported now (Q quality): at most once per
// max(1 s, total/4).
func quietReport(now, last time.Time, total time.Duration) bool {
	return last.IsZero() || now.Sub(last) >= max(time.Second, total/4)
}

// hasID reports whether ids contains id.
func hasID(ids []uint32, id uint32) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// earliest returns the earlier non-zero time.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}
