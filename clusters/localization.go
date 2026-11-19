package clusters

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Localization clusters (spec 11.3-11.5).
const (
	IDLocalizationConfiguration = 0x002B
	IDTimeFormatLocalization    = 0x002C
	IDUnitLocalization          = 0x002D
)

var errLocalizationState = errors.New("localization: malformed stored state")

// LocalizationConfiguration is the Localization Configuration cluster
// (endpoint 0): the language a node uses with people, one of those it
// supports, kept across restarts (im.Persister).
type LocalizationConfiguration struct {
	im.ClusterBase
	ActiveLocale     string   // a language tag such as "en-US"
	SupportedLocales []string // at most 32, each at most 35 bytes
}

func (*LocalizationConfiguration) ID() uint32       { return IDLocalizationConfiguration }
func (*LocalizationConfiguration) Revision() uint16 { return 1 }

var localeAttrs = []uint32{0, 1}

func (*LocalizationConfiguration) Attributes() []uint32 { return localeAttrs }

func (*LocalizationConfiguration) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*LocalizationConfiguration) WritePrivilege(uint32) im.Privilege  { return im.Manage }
func (*LocalizationConfiguration) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (c *LocalizationConfiguration) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0:
		w.PutString(tag, c.ActiveLocale)
	case 1:
		w.StartArray(tag)
		for _, l := range c.SupportedLocales {
			w.PutString(tlv.Anonymous, l)
		}
		w.EndContainer()
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// WriteAttribute sets ActiveLocale to one of SupportedLocales.
func (c *LocalizationConfiguration) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	switch attr {
	case 0:
	case 1:
		return im.UnsupportedWrite
	default:
		return im.UnsupportedAttribute
	}
	s, err := r.String()
	if err != nil {
		return im.InvalidDataType
	}
	if len(s) > 35 {
		return im.ConstraintError
	}
	for _, l := range c.SupportedLocales {
		if l == s {
			if s != c.ActiveLocale {
				c.ActiveLocale = s
				ctx.Node.Changed(ctx.Endpoint, IDLocalizationConfiguration, 0)
			}
			return im.Success
		}
	}
	return im.ConstraintError
}

// EncodeState saves ActiveLocale (im.Persister).
func (c *LocalizationConfiguration) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.PutString(tag, c.ActiveLocale)
}

// DecodeState restores ActiveLocale if it is still supported
// (im.Persister).
func (c *LocalizationConfiguration) DecodeState(r *tlv.Reader) error {
	s, err := r.String()
	if err != nil {
		return errLocalizationState
	}
	for _, l := range c.SupportedLocales {
		if l == s {
			c.ActiveLocale = s
		}
	}
	return nil
}

// Hour formats (HourFormatEnum).
const (
	Hour12             = 0
	Hour24             = 1
	HourUseActiveLocal = 0xFF
)

// TimeFormatLocalization is the Time Format Localization cluster
// (endpoint 0): the clock and calendar a node shows times in. With
// CalendarTypes set it has the CALFMT feature. Both are kept across
// restarts (im.Persister).
type TimeFormatLocalization struct {
	im.ClusterBase
	HourFormat uint8 // Hour12, Hour24 or HourUseActiveLocal
	// CalendarTypes are the calendars (CalendarTypeEnum: 4 Gregorian...)
	// the node supports; ActiveCalendar is one of them, or 0xFF to use the
	// active locale's.
	CalendarTypes  []uint8
	ActiveCalendar uint8
}

func (*TimeFormatLocalization) ID() uint32       { return IDTimeFormatLocalization }
func (*TimeFormatLocalization) Revision() uint16 { return 1 }

func (c *TimeFormatLocalization) FeatureMap() uint32 {
	if len(c.CalendarTypes) > 0 {
		return 1 // CALFMT
	}
	return 0
}

var (
	timeFormatAttrs         = []uint32{0}
	timeFormatCalendarAttrs = []uint32{0, 1, 2}
)

func (c *TimeFormatLocalization) Attributes() []uint32 {
	if len(c.CalendarTypes) > 0 {
		return timeFormatCalendarAttrs
	}
	return timeFormatAttrs
}

func (*TimeFormatLocalization) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*TimeFormatLocalization) WritePrivilege(uint32) im.Privilege  { return im.Manage }
func (*TimeFormatLocalization) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (c *TimeFormatLocalization) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	cal := len(c.CalendarTypes) > 0
	switch {
	case attr == 0:
		w.PutUint(tag, uint64(c.HourFormat))
	case attr == 1 && cal:
		w.PutUint(tag, uint64(c.ActiveCalendar))
	case attr == 2 && cal:
		w.StartArray(tag)
		for _, t := range c.CalendarTypes {
			w.PutUint(tlv.Anonymous, uint64(t))
		}
		w.EndContainer()
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (c *TimeFormatLocalization) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	cal := len(c.CalendarTypes) > 0
	switch {
	case attr == 0, attr == 1 && cal:
	case attr == 2 && cal:
		return im.UnsupportedWrite
	default:
		return im.UnsupportedAttribute
	}
	v, err := r.Uint8()
	if err != nil {
		return im.InvalidDataType
	}
	if attr == 0 {
		if v != Hour12 && v != Hour24 && v != HourUseActiveLocal {
			return im.ConstraintError
		}
		if v != c.HourFormat {
			c.HourFormat = v
			ctx.Node.Changed(ctx.Endpoint, IDTimeFormatLocalization, 0)
		}
		return im.Success
	}
	ok := v == 0xFF // use the active locale's
	for _, t := range c.CalendarTypes {
		ok = ok || t == v
	}
	if !ok {
		return im.ConstraintError
	}
	if v != c.ActiveCalendar {
		c.ActiveCalendar = v
		ctx.Node.Changed(ctx.Endpoint, IDTimeFormatLocalization, 1)
	}
	return im.Success
}

// EncodeState saves the hour format and calendar (im.Persister).
func (c *TimeFormatLocalization) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(0), uint64(c.HourFormat))
	w.PutUint(tlv.ContextTag(1), uint64(c.ActiveCalendar))
	w.EndContainer()
}

// DecodeState restores them (im.Persister).
func (c *TimeFormatLocalization) DecodeState(r *tlv.Reader) error {
	return im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			c.HourFormat, err = r.Uint8()
		case 1:
			c.ActiveCalendar, err = r.Uint8()
		}
		return err
	})
}

// Temperature units (TempUnitEnum).
const (
	Fahrenheit = 0
	Celsius    = 1
	Kelvin     = 2
)

// UnitLocalization is the Unit Localization cluster (endpoint 0) with the
// TEMP feature: the temperature unit a node shows, one of those it
// supports, kept across restarts (im.Persister).
type UnitLocalization struct {
	im.ClusterBase
	TemperatureUnit uint8
	// SupportedUnits are the units TemperatureUnit may be set to; empty
	// means all three.
	SupportedUnits []uint8
}

func (*UnitLocalization) ID() uint32         { return IDUnitLocalization }
func (*UnitLocalization) Revision() uint16   { return 2 }
func (*UnitLocalization) FeatureMap() uint32 { return 1 } // TEMP

var unitAttrs = []uint32{0, 1}

func (*UnitLocalization) Attributes() []uint32 { return unitAttrs }

func (*UnitLocalization) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*UnitLocalization) WritePrivilege(uint32) im.Privilege  { return im.Manage }
func (*UnitLocalization) InvokePrivilege(uint32) im.Privilege { return im.Operate }

var allTempUnits = []uint8{Fahrenheit, Celsius, Kelvin}

func (c *UnitLocalization) units() []uint8 {
	if len(c.SupportedUnits) == 0 {
		return allTempUnits
	}
	return c.SupportedUnits
}

func (c *UnitLocalization) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0:
		w.PutUint(tag, uint64(c.TemperatureUnit))
	case 1:
		w.StartArray(tag)
		for _, u := range c.units() {
			w.PutUint(tlv.Anonymous, uint64(u))
		}
		w.EndContainer()
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (c *UnitLocalization) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	switch attr {
	case 0:
	case 1:
		return im.UnsupportedWrite
	default:
		return im.UnsupportedAttribute
	}
	v, err := r.Uint8()
	if err != nil {
		return im.InvalidDataType
	}
	for _, u := range c.units() {
		if u == v {
			if v != c.TemperatureUnit {
				c.TemperatureUnit = v
				ctx.Node.Changed(ctx.Endpoint, IDUnitLocalization, 0)
			}
			return im.Success
		}
	}
	return im.ConstraintError
}

// EncodeState saves the unit (im.Persister).
func (c *UnitLocalization) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.PutUint(tag, uint64(c.TemperatureUnit))
}

// DecodeState restores it (im.Persister).
func (c *UnitLocalization) DecodeState(r *tlv.Reader) error {
	v, err := r.Uint8()
	if err != nil {
		return errLocalizationState
	}
	for _, u := range c.units() {
		if u == v {
			c.TemperatureUnit = v
		}
	}
	return nil
}
