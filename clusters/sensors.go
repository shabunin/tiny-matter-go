package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Sensor cluster IDs.
const (
	IDBooleanState                = 0x0045
	IDIlluminanceMeasurement      = 0x0400
	IDTemperatureMeasurement      = 0x0402
	IDPressureMeasurement         = 0x0403
	IDRelativeHumidityMeasurement = 0x0405
	IDOccupancySensing            = 0x0406
)

// Sensor and plug device types (Matter 1.4 device library).
var (
	DeviceTypeContactSensor     = im.DeviceType{ID: 0x0015, Revision: 2}
	DeviceTypeLightSensor       = im.DeviceType{ID: 0x0106, Revision: 3}
	DeviceTypeOccupancySensor   = im.DeviceType{ID: 0x0107, Revision: 4}
	DeviceTypeTemperatureSensor = im.DeviceType{ID: 0x0302, Revision: 2}
	DeviceTypeHumiditySensor    = im.DeviceType{ID: 0x0307, Revision: 2}
	DeviceTypePressureSensor    = im.DeviceType{ID: 0x0305, Revision: 2}
	DeviceTypeOnOffPlugInUnit   = im.DeviceType{ID: 0x010A, Revision: 3}
	DeviceTypeDimmablePlugIn    = im.DeviceType{ID: 0x010B, Revision: 4}
)

// BooleanState is the Boolean State cluster: one boolean reading, such as
// a contact sensor's (true: contact, so closed). Set records changes and
// the StateChange event.
type BooleanState struct {
	im.ClusterBase
	value bool
}

func (*BooleanState) ID() uint32       { return IDBooleanState }
func (*BooleanState) Revision() uint16 { return 1 }

var (
	booleanStateAttrs  = []uint32{0}
	booleanStateEvents = []uint32{0} // StateChange
)

func (*BooleanState) Attributes() []uint32 { return booleanStateAttrs }
func (*BooleanState) Events() []uint32     { return booleanStateEvents }

// Value returns the state.
func (b *BooleanState) Value() bool { return b.value }

func (b *BooleanState) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr != 0 {
		return im.UnsupportedAttribute
	}
	w.PutBool(tag, b.value)
	return im.Success
}

// Set updates the state of the cluster on endpoint.
func (b *BooleanState) Set(n *im.Node, endpoint uint16, now time.Time, v bool) {
	if v == b.value {
		return
	}
	b.value = v
	n.Changed(endpoint, IDBooleanState, 0)
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: endpoint, Cluster: IDBooleanState, Event: 0},
		Priority: im.PriorityInfo,
		Fields:   func(w *tlv.Writer) { w.PutBool(tlv.ContextTag(0), v) },
	})
}

// Measurement is one of the measurement clusters that report a single
// value with its range: Temperature Measurement (signed, in 0.01 °C),
// Relative Humidity Measurement (0.01 %) and Illuminance Measurement
// (10000·log10(lux)+1). Unknown values are null. Create it with
// NewTemperatureMeasurement, NewHumidityMeasurement or
// NewIlluminanceMeasurement and feed it with Set.
type Measurement struct {
	im.ClusterBase
	id       uint32
	revision uint16
	signed   bool

	value    Nullable
	min, max Nullable
	// Tolerance, if not zero, is reported (the magnitude of the possible
	// error, in the value's units).
	Tolerance uint16
}

// Nullable is a measured value or null.
type Nullable struct {
	Value int32
	Valid bool
}

// Value returns a non-null Nullable.
func Value(v int32) Nullable { return Nullable{Value: v, Valid: true} }

// Null is the null value.
var Null = Nullable{}

// NewTemperatureMeasurement returns a Temperature Measurement cluster
// measuring from min to max (in 0.01 °C; null if unknown).
func NewTemperatureMeasurement(min, max Nullable) *Measurement {
	return &Measurement{id: IDTemperatureMeasurement, revision: 4, signed: true, min: min, max: max}
}

// NewPressureMeasurement returns a Pressure Measurement cluster (without
// the Extended feature) measuring from min to max (in 0.1 kPa, which is
// hPa; null if unknown).
func NewPressureMeasurement(min, max Nullable) *Measurement {
	return &Measurement{id: IDPressureMeasurement, revision: 3, signed: true, min: min, max: max}
}

// NewHumidityMeasurement returns a Relative Humidity Measurement cluster
// measuring from min to max (in 0.01 %; null if unknown).
func NewHumidityMeasurement(min, max Nullable) *Measurement {
	return &Measurement{id: IDRelativeHumidityMeasurement, revision: 3, min: min, max: max}
}

// NewIlluminanceMeasurement returns an Illuminance Measurement cluster
// measuring from min to max (as 10000·log10(lux)+1; null if unknown).
func NewIlluminanceMeasurement(min, max Nullable) *Measurement {
	return &Measurement{id: IDIlluminanceMeasurement, revision: 3, min: min, max: max}
}

func (m *Measurement) ID() uint32       { return m.id }
func (m *Measurement) Revision() uint16 { return m.revision }

var (
	measurementAttrs          = []uint32{0, 1, 2}
	measurementAttrsTolerance = []uint32{0, 1, 2, 3}
)

func (m *Measurement) Attributes() []uint32 {
	if m.Tolerance != 0 {
		return measurementAttrsTolerance
	}
	return measurementAttrs
}

// Measured returns the measured value.
func (m *Measurement) Measured() Nullable { return m.value }

func (m *Measurement) put(w *tlv.Writer, tag tlv.Tag, v Nullable) {
	switch {
	case !v.Valid:
		w.PutNull(tag)
	case m.signed:
		w.PutInt(tag, int64(v.Value))
	default:
		w.PutUint(tag, uint64(v.Value))
	}
}

func (m *Measurement) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0: // MeasuredValue
		m.put(w, tag, m.value)
	case 1: // MinMeasuredValue
		m.put(w, tag, m.min)
	case 2: // MaxMeasuredValue
		m.put(w, tag, m.max)
	case 3: // Tolerance
		if m.Tolerance == 0 {
			return im.UnsupportedAttribute
		}
		w.PutUint(tag, uint64(m.Tolerance))
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// Set records a new measurement (null if unknown) of the cluster on
// endpoint. A known value is clamped to the range.
func (m *Measurement) Set(n *im.Node, endpoint uint16, v Nullable) {
	if v.Valid {
		if m.min.Valid && v.Value < m.min.Value {
			v.Value = m.min.Value
		}
		if m.max.Valid && v.Value > m.max.Value {
			v.Value = m.max.Value
		}
	}
	if v == m.value {
		return
	}
	m.value = v
	n.Changed(endpoint, m.id, 0)
}

// Occupancy sensor kinds (Occupancy Sensing features).
const (
	OccupancyOther           = 1 << 0
	OccupancyPassiveInfrared = 1 << 1
	OccupancyUltrasonic      = 1 << 2
	OccupancyPhysicalContact = 1 << 3
	OccupancyActiveInfrared  = 1 << 4
	OccupancyRadar           = 1 << 5
	OccupancyRFSensing       = 1 << 6
	OccupancyVision          = 1 << 7
)

// OccupancySensing is the Occupancy Sensing cluster without hold time
// settings. Sensors is a set of Occupancy* kinds (at least one); Set
// records changes and the OccupancyChanged event.
type OccupancySensing struct {
	im.ClusterBase
	Sensors  uint32
	occupied bool
}

func (*OccupancySensing) ID() uint32           { return IDOccupancySensing }
func (*OccupancySensing) Revision() uint16     { return 5 }
func (o *OccupancySensing) FeatureMap() uint32 { return o.Sensors }

var (
	occupancyAttrs  = []uint32{0, 1, 2}
	occupancyEvents = []uint32{0} // OccupancyChanged
)

func (*OccupancySensing) Attributes() []uint32 { return occupancyAttrs }
func (*OccupancySensing) Events() []uint32     { return occupancyEvents }

// Occupied reports the sensed occupancy.
func (o *OccupancySensing) Occupied() bool { return o.occupied }

func (o *OccupancySensing) bitmap() uint64 {
	if o.occupied {
		return 1
	}
	return 0
}

// sensorType returns the deprecated OccupancySensorType and
// OccupancySensorTypeBitmap attributes for the features, as the SDK
// derives them: sensors other than PIR, ultrasonic and physical contact
// are reported as PIR.
func (o *OccupancySensing) sensorType() (enum, bitmap uint64) {
	pir := o.Sensors&^(OccupancyUltrasonic|OccupancyPhysicalContact) != 0
	us := o.Sensors&OccupancyUltrasonic != 0
	switch {
	case pir && us:
		return 2, 3
	case us:
		return 1, 2
	case o.Sensors&OccupancyPhysicalContact != 0 && !pir:
		return 3, 4
	}
	return 0, 1
}

func (o *OccupancySensing) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	enum, bitmap := o.sensorType()
	switch attr {
	case 0: // Occupancy
		w.PutUint(tag, o.bitmap())
	case 1: // OccupancySensorType
		w.PutUint(tag, enum)
	case 2: // OccupancySensorTypeBitmap
		w.PutUint(tag, bitmap)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// Set updates the occupancy of the cluster on endpoint.
func (o *OccupancySensing) Set(n *im.Node, endpoint uint16, now time.Time, occupied bool) {
	if occupied == o.occupied {
		return
	}
	o.occupied = occupied
	n.Changed(endpoint, IDOccupancySensing, 0)
	b := o.bitmap()
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: endpoint, Cluster: IDOccupancySensing, Event: 0},
		Priority: im.PriorityInfo,
		Fields:   func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), b) },
	})
}
