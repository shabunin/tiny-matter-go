package clusters

import (
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// IDPowerSource is the Power Source cluster (spec 11.7).
const IDPowerSource = 0x002F

// DeviceTypePowerSource goes on an endpoint with a Power Source cluster.
var DeviceTypePowerSource = im.DeviceType{ID: 0x0011, Revision: 1}

// Power source status (PowerSourceStatusEnum).
const (
	PowerUnspecified = 0
	PowerActive      = 1
	PowerStandby     = 2
	PowerUnavailable = 3
)

// Battery charge levels (BatChargeLevelEnum) and charge states
// (BatChargeStateEnum).
const (
	BatOK       = 0
	BatWarning  = 1
	BatCritical = 2

	BatChargeUnknown      = 0
	BatCharging           = 1
	BatAtFullCharge       = 2
	BatNotCharging        = 3
	BatReplaceUnspecified = 0
	BatNotReplaceable     = 1
	BatUserReplaceable    = 2
	BatFactoryReplaceable = 3
)

// PowerState is what a node knows of a power source, sampled when read.
type PowerState struct {
	Status uint8 // Power*
	// Wired sources.
	WiredPresent bool
	// Battery sources; unknown values read as null.
	BatVoltage     uint32 // mV; 0: unknown
	BatPercent     uint8  // in half percent (200 = 100%); 0xFF: unknown
	BatChargeLevel uint8  // Bat{OK,Warning,Critical}
	BatPresent     bool
	BatChargeState uint8 // BatCharge*, for rechargeable batteries
}

// PowerSource is a Power Source cluster: a wired source (Wired set) or a
// battery, rechargeable or not. Endpoints lists the endpoints it powers
// (empty: the whole node, on endpoint 0).
type PowerSource struct {
	im.ClusterBase
	Order       uint8  // lower is used first
	Description string // at most 60 bytes, e.g. "USB" or "Li-ion battery"
	Wired       bool
	// WiredDC marks a wired source as direct current (WiredCurrentType).
	WiredDC bool
	// Rechargeable marks a battery as rechargeable (the RECHG feature).
	Rechargeable bool
	// Replaceability is a battery's BatReplaceability.
	Replaceability uint8
	Endpoints      []uint16
	// State, if set, returns the current state; without it the source is
	// active, and battery values unknown.
	State func() PowerState
}

func (*PowerSource) ID() uint32       { return IDPowerSource }
func (*PowerSource) Revision() uint16 { return 3 }

func (p *PowerSource) FeatureMap() uint32 {
	switch {
	case p.Wired:
		return 1 // WIRED
	case p.Rechargeable:
		return 2 | 4 // BAT, RECHG
	}
	return 2 // BAT
}

const (
	psStatus                = 0x00
	psOrder                 = 0x01
	psDescription           = 0x02
	psWiredCurrentType      = 0x05
	psWiredPresent          = 0x09
	psBatVoltage            = 0x0B
	psBatPercentRemaining   = 0x0C
	psBatChargeLevel        = 0x0E
	psBatReplacementNeeded  = 0x0F
	psBatReplaceability     = 0x10
	psBatPresent            = 0x11
	psBatChargeState        = 0x1A
	psBatFunctionalCharging = 0x1C
	psEndpointList          = 0x1F
)

var (
	psWiredAttrs = []uint32{psStatus, psOrder, psDescription, psWiredCurrentType, psWiredPresent, psEndpointList}
	psBatAttrs   = []uint32{psStatus, psOrder, psDescription, psBatVoltage, psBatPercentRemaining, psBatChargeLevel,
		psBatReplacementNeeded, psBatReplaceability, psBatPresent, psEndpointList}
	psRechgAttrs = []uint32{psStatus, psOrder, psDescription, psBatVoltage, psBatPercentRemaining, psBatChargeLevel,
		psBatReplacementNeeded, psBatReplaceability, psBatPresent, psBatChargeState, psBatFunctionalCharging, psEndpointList}
)

func (p *PowerSource) Attributes() []uint32 {
	switch {
	case p.Wired:
		return psWiredAttrs
	case p.Rechargeable:
		return psRechgAttrs
	}
	return psBatAttrs
}

func (p *PowerSource) state() PowerState {
	if p.State != nil {
		return p.State()
	}
	return PowerState{Status: PowerActive, WiredPresent: true, BatPercent: 0xFF, BatPresent: true}
}

func (p *PowerSource) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if !hasAttr(p.Attributes(), attr) {
		return im.UnsupportedAttribute
	}
	s := p.state()
	switch attr {
	case psStatus:
		w.PutUint(tag, uint64(s.Status))
	case psOrder:
		w.PutUint(tag, uint64(p.Order))
	case psDescription:
		w.PutString(tag, p.Description)
	case psWiredCurrentType:
		if p.WiredDC {
			w.PutUint(tag, 1)
		} else {
			w.PutUint(tag, 0)
		}
	case psWiredPresent:
		w.PutBool(tag, s.WiredPresent)
	case psBatVoltage:
		if s.BatVoltage == 0 {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(s.BatVoltage))
		}
	case psBatPercentRemaining:
		if s.BatPercent > 200 {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(s.BatPercent))
		}
	case psBatChargeLevel:
		w.PutUint(tag, uint64(s.BatChargeLevel))
	case psBatReplacementNeeded:
		w.PutBool(tag, false)
	case psBatReplaceability:
		w.PutUint(tag, uint64(p.Replaceability))
	case psBatPresent:
		w.PutBool(tag, s.BatPresent)
	case psBatChargeState:
		w.PutUint(tag, uint64(s.BatChargeState))
	case psBatFunctionalCharging:
		w.PutBool(tag, true)
	case psEndpointList:
		w.StartArray(tag)
		for _, e := range p.Endpoints {
			w.PutUint(tlv.Anonymous, uint64(e))
		}
		w.EndContainer()
	}
	return im.Success
}

func hasAttr(ids []uint32, id uint32) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
