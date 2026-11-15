// Package thread holds what Matter needs to know about Thread networks.
// For now that is the operational dataset: the parameters of a network that
// a commissioner hands a device (Network Commissioning
// AddOrUpdateThreadNetwork) and that a border router exports, for example
// with `ot-ctl dataset active -x`.
package thread

import (
	"encoding/binary"
	"errors"
)

// MaxDatasetLen is the largest operational dataset Matter carries.
const MaxDatasetLen = 254

// TLV types of an operational dataset (Thread specification 8.10).
const (
	TypeChannel         = 0
	TypePANID           = 1
	TypeExtendedPANID   = 2
	TypeNetworkName     = 3
	TypePSKc            = 4
	TypeNetworkKey      = 5
	TypeMeshLocalPrefix = 7
	TypeSecurityPolicy  = 12
	TypeActiveTimestamp = 14
	TypeDelayTimer      = 52
	TypeChannelMask     = 53
)

// Errors.
var (
	ErrDataset    = errors.New("thread: malformed operational dataset")
	ErrIncomplete = errors.New("thread: operational dataset lacks the channel, PAN ID, extended PAN ID or network key")
)

// Dataset is an operational dataset. Raw keeps its TLV form, which is
// what is handed on; the fields are decoded from it.
type Dataset struct {
	Raw []byte

	Channel         uint16 // on channel page 0
	PANID           uint16
	ExtendedPANID   [8]byte
	NetworkName     string
	NetworkKey      [16]byte
	MeshLocalPrefix [8]byte
	PSKc            [16]byte
	// ActiveTimestamp is the raw 64-bit timestamp: seconds in the top 48
	// bits, then 15 bits of ticks and the authoritative bit.
	ActiveTimestamp uint64

	has uint64 // bit t set: TLV type t (< 64) is present
}

// Has reports whether the dataset has a TLV of type t.
func (d *Dataset) Has(t uint8) bool { return t < 64 && d.has&(1<<t) != 0 }

// ParseDataset decodes an operational dataset in its TLV form. It must
// hold what a device needs to join: the channel, the PAN ID, the extended
// PAN ID and the network key. Unknown TLVs are kept in Raw and skipped.
func ParseDataset(b []byte) (*Dataset, error) {
	if len(b) > MaxDatasetLen {
		return nil, ErrDataset
	}
	d := &Dataset{Raw: b}
	for i := 0; i < len(b); {
		if len(b)-i < 2 {
			return nil, ErrDataset
		}
		t, n := b[i], int(b[i+1])
		if n == 0xFF { // the extended format is not allowed in a dataset
			return nil, ErrDataset
		}
		i += 2
		if len(b)-i < n {
			return nil, ErrDataset
		}
		v := b[i : i+n]
		i += n
		ok := true
		switch t {
		case TypeChannel:
			// The channel page, then the channel; only page 0 (2.4 GHz).
			ok = n == 3 && v[0] == 0
			if ok {
				d.Channel = binary.BigEndian.Uint16(v[1:])
			}
		case TypePANID:
			ok = n == 2
			if ok {
				d.PANID = binary.BigEndian.Uint16(v)
			}
		case TypeExtendedPANID:
			ok = n == 8 && copy(d.ExtendedPANID[:], v) == 8
		case TypeNetworkName:
			ok = n >= 1 && n <= 16
			d.NetworkName = string(v)
		case TypeNetworkKey:
			ok = n == 16 && copy(d.NetworkKey[:], v) == 16
		case TypeMeshLocalPrefix:
			ok = n == 8 && copy(d.MeshLocalPrefix[:], v) == 8
		case TypePSKc:
			ok = n == 16 && copy(d.PSKc[:], v) == 16
		case TypeActiveTimestamp:
			ok = n == 8
			if ok {
				d.ActiveTimestamp = binary.BigEndian.Uint64(v)
			}
		}
		if !ok {
			return nil, ErrDataset
		}
		if t < 64 {
			d.has |= 1 << t
		}
	}
	for _, t := range []uint8{TypeChannel, TypePANID, TypeExtendedPANID, TypeNetworkKey} {
		if !d.Has(t) {
			return nil, ErrIncomplete
		}
	}
	return d, nil
}
