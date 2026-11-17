package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// IDBridgedDeviceBasicInformation is the Bridged Device Basic Information
// cluster ID.
const IDBridgedDeviceBasicInformation = 0x0039

// Bridge device types: an Aggregator endpoint holds the bridged devices,
// each an endpoint with the Bridged Node device type next to its own (an
// On/Off Light, say).
var (
	DeviceTypeAggregator  = im.DeviceType{ID: 0x000E, Revision: 2}
	DeviceTypeBridgedNode = im.DeviceType{ID: 0x0013, Revision: 3}
)

// BridgedDeviceBasicInformation describes a device a bridge exposes: who
// made it, whether the bridge can reach it (Reachable, with the
// ReachableChanged event) and a stable UniqueID. Empty strings and zero
// numbers are left out. Set the fields before adding the cluster; change
// reachability with SetReachable.
type BridgedDeviceBasicInformation struct {
	im.ClusterBase
	VendorName            string
	VendorID              uint16
	ProductName           string
	ProductID             uint16
	NodeLabel             string // writable, at most 32 bytes; saved
	HardwareVersion       uint16
	HardwareVersionString string
	SoftwareVersion       uint32
	SoftwareVersionString string
	SerialNumber          string
	UniqueID              string // required: stable for the bridged device

	unreachable bool
	attrs       []uint32
}

// Bridged Device Basic Information attributes (as Basic Information's).
const (
	bbiReachable = 0x11
	bbiUniqueID  = 0x12

	// EventReachableChanged is the Bridged Device Basic Information
	// event recorded when Reachable changes.
	EventReachableChanged = 0x03
)

var bridgedInfoEvents = []uint32{EventReachableChanged}

func (*BridgedDeviceBasicInformation) ID() uint32       { return IDBridgedDeviceBasicInformation }
func (*BridgedDeviceBasicInformation) Revision() uint16 { return 4 }
func (*BridgedDeviceBasicInformation) Events() []uint32 { return bridgedInfoEvents }

func (b *BridgedDeviceBasicInformation) Attributes() []uint32 {
	if b.attrs != nil {
		return b.attrs
	}
	has := []struct {
		id uint32
		ok bool
	}{
		{biVendorName, b.VendorName != ""},
		{biVendorID, b.VendorID != 0},
		{biProductName, b.ProductName != ""},
		{biProductID, b.ProductID != 0},
		{biNodeLabel, true},
		{biHardwareVersion, b.HardwareVersion != 0 || b.HardwareVersionString != ""},
		{biHardwareVersionString, b.HardwareVersionString != ""},
		{biSoftwareVersion, b.SoftwareVersion != 0 || b.SoftwareVersionString != ""},
		{biSoftwareVersionString, b.SoftwareVersionString != ""},
		{biSerialNumber, b.SerialNumber != ""},
		{bbiReachable, true},
		{bbiUniqueID, true},
	}
	b.attrs = []uint32{}
	for _, a := range has {
		if a.ok {
			b.attrs = append(b.attrs, a.id)
		}
	}
	return b.attrs
}

// Reachable reports whether the bridge can reach the device.
func (b *BridgedDeviceBasicInformation) Reachable() bool { return !b.unreachable }

func (b *BridgedDeviceBasicInformation) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if !hasID(b.Attributes(), attr) {
		return im.UnsupportedAttribute
	}
	switch attr {
	case biVendorName:
		w.PutString(tag, b.VendorName)
	case biVendorID:
		w.PutUint(tag, uint64(b.VendorID))
	case biProductName:
		w.PutString(tag, b.ProductName)
	case biProductID:
		w.PutUint(tag, uint64(b.ProductID))
	case biNodeLabel:
		w.PutString(tag, b.NodeLabel)
	case biHardwareVersion:
		w.PutUint(tag, uint64(b.HardwareVersion))
	case biHardwareVersionString:
		w.PutString(tag, b.HardwareVersionString)
	case biSoftwareVersion:
		w.PutUint(tag, uint64(b.SoftwareVersion))
	case biSoftwareVersionString:
		w.PutString(tag, b.SoftwareVersionString)
	case biSerialNumber:
		w.PutString(tag, b.SerialNumber)
	case bbiReachable:
		w.PutBool(tag, !b.unreachable)
	case bbiUniqueID:
		w.PutString(tag, b.UniqueID)
	}
	return im.Success
}

func (b *BridgedDeviceBasicInformation) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != biNodeLabel {
		if hasID(b.Attributes(), attr) {
			return im.UnsupportedWrite
		}
		return im.UnsupportedAttribute
	}
	if appendItem {
		return im.InvalidAction
	}
	s, err := r.String()
	if err != nil {
		return im.InvalidDataType
	}
	if len(s) > 32 {
		return im.ConstraintError
	}
	b.NodeLabel = s
	return im.Success
}

func (*BridgedDeviceBasicInformation) ReadPrivilege(uint32) im.Privilege  { return im.View }
func (*BridgedDeviceBasicInformation) WritePrivilege(uint32) im.Privilege { return im.Manage }

func (*BridgedDeviceBasicInformation) InvokePrivilege(uint32) im.Privilege { return im.Operate }

// SetReachable records whether the device on endpoint can be reached.
func (b *BridgedDeviceBasicInformation) SetReachable(n *im.Node, endpoint uint16, now time.Time, reachable bool) {
	if reachable == !b.unreachable {
		return
	}
	b.unreachable = !reachable
	n.Changed(endpoint, IDBridgedDeviceBasicInformation, bbiReachable)
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: endpoint, Cluster: IDBridgedDeviceBasicInformation, Event: EventReachableChanged},
		Priority: im.PriorityInfo,
		Fields:   func(w *tlv.Writer) { w.PutBool(tlv.ContextTag(0), reachable) },
	})
}

// EncodeState saves the NodeLabel (im.Persister).
func (b *BridgedDeviceBasicInformation) EncodeState(w *tlv.Writer, tag tlv.Tag) {
	w.PutString(tag, b.NodeLabel)
}

// DecodeState restores the NodeLabel.
func (b *BridgedDeviceBasicInformation) DecodeState(r *tlv.Reader) error {
	s, err := r.String()
	if err == nil {
		b.NodeLabel = s
	}
	return err
}
