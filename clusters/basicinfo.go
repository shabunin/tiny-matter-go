package clusters

import (
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// BasicInformation is the Basic Information cluster (endpoint 0).
type BasicInformation struct {
	im.ClusterBase
	VendorName            string
	VendorID              uint16
	ProductName           string
	ProductID             uint16
	HardwareVersion       uint16
	HardwareVersionString string
	SoftwareVersion       uint32
	SoftwareVersionString string
	SerialNumber          string // optional; omitted when empty
	UniqueID              string

	NodeLabel string // writable, at most 32 bytes
	Location  string // writable, ISO 3166-1 alpha-2 or "XX"

	// Revisions reported; zero values select Matter 1.4.
	DataModelRevision    uint16
	SpecificationVersion uint32
}

func (*BasicInformation) ID() uint32       { return IDBasicInformation }
func (*BasicInformation) Revision() uint16 { return 4 }

const (
	biDataModelRevision     = 0x00
	biVendorName            = 0x01
	biVendorID              = 0x02
	biProductName           = 0x03
	biProductID             = 0x04
	biNodeLabel             = 0x05
	biLocation              = 0x06
	biHardwareVersion       = 0x07
	biHardwareVersionString = 0x08
	biSoftwareVersion       = 0x09
	biSoftwareVersionString = 0x0A
	biSerialNumber          = 0x0F
	biUniqueID              = 0x12
	biCapabilityMinima      = 0x13
	biSpecificationVersion  = 0x15
	biMaxPathsPerInvoke     = 0x16
)

var (
	basicInfoAttrs       = []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x12, 0x13, 0x15, 0x16}
	basicInfoAttrsSerial = []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x0F, 0x12, 0x13, 0x15, 0x16}
)

func (b *BasicInformation) Attributes() []uint32 {
	if b.SerialNumber != "" {
		return basicInfoAttrsSerial
	}
	return basicInfoAttrs
}

func (b *BasicInformation) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case biDataModelRevision:
		v := b.DataModelRevision
		if v == 0 {
			v = 18
		}
		w.PutUint(tag, uint64(v))
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
	case biLocation:
		loc := b.Location
		if loc == "" {
			loc = "XX"
		}
		w.PutString(tag, loc)
	case biHardwareVersion:
		w.PutUint(tag, uint64(b.HardwareVersion))
	case biHardwareVersionString:
		w.PutString(tag, b.HardwareVersionString)
	case biSoftwareVersion:
		w.PutUint(tag, uint64(b.SoftwareVersion))
	case biSoftwareVersionString:
		w.PutString(tag, b.SoftwareVersionString)
	case biSerialNumber:
		if b.SerialNumber == "" {
			return im.UnsupportedAttribute
		}
		w.PutString(tag, b.SerialNumber)
	case biUniqueID:
		w.PutString(tag, b.UniqueID)
	case biCapabilityMinima:
		w.StartStruct(tag)
		w.PutUint(tlv.ContextTag(0), 3) // CaseSessionsPerFabric
		w.PutUint(tlv.ContextTag(1), 3) // SubscriptionsPerFabric
		w.EndContainer()
	case biSpecificationVersion:
		v := b.SpecificationVersion
		if v == 0 {
			v = 0x01040000
		}
		w.PutUint(tag, uint64(v))
	case biMaxPathsPerInvoke:
		w.PutUint(tag, im.MaxPathsPerInvoke)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (b *BasicInformation) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if appendItem {
		return im.InvalidAction
	}
	switch attr {
	case biNodeLabel:
		s, err := r.String()
		if err != nil {
			return im.InvalidDataType
		}
		if len(s) > 32 {
			return im.ConstraintError
		}
		b.NodeLabel = s
	case biLocation:
		s, err := r.String()
		if err != nil {
			return im.InvalidDataType
		}
		if len(s) != 2 {
			return im.ConstraintError
		}
		b.Location = s
	default:
		return im.UnsupportedWrite
	}
	return im.Success
}

func (*BasicInformation) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*BasicInformation) WritePrivilege(uint32) im.Privilege  { return im.Manage }
func (*BasicInformation) InvokePrivilege(uint32) im.Privilege { return im.Operate }
