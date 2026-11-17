// Package clusters implements server clusters for the im data model.
package clusters

import (
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Cluster IDs.
const (
	IDIdentify               = 0x0003
	IDGroups                 = 0x0004
	IDOnOff                  = 0x0006
	IDDescriptor             = 0x001D
	IDAccessControl          = 0x001F
	IDBasicInformation       = 0x0028
	IDOTAProvider            = 0x0029
	IDOTARequestor           = 0x002A
	IDGeneralCommissioning   = 0x0030
	IDNetworkCommissioning   = 0x0031
	IDGeneralDiagnostics     = 0x0033
	IDSwitch                 = 0x003B
	IDAdminCommissioning     = 0x003C
	IDOperationalCredentials = 0x003E
	IDGroupKeyManagement     = 0x003F
)

// Device types.
var (
	DeviceTypeRootNode      = im.DeviceType{ID: 0x0016, Revision: 3}
	DeviceTypeOnOffLight    = im.DeviceType{ID: 0x0100, Revision: 3}
	DeviceTypeGenericSwitch = im.DeviceType{ID: 0x000F, Revision: 3}
	DeviceTypeOTARequestor  = im.DeviceType{ID: 0x0012, Revision: 1}
	DeviceTypeOTAProvider   = im.DeviceType{ID: 0x0014, Revision: 1}
)

// Descriptor is the Descriptor cluster. One value serves every endpoint: it
// describes the endpoint it is read on. The root endpoint's parts list
// holds every other endpoint; another endpoint's, its descendants (see
// im.Endpoint.Parent), as an aggregator lists its bridged devices.
type Descriptor struct{ im.ClusterBase }

func (Descriptor) ID() uint32       { return IDDescriptor }
func (Descriptor) Revision() uint16 { return 2 }

var descriptorAttrs = []uint32{0, 1, 2, 3}

func (Descriptor) Attributes() []uint32 { return descriptorAttrs }

func (Descriptor) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	e := ctx.Node.Endpoint(ctx.Endpoint)
	if e == nil {
		return im.UnsupportedEndpoint
	}
	w.StartArray(tag)
	switch attr {
	case 0: // DeviceTypeList
		for _, d := range e.DeviceTypes {
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(0), uint64(d.ID))
			w.PutUint(tlv.ContextTag(1), uint64(d.Revision))
			w.EndContainer()
		}
	case 1: // ServerList
		var buf [16]uint32
		for _, id := range e.ClusterIDs(buf[:0]) {
			w.PutUint(tlv.Anonymous, uint64(id))
		}
	case 2: // ClientList
	case 3: // PartsList
		var buf [16]uint16
		for _, id := range ctx.Node.Parts(e.ID, buf[:0]) {
			w.PutUint(tlv.Anonymous, uint64(id))
		}
	default:
		w.EndContainer()
		return im.UnsupportedAttribute
	}
	w.EndContainer()
	return im.Success
}
