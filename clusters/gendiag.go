package clusters

import (
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Boot reasons (BootReasonEnum).
const (
	BootUnspecified      = 0
	BootPowerOn          = 1
	BootBrownOut         = 2
	BootSoftwareWatchdog = 3
	BootHardwareWatchdog = 4
	BootSoftwareUpdate   = 5
	BootSoftwareReset    = 6
)

// Interface types (InterfaceTypeEnum).
const (
	InterfaceUnspecified = 0
	InterfaceWiFi        = 1
	InterfaceEthernet    = 2
	InterfaceCellular    = 3
	InterfaceThread      = 4
)

// NetworkInterface describes one network interface of the node.
type NetworkInterface struct {
	Name            string // at most 32 bytes
	Operational     bool
	HardwareAddress []byte // 6 or 8 bytes
	IPv4, IPv6      []netip.Addr
	Type            uint8
}

// EventBootReason is the General Diagnostics BootReason event.
const EventBootReason = 0x03

// GeneralDiagnostics is the General Diagnostics cluster (endpoint 0).
type GeneralDiagnostics struct {
	im.ClusterBase
	// Interfaces, if set, returns the node's network interfaces.
	Interfaces  func() []NetworkInterface
	RebootCount uint16
	BootReason  uint8
	// Boot is when the node booted, the zero of UpTime and of the system
	// time.
	Boot time.Time
	// EnableKey, if not all zero, enables the TestEventTrigger command,
	// which passes triggers sent with this key to Trigger.
	EnableKey [16]byte
	Trigger   func(ctx *im.Context, trigger uint64) im.Status
}

func (*GeneralDiagnostics) ID() uint32       { return IDGeneralDiagnostics }
func (*GeneralDiagnostics) Revision() uint16 { return 2 }

const (
	gdNetworkInterfaces        = 0x00
	gdRebootCount              = 0x01
	gdUpTime                   = 0x02
	gdBootReason               = 0x04
	gdTestEventTriggersEnabled = 0x08

	gdTestEventTrigger      = 0x00
	gdTimeSnapshot          = 0x01
	gdTimeSnapshotResponse  = 0x02
	maxInterfaceIPv4Address = 4
	maxInterfaceIPv6Address = 8
)

var (
	genDiagAttrs  = []uint32{gdNetworkInterfaces, gdRebootCount, gdUpTime, gdBootReason, gdTestEventTriggersEnabled}
	genDiagCmds   = []uint32{gdTestEventTrigger, gdTimeSnapshot}
	genDiagGen    = []uint32{gdTimeSnapshotResponse}
	genDiagEvents = []uint32{EventBootReason}
)

func (*GeneralDiagnostics) Attributes() []uint32        { return genDiagAttrs }
func (*GeneralDiagnostics) AcceptedCommands() []uint32  { return genDiagCmds }
func (*GeneralDiagnostics) GeneratedCommands() []uint32 { return genDiagGen }
func (*GeneralDiagnostics) Events() []uint32            { return genDiagEvents }

func (*GeneralDiagnostics) ReadPrivilege(uint32) im.Privilege  { return im.View }
func (*GeneralDiagnostics) WritePrivilege(uint32) im.Privilege { return im.Administer }
func (*GeneralDiagnostics) InvokePrivilege(cmd uint32) im.Privilege {
	if cmd == gdTestEventTrigger {
		return im.Manage
	}
	return im.Operate
}

func (g *GeneralDiagnostics) enabled() bool { return g.EnableKey != [16]byte{} }

// sinceBoot returns the time since boot at now.
func (g *GeneralDiagnostics) sinceBoot(now time.Time) time.Duration {
	if g.Boot.IsZero() || now.Before(g.Boot) {
		return 0
	}
	return now.Sub(g.Boot)
}

func (g *GeneralDiagnostics) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case gdNetworkInterfaces:
		w.StartArray(tag)
		if g.Interfaces != nil {
			for _, ni := range g.Interfaces() {
				encodeNetworkInterface(w, &ni)
			}
		}
		w.EndContainer()
	case gdRebootCount:
		w.PutUint(tag, uint64(g.RebootCount))
	case gdUpTime:
		w.PutUint(tag, uint64(g.sinceBoot(ctx.Now)/time.Second))
	case gdBootReason:
		w.PutUint(tag, uint64(g.BootReason))
	case gdTestEventTriggersEnabled:
		w.PutBool(tag, g.enabled())
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func encodeNetworkInterface(w *tlv.Writer, ni *NetworkInterface) {
	w.StartStruct(tlv.Anonymous)
	name := ni.Name
	if len(name) > 32 {
		name = name[:32]
	}
	w.PutString(tlv.ContextTag(0), name)
	w.PutBool(tlv.ContextTag(1), ni.Operational)
	w.PutNull(tlv.ContextTag(2)) // off-premise reachability unknown
	w.PutNull(tlv.ContextTag(3))
	w.PutBytes(tlv.ContextTag(4), ni.HardwareAddress)
	w.StartArray(tlv.ContextTag(5))
	n := 0
	for _, a := range ni.IPv4 {
		if a = a.Unmap(); a.Is4() && n < maxInterfaceIPv4Address {
			b := a.As4()
			w.PutBytes(tlv.Anonymous, b[:])
			n++
		}
	}
	w.EndContainer()
	w.StartArray(tlv.ContextTag(6))
	n = 0
	for _, a := range ni.IPv6 {
		if a.Is6() && !a.Is4In6() && n < maxInterfaceIPv6Address {
			b := a.As16()
			w.PutBytes(tlv.Anonymous, b[:])
			n++
		}
	}
	w.EndContainer()
	w.PutUint(tlv.ContextTag(7), uint64(ni.Type))
	w.EndContainer()
}

func (g *GeneralDiagnostics) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	switch cmd {
	case gdTestEventTrigger:
		var key []byte
		var trigger uint64
		var have uint8
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 0:
				key, err = r.Bytes()
				have |= 1
			case 1:
				trigger, err = r.Uint()
				have |= 2
			}
			return err
		})
		if err != nil || have != 3 {
			return im.InvalidCommand
		}
		// A key that does not enable triggers is a constraint error,
		// as in the SDK.
		if !g.enabled() || string(key) != string(g.EnableKey[:]) {
			return im.ConstraintError
		}
		if g.Trigger == nil {
			return im.InvalidCommand
		}
		return g.Trigger(ctx, trigger)
	case gdTimeSnapshot:
		w := resp.Fields(gdTimeSnapshotResponse)
		w.PutUint(tlv.ContextTag(0), uint64(g.sinceBoot(ctx.Now)/time.Millisecond))
		w.PutNull(tlv.ContextTag(1)) // no UTC time
		return im.Success
	}
	return im.UnsupportedCommand
}

// BootReasonEvent records the BootReason event, which a node generates
// once it has booted.
func (g *GeneralDiagnostics) BootReasonEvent(n *im.Node, now time.Time) {
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: 0, Cluster: IDGeneralDiagnostics, Event: EventBootReason},
		Priority: im.PriorityCritical,
		Fields:   func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), uint64(g.BootReason)) },
	})
}
