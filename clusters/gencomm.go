package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// CommissioningError is the General Commissioning error code.
type CommissioningError uint8

const (
	CommissioningOK       CommissioningError = 0
	ValueOutsideRange     CommissioningError = 1
	InvalidAuthentication CommissioningError = 2
	NoFailSafe            CommissioningError = 3
	BusyWithOtherAdmin    CommissioningError = 4
)

// Regulatory location types.
const (
	RegulatoryIndoor        = 0
	RegulatoryOutdoor       = 1
	RegulatoryIndoorOutdoor = 2
)

// FailSafe is the commissioning fail-safe timer (spec 11.10.7.2.2). When it
// expires, the expiry hooks roll back what was configured under it.
type FailSafe struct {
	armed       bool
	deadline    time.Time
	maxDeadline time.Time // cumulative limit from the first arming
	fabricIndex uint8     // accessing fabric that armed it

	// OnExpire hooks run, in order, when the timer expires or is disarmed
	// with a zero expiry.
	OnExpire []func(now time.Time)
}

// Armed reports whether the fail-safe is armed at now, expiring it first if
// its deadline has passed.
func (f *FailSafe) Armed(now time.Time) bool {
	f.Poll(now)
	return f.armed
}

// FabricIndex returns the accessing fabric that armed the fail-safe.
func (f *FailSafe) FabricIndex() uint8 { return f.fabricIndex }

// Arm arms or re-arms the fail-safe for d, capped by maxCumulative since
// first armed.
func (f *FailSafe) Arm(now time.Time, d, maxCumulative time.Duration, fabricIndex uint8) {
	if !f.Armed(now) {
		f.armed, f.fabricIndex = true, fabricIndex
		f.maxDeadline = now.Add(maxCumulative)
	}
	f.deadline = now.Add(d)
	if f.deadline.After(f.maxDeadline) {
		f.deadline = f.maxDeadline
	}
}

// Disarm disarms the fail-safe without running the expiry hooks (on
// successful commissioning).
func (f *FailSafe) Disarm() { f.armed = false }

// Expire disarms the fail-safe and runs the expiry hooks.
func (f *FailSafe) Expire(now time.Time) {
	if !f.armed {
		return
	}
	f.armed = false
	for _, h := range f.OnExpire {
		h(now)
	}
}

// Poll expires the fail-safe if due and returns its deadline (zero if not
// armed).
func (f *FailSafe) Poll(now time.Time) time.Time {
	if f.armed && !now.Before(f.deadline) {
		f.Expire(now)
	}
	if !f.armed {
		return time.Time{}
	}
	return f.deadline
}

// GeneralCommissioning is the General Commissioning cluster.
type GeneralCommissioning struct {
	im.ClusterBase
	FailSafe *FailSafe

	Breadcrumb                   uint64
	RegulatoryConfig             uint8
	LocationCapability           uint8 // default RegulatoryIndoorOutdoor
	SupportsConcurrentConnection bool
	// FailSafeExpiryLength is the recommended initial fail-safe duration
	// (default 60 s); MaxCumulativeFailsafe bounds re-arming (default 900 s).
	FailSafeExpiryLength  time.Duration
	MaxCumulativeFailsafe time.Duration

	// FabricIndex returns the accessing fabric of a request (0 when the
	// session has none yet, as for PASE before AddNOC).
	FabricIndex func(ctx *im.Context) uint8
	// Complete handles CommissioningComplete once the fail-safe checks
	// pass; it must verify the request came over CASE on the fabric that
	// armed the fail-safe. Nil answers InvalidAuthentication.
	Complete func(ctx *im.Context) CommissioningError
}

// NewGeneralCommissioning returns the cluster with default settings.
func NewGeneralCommissioning(fs *FailSafe) *GeneralCommissioning {
	return &GeneralCommissioning{
		FailSafe:                     fs,
		RegulatoryConfig:             RegulatoryIndoorOutdoor,
		LocationCapability:           RegulatoryIndoorOutdoor,
		SupportsConcurrentConnection: true,
		FailSafeExpiryLength:         60 * time.Second,
		MaxCumulativeFailsafe:        900 * time.Second,
	}
}

func (*GeneralCommissioning) ID() uint32       { return IDGeneralCommissioning }
func (*GeneralCommissioning) Revision() uint16 { return 2 }

const (
	gcBreadcrumb                   = 0
	gcBasicCommissioningInfo       = 1
	gcRegulatoryConfig             = 2
	gcLocationCapability           = 3
	gcSupportsConcurrentConnection = 4

	gcArmFailSafe                   = 0
	gcArmFailSafeResponse           = 1
	gcSetRegulatoryConfig           = 2
	gcSetRegulatoryConfigResponse   = 3
	gcCommissioningComplete         = 4
	gcCommissioningCompleteResponse = 5
)

var (
	gcAttrs     = []uint32{0, 1, 2, 3, 4}
	gcAccepted  = []uint32{gcArmFailSafe, gcSetRegulatoryConfig, gcCommissioningComplete}
	gcGenerated = []uint32{gcArmFailSafeResponse, gcSetRegulatoryConfigResponse, gcCommissioningCompleteResponse}
)

func (*GeneralCommissioning) Attributes() []uint32        { return gcAttrs }
func (*GeneralCommissioning) AcceptedCommands() []uint32  { return gcAccepted }
func (*GeneralCommissioning) GeneratedCommands() []uint32 { return gcGenerated }

func (g *GeneralCommissioning) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case gcBreadcrumb:
		w.PutUint(tag, g.Breadcrumb)
	case gcBasicCommissioningInfo:
		w.StartStruct(tag)
		w.PutUint(tlv.ContextTag(0), uint64(g.FailSafeExpiryLength/time.Second))
		w.PutUint(tlv.ContextTag(1), uint64(g.MaxCumulativeFailsafe/time.Second))
		w.EndContainer()
	case gcRegulatoryConfig:
		w.PutUint(tag, uint64(g.RegulatoryConfig))
	case gcLocationCapability:
		w.PutUint(tag, uint64(g.LocationCapability))
	case gcSupportsConcurrentConnection:
		w.PutBool(tag, g.SupportsConcurrentConnection)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (g *GeneralCommissioning) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != gcBreadcrumb {
		return im.UnsupportedWrite
	}
	v, err := r.Uint()
	if err != nil || appendItem {
		return im.InvalidDataType
	}
	g.Breadcrumb = v
	return im.Success
}

func (g *GeneralCommissioning) fabricIndex(ctx *im.Context) uint8 {
	if g.FabricIndex == nil {
		return 0
	}
	return g.FabricIndex(ctx)
}

// ResetBreadcrumb sets Breadcrumb back to 0, as a fail-safe expiry does.
func (g *GeneralCommissioning) ResetBreadcrumb(node *im.Node) {
	if g.Breadcrumb != 0 {
		g.Breadcrumb = 0
		if node != nil {
			node.Changed(0, IDGeneralCommissioning, gcBreadcrumb)
		}
	}
}

func (g *GeneralCommissioning) setBreadcrumb(ctx *im.Context, v uint64, ok bool) {
	if ok && v != g.Breadcrumb {
		g.Breadcrumb = v
		ctx.Node.Changed(ctx.Endpoint, IDGeneralCommissioning, gcBreadcrumb)
	}
}

func respond(resp *im.Response, cmd uint32, code CommissioningError) im.Status {
	w := resp.Fields(cmd)
	w.PutUint(tlv.ContextTag(0), uint64(code))
	w.PutString(tlv.ContextTag(1), "")
	return im.Success
}

func (g *GeneralCommissioning) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	switch cmd {
	case gcArmFailSafe:
		var (
			expiry     uint16
			breadcrumb uint64
			have       uint8
		)
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 0:
				expiry, err = r.Uint16()
				have |= 1
			case 1:
				breadcrumb, err = r.Uint()
				have |= 2
			}
			return err
		})
		if err != nil || have != 3 {
			return im.InvalidCommand
		}
		fs, fabric := g.FailSafe, g.fabricIndex(ctx)
		if fs.Armed(ctx.Now) && fs.FabricIndex() != fabric {
			return respond(resp, gcArmFailSafeResponse, BusyWithOtherAdmin)
		}
		if expiry == 0 {
			// The expiry resets the breadcrumb; the request's is not kept.
			fs.Expire(ctx.Now)
		} else {
			fs.Arm(ctx.Now, time.Duration(expiry)*time.Second, g.MaxCumulativeFailsafe, fabric)
			g.setBreadcrumb(ctx, breadcrumb, true)
		}
		return respond(resp, gcArmFailSafeResponse, CommissioningOK)

	case gcSetRegulatoryConfig:
		var (
			cfg        uint8
			country    string
			breadcrumb uint64
			have       uint8
		)
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 0:
				cfg, err = r.Uint8()
				have |= 1
			case 1:
				country, err = r.String()
				have |= 2
			case 2:
				breadcrumb, err = r.Uint()
				have |= 4
			}
			return err
		})
		if err != nil || have != 7 || len(country) != 2 || cfg > RegulatoryIndoorOutdoor {
			return im.InvalidCommand
		}
		if g.LocationCapability != RegulatoryIndoorOutdoor && cfg != g.LocationCapability {
			return respond(resp, gcSetRegulatoryConfigResponse, ValueOutsideRange)
		}
		if cfg != g.RegulatoryConfig {
			g.RegulatoryConfig = cfg
			ctx.Node.Changed(ctx.Endpoint, IDGeneralCommissioning, gcRegulatoryConfig)
		}
		g.setBreadcrumb(ctx, breadcrumb, true)
		return respond(resp, gcSetRegulatoryConfigResponse, CommissioningOK)

	case gcCommissioningComplete:
		code := InvalidAuthentication
		switch {
		case !g.FailSafe.Armed(ctx.Now):
			code = NoFailSafe
		case g.Complete != nil:
			code = g.Complete(ctx)
		}
		if code == CommissioningOK {
			g.FailSafe.Disarm()
			g.setBreadcrumb(ctx, 0, true)
		}
		return respond(resp, gcCommissioningCompleteResponse, code)
	}
	return im.UnsupportedCommand
}

func (*GeneralCommissioning) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*GeneralCommissioning) WritePrivilege(uint32) im.Privilege  { return im.Administer }
func (*GeneralCommissioning) InvokePrivilege(uint32) im.Privilege { return im.Administer }

// SetFabricIndex records the fabric a NOC was added for under the
// fail-safe; CommissioningComplete must come from that fabric.
func (f *FailSafe) SetFabricIndex(index uint8) { f.fabricIndex = index }
