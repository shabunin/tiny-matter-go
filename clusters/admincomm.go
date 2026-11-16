package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Commissioning window status (WindowStatus attribute).
const (
	WindowNotOpen      = 0
	WindowEnhancedOpen = 1
	WindowBasicOpen    = 2
)

// AdminStatus is an Administrator Commissioning cluster-specific status.
type AdminStatus uint8

const (
	AdminOK                 AdminStatus = 0
	AdminBusy               AdminStatus = 2
	AdminPAKEParameterError AdminStatus = 3
	AdminWindowNotOpen      AdminStatus = 4
)

// Commissioning timeout limits for windows opened by an administrator.
const (
	MinCommissioningTimeout = 180 * time.Second
	MaxCommissioningTimeout = 900 * time.Second
)

// Window describes a commissioning window an administrator asks to open.
// Verifier is nil for a basic window (the device's own passcode).
type Window struct {
	Timeout       time.Duration
	Verifier      *spake2p.Verifier
	Salt          []byte
	Iterations    uint32
	Discriminator uint16
}

// AdminCommissioning is the Administrator Commissioning cluster with the
// Basic feature: it lets an administrator reopen commissioning so another
// controller can join (multi-admin).
type AdminCommissioning struct {
	im.ClusterBase

	WindowStatus     uint8
	AdminFabricIndex uint8 // 0 = null
	AdminVendorID    uint16

	// Open opens the window w; Revoke closes the open window and aborts a
	// commissioning in progress. They implement the commands.
	Open   func(ctx *im.Context, w *Window) AdminStatus
	Revoke func(ctx *im.Context) AdminStatus
}

func (*AdminCommissioning) ID() uint32         { return IDAdminCommissioning }
func (*AdminCommissioning) Revision() uint16   { return 1 }
func (*AdminCommissioning) FeatureMap() uint32 { return 1 } // BC

const (
	acOpenCommissioningWindow      = 0
	acOpenBasicCommissioningWindow = 1
	acRevokeCommissioning          = 2

	acWindowStatus     = 0
	acAdminFabricIndex = 1
	acAdminVendorID    = 2
)

var (
	acAttrs = []uint32{acWindowStatus, acAdminFabricIndex, acAdminVendorID}
	acCmds  = []uint32{acOpenCommissioningWindow, acOpenBasicCommissioningWindow, acRevokeCommissioning}
)

func (*AdminCommissioning) Attributes() []uint32               { return acAttrs }
func (*AdminCommissioning) AcceptedCommands() []uint32         { return acCmds }
func (*AdminCommissioning) ReadPrivilege(uint32) im.Privilege  { return im.View }
func (*AdminCommissioning) WritePrivilege(uint32) im.Privilege { return im.Administer }
func (*AdminCommissioning) InvokePrivilege(uint32) im.Privilege {
	return im.Administer
}

func (a *AdminCommissioning) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case acWindowStatus:
		w.PutUint(tag, uint64(a.WindowStatus))
	case acAdminFabricIndex:
		if a.AdminFabricIndex == 0 {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(a.AdminFabricIndex))
		}
	case acAdminVendorID:
		// Null only while the window is closed: it outlives the removal
		// of the fabric that opened the window (see ForgetFabric).
		if a.WindowStatus == WindowNotOpen || a.AdminVendorID == 0 {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(a.AdminVendorID))
		}
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// SetWindow updates the attributes, reporting what changed.
func (a *AdminCommissioning) SetWindow(n *im.Node, status, fabricIndex uint8, vendorID uint16) {
	if status != a.WindowStatus {
		a.WindowStatus = status
		n.Changed(0, IDAdminCommissioning, acWindowStatus)
	}
	if fabricIndex != a.AdminFabricIndex || vendorID != a.AdminVendorID {
		a.AdminFabricIndex, a.AdminVendorID = fabricIndex, vendorID
		n.Changed(0, IDAdminCommissioning, acAdminFabricIndex)
		n.Changed(0, IDAdminCommissioning, acAdminVendorID)
	}
}

// ForgetFabric handles the removal of a fabric: if it opened the window,
// AdminFabricIndex becomes null, while AdminVendorId keeps its value until
// the window closes.
func (a *AdminCommissioning) ForgetFabric(n *im.Node, index uint8) {
	if index != 0 && a.AdminFabricIndex == index {
		a.AdminFabricIndex = 0
		n.Changed(0, IDAdminCommissioning, acAdminFabricIndex)
	}
}

func (a *AdminCommissioning) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	if !ctx.Timed {
		return im.NeedsTimedInteraction
	}
	var (
		w       Window
		timeout uint64
		haveT   bool
		vb      []byte
		have    uint8
	)
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			timeout, err = r.Uint()
			haveT = true
		case 1:
			if cmd == acOpenCommissioningWindow {
				vb, err = r.Bytes()
				have |= 1
			}
		case 2:
			if cmd == acOpenCommissioningWindow {
				var d uint64
				d, err = r.Uint()
				w.Discriminator = uint16(d)
				if d > 0xFFF {
					return im.InvalidCommand
				}
				have |= 2
			}
		case 3:
			if cmd == acOpenCommissioningWindow {
				var it uint64
				it, err = r.Uint()
				if it > 0xFFFFFFFF {
					it = 0
				}
				w.Iterations = uint32(it)
				have |= 4
			}
		case 4:
			if cmd == acOpenCommissioningWindow {
				var s []byte
				s, err = r.Bytes()
				w.Salt = append([]byte(nil), s...)
				have |= 8
			}
		}
		return err
	})
	if err != nil {
		if st, ok := err.(im.Status); ok {
			return st
		}
		return im.InvalidCommand
	}

	var st AdminStatus
	switch cmd {
	case acOpenCommissioningWindow:
		if !haveT || have != 15 {
			return im.InvalidCommand
		}
		if w.Iterations < spake2p.MinIterations || w.Iterations > spake2p.MaxIterations ||
			len(w.Salt) < spake2p.MinSaltSize || len(w.Salt) > spake2p.MaxSaltSize {
			return resp.ClusterStatus(uint8(AdminPAKEParameterError))
		}
		if s := a.timeout(timeout, &w); s != im.Success {
			return s
		}
		if w.Verifier, err = spake2p.ParseVerifier(vb); err != nil {
			return resp.ClusterStatus(uint8(AdminPAKEParameterError))
		}
		st = a.open(ctx, &w)
	case acOpenBasicCommissioningWindow:
		if !haveT {
			return im.InvalidCommand
		}
		if s := a.timeout(timeout, &w); s != im.Success {
			return s
		}
		st = a.open(ctx, &w)
	case acRevokeCommissioning:
		st = AdminWindowNotOpen
		if a.Revoke != nil {
			st = a.Revoke(ctx)
		}
	default:
		return im.UnsupportedCommand
	}
	if st != AdminOK {
		return resp.ClusterStatus(uint8(st))
	}
	return im.Success
}

func (a *AdminCommissioning) timeout(v uint64, w *Window) im.Status {
	w.Timeout = time.Duration(v) * time.Second
	if w.Timeout < MinCommissioningTimeout || w.Timeout > MaxCommissioningTimeout {
		return im.InvalidCommand
	}
	return im.Success
}

func (a *AdminCommissioning) open(ctx *im.Context, w *Window) AdminStatus {
	if a.Open == nil {
		return AdminBusy
	}
	return a.Open(ctx, w)
}
