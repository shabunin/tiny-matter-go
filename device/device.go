// Package device assembles a Matter node: the session layer, PASE and CASE
// session establishment, the Interaction Model server with the root-node
// clusters, fabrics, access control, the commissioning fail-safe and DNS-SD
// advertising. Applications add their own endpoints to Node and drive the
// device with HandlePacket and Poll (sans-IO).
package device

import (
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/dnssd"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/securechannel/pase"
	"github.com/shabunin/tiny-matter-go/storage"
)

// Config configures a device.
type Config struct {
	Transport exchange.Transport
	Rand      io.Reader
	Port      uint16 // UDP port, for DNS-SD (default 5540)

	// Commissioning: the passcode verifier with its PBKDF parameters.
	Verifier      *spake2p.Verifier
	Salt          []byte
	Iterations    uint32
	Discriminator uint16

	Attestation *clusters.Attestation
	// Basic is the Basic Information cluster; VendorID and ProductID must
	// match the attestation credentials.
	Basic *clusters.BasicInformation
	// DeviceType is advertised while commissionable.
	DeviceType uint32

	Advertiser dnssd.Advertiser // optional
	Log        func(msg string) // optional

	// Store, if set, keeps fabrics and the ACL across restarts. New loads
	// it; changes are saved from Poll.
	Store storage.Store

	// Clock, if set, returns the current time (time.Now on real
	// hardware); see exchange.Config.Clock.
	Clock func() time.Time

	// WiFi adds the Network Commissioning cluster (Wi-Fi, non-concurrent),
	// so a commissioner can provision the network, typically over BLE.
	// Set Net.Connect (and optionally Net.Scan) after New.
	WiFi bool
	// Thread adds it for a Thread interface instead: the commissioner
	// provisions an operational dataset. Set Net.Connect (and optionally
	// Net.ScanThread, ThreadFeatures and ThreadVersion) after New.
	Thread bool
}

// Device is a Matter node.
type Device struct {
	cfg      Config
	M        *exchange.Manager
	Node     *im.Node
	Root     *im.Endpoint
	Server   *im.Server
	Fabrics  *fabric.Table
	ACL      *clusters.AccessControl
	FailSafe *clusters.FailSafe
	PASE     *pase.Responder
	General  *clusters.GeneralCommissioning
	OpCreds  *clusters.OperationalCredentials
	Admin    *clusters.AdminCommissioning
	// Net is the Network Commissioning cluster (nil unless Config.WiFi or
	// Config.Thread).
	Net *clusters.NetworkCommissioning
	// Diagnostics is the General Diagnostics cluster. Set its BootReason
	// and Interfaces before the first Poll, which records the boot events.
	Diagnostics *clusters.GeneralDiagnostics
	// HoldSaves postpones writing the store while set, for example while a
	// BLE link would not survive the stall of a flash erase. Pending
	// changes are written by the first Poll after it is cleared.
	HoldSaves bool

	deferred []func(now time.Time)
	instance uint64 // commissionable instance name
	// The open commissioning window: its advertised discriminator and
	// commissioning mode, and when it closes (zero: no timeout).
	windowDisc     uint16
	windowMode     int
	windowDeadline time.Time
	dirty          bool   // persistent state changed since the last save
	saved          []byte // last saved state
	started        bool   // the boot events were recorded
	eventLimit     uint64 // event numbers reserved in the store
}

// New creates a device. Its commissioning window starts closed; call
// OpenCommissioningWindow (typically when no fabric is configured).
func New(cfg Config) (*Device, error) {
	if cfg.Transport == nil || cfg.Rand == nil || cfg.Attestation == nil || cfg.Basic == nil {
		return nil, errors.New("device: Transport, Rand, Attestation and Basic are required")
	}
	if cfg.WiFi && cfg.Thread {
		return nil, errors.New("device: one network interface: Wi-Fi or Thread")
	}
	if cfg.Port == 0 {
		cfg.Port = 5540
	}
	m, err := exchange.NewManager(exchange.Config{Transport: cfg.Transport, Rand: cfg.Rand, Clock: cfg.Clock})
	if err != nil {
		return nil, err
	}
	var seed [4]byte
	io.ReadFull(cfg.Rand, seed[:])
	d := &Device{
		cfg: cfg, M: m,
		Node:     im.NewNode(binary.LittleEndian.Uint32(seed[:])),
		Fabrics:  &fabric.Table{},
		ACL:      &clusters.AccessControl{},
		FailSafe: &clusters.FailSafe{},
	}
	disp := securechannel.NewDispatcher(m)
	d.PASE, err = pase.NewResponder(m, disp, pase.ResponderConfig{
		Verifier: cfg.Verifier, Salt: cfg.Salt, Iterations: cfg.Iterations, Rand: cfg.Rand,
		OnEstablished: func(now time.Time, s *exchange.Session) { d.log("PASE session established") },
		OnFailed:      func(now time.Time, err error) { d.log("PASE failed: " + err.Error()) },
	})
	if err != nil {
		return nil, err
	}

	casesession.NewResponder(m, disp, casesession.ResponderConfig{
		Fabrics: d.Fabrics, Rand: cfg.Rand,
		OnEstablished: func(now time.Time, s *exchange.Session, f *fabric.Fabric) {
			d.log("CASE session established")
		},
		OnFailed: func(now time.Time, err error) { d.log("CASE failed: " + err.Error()) },
	})

	d.General = clusters.NewGeneralCommissioning(d.FailSafe)
	d.General.FabricIndex = func(ctx *im.Context) uint8 { return ctx.Session.FabricIndex }
	d.General.Complete = d.commissioningComplete
	d.OpCreds = clusters.NewOperationalCredentials(cfg.Attestation, d.Fabrics, d.FailSafe, d.ACL, cfg.Rand)
	d.OpCreds.OnFabricRemoved = func(now time.Time, index uint8) {
		d.Node.Events.RemoveFabric(index)
		d.later(func(now time.Time) {
			d.closeFabricSessions(now, index)
			if d.Admin.AdminFabricIndex == index {
				d.Admin.SetWindow(d.Node, d.Admin.WindowStatus, 0, 0)
			}
			if d.Fabrics.Committed() == 0 && len(d.Fabrics.Fabrics()) == 0 && !d.PASE.WindowOpen() {
				d.log("last fabric removed: opening the commissioning window")
				d.OpenCommissioningWindow()
			}
		})
		d.advertise()
	}
	d.OpCreds.OnFabricAdded = func(now time.Time, f *fabric.Fabric) {
		d.log("fabric added (pending commissioning complete)")
		d.advertise()
	}
	d.FailSafe.OnExpire = append(d.FailSafe.OnExpire, func(now time.Time) {
		d.log("fail-safe expired: commissioning rolled back")
	})

	d.OpCreds.OnFabricLeave = func(now time.Time, index uint8) { cfg.Basic.Leave(d.Node, now, index) }

	d.Admin = &clusters.AdminCommissioning{Open: d.adminOpen, Revoke: d.adminRevoke}
	d.Diagnostics = &clusters.GeneralDiagnostics{}

	d.Root = d.Node.AddEndpoint(0, clusters.DeviceTypeRootNode)
	d.Node.AddCluster(d.Root, clusters.Descriptor{}, d.ACL, cfg.Basic, d.General, d.Diagnostics, d.Admin, d.OpCreds)
	if cfg.WiFi || cfg.Thread {
		d.Net = clusters.NewNetworkCommissioning(d.FailSafe, nil)
		d.Net.Thread = cfg.Thread
		d.Net.FabricIndex = d.General.FabricIndex
		d.General.SupportsConcurrentConnection = false
		d.FailSafe.OnExpire = append(d.FailSafe.OnExpire, func(now time.Time) {
			if d.Net.Rollback(d.Node) {
				d.log("network configuration rolled back")
			}
		})
		d.Node.AddCluster(d.Root, d.Net)
	}
	d.Server = im.NewServer(m, d.Node)
	d.Server.Access = d.ACL
	serverHook := d.Node.OnChange // subscriptions
	d.Node.OnChange = func(p im.ConcretePath) {
		if persistent(p) {
			d.dirty = true
		}
		serverHook(p)
	}
	if cfg.Store != nil {
		if err := d.load(); err != nil {
			d.log("stored state ignored: " + err.Error())
		} else if n := d.Fabrics.Committed(); n > 0 {
			d.log("restored " + strconv.Itoa(n) + " fabric(s)")
		}
		d.saved = d.encodeState()
		// Event numbers continue past those reserved before the restart,
		// and the reboot is counted; both are saved now.
		d.eventLimit = d.Node.Events.Start(d.eventLimit)
		d.Node.Events.OnReserve = func(limit uint64) {
			d.eventLimit = limit
			d.dirty = true
		}
		if d.Diagnostics.RebootCount < 0xFFFF {
			d.Diagnostics.RebootCount++
		}
		d.save()
		d.advertise()
	}
	if cfg.Clock != nil {
		d.boot(cfg.Clock())
	}
	return d, nil
}

// boot sets the time the node booted.
func (d *Device) boot(t time.Time) {
	d.Node.Events.Boot = t
	d.Diagnostics.Boot = t
}

// Commissioned reports whether the node belongs to at least one fabric.
// Applications typically open the commissioning window when it does not.
func (d *Device) Commissioned() bool { return d.Fabrics.Committed() > 0 }

func (d *Device) log(msg string) {
	if d.cfg.Log != nil {
		d.cfg.Log(msg)
	}
}

func (d *Device) later(f func(now time.Time)) { d.deferred = append(d.deferred, f) }

// HandlePacket processes a received UDP datagram.
func (d *Device) HandlePacket(now time.Time, from exchange.Addr, pkt []byte) error {
	return d.M.HandlePacket(now, from, pkt)
}

// Poll runs timers and deferred work, returning when it next needs to run
// (zero if idle).
func (d *Device) Poll(now time.Time) time.Time {
	if !d.started {
		d.started = true
		if d.Diagnostics.Boot.IsZero() {
			d.boot(now)
		}
		d.cfg.Basic.StartUp(d.Node, now)
		d.Diagnostics.BootReasonEvent(d.Node, now)
	}
	for len(d.deferred) > 0 {
		f := d.deferred[0]
		d.deferred = d.deferred[1:]
		f(now)
	}
	if d.dirty && !d.HoldSaves {
		d.dirty = false
		d.save()
	}
	if !d.windowDeadline.IsZero() && !now.Before(d.windowDeadline) {
		d.log("commissioning window timed out")
		d.closeWindow()
	}
	next := d.M.Poll(now)
	if t := d.windowDeadline; !t.IsZero() && (next.IsZero() || t.Before(next)) {
		next = t
	}
	if t := d.FailSafe.Poll(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
		next = t
	}
	if t := d.Node.Poll(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
		next = t
	}
	if t := d.Server.Poll(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
		next = t
	}
	return next
}

// OpenCommissioningWindow allows commissioning with the passcode and
// advertises the commissionable service, until commissioning completes.
func (d *Device) OpenCommissioningWindow() {
	d.PASE.OpenWindow()
	d.windowOpened(clusters.WindowBasicOpen, d.cfg.Discriminator, 1, time.Time{}, 0)
}

func (d *Device) windowOpened(status uint8, disc uint16, mode int, deadline time.Time, fabricIndex uint8) {
	var b [8]byte
	io.ReadFull(d.cfg.Rand, b[:])
	d.instance = binary.LittleEndian.Uint64(b[:])
	d.windowDisc, d.windowMode, d.windowDeadline = disc, mode, deadline
	var vendor uint16
	if f := d.Fabrics.Get(fabricIndex); f != nil {
		vendor = f.VendorID
	} else {
		fabricIndex = 0
	}
	d.Admin.SetWindow(d.Node, status, fabricIndex, vendor)
	d.advertise()
}

// closeWindow stops accepting PASE and commissionable advertising.
func (d *Device) closeWindow() {
	d.PASE.CloseWindow()
	d.windowDeadline = time.Time{}
	d.Admin.SetWindow(d.Node, clusters.WindowNotOpen, 0, 0)
	d.advertise()
}

// adminOpen implements OpenCommissioningWindow and
// OpenBasicCommissioningWindow.
func (d *Device) adminOpen(ctx *im.Context, w *clusters.Window) clusters.AdminStatus {
	if d.PASE.WindowOpen() || d.FailSafe.Armed(ctx.Now) {
		return clusters.AdminBusy
	}
	deadline := ctx.Now.Add(w.Timeout)
	if w.Verifier == nil {
		d.PASE.OpenWindow()
		d.windowOpened(clusters.WindowBasicOpen, d.cfg.Discriminator, 1, deadline, ctx.Session.FabricIndex)
		d.log("basic commissioning window opened")
		return clusters.AdminOK
	}
	if !d.PASE.OpenWindowWith(pase.WindowParams{Verifier: w.Verifier, Salt: w.Salt, Iterations: w.Iterations}) {
		return clusters.AdminPAKEParameterError
	}
	d.windowOpened(clusters.WindowEnhancedOpen, w.Discriminator, 2, deadline, ctx.Session.FabricIndex)
	d.log("enhanced commissioning window opened, discriminator " + strconv.Itoa(int(w.Discriminator)))
	return clusters.AdminOK
}

// adminRevoke implements RevokeCommissioning: it closes the window and
// aborts a commissioning started through it.
func (d *Device) adminRevoke(ctx *im.Context) clusters.AdminStatus {
	if !d.PASE.WindowOpen() {
		return clusters.AdminWindowNotOpen
	}
	d.closeWindow()
	if d.FailSafe.Armed(ctx.Now) && d.FailSafe.FabricIndex() == 0 {
		d.FailSafe.Expire(ctx.Now)
	}
	d.later(d.closePASESessions)
	d.log("commissioning window revoked")
	return clusters.AdminOK
}

// commissioningComplete commits the fabric added under the fail-safe. It
// is called by GeneralCommissioning once the fail-safe is armed.
func (d *Device) commissioningComplete(ctx *im.Context) clusters.CommissioningError {
	s := ctx.Session
	if s.AuthMode != exchange.AuthCASE || s.FabricIndex == 0 || s.FabricIndex != d.FailSafe.FabricIndex() {
		return clusters.InvalidAuthentication
	}
	d.Fabrics.Commit()
	if d.Net != nil {
		d.Net.Commit()
	}
	d.dirty = true
	d.OpCreds.Reset()
	d.closeWindow()
	d.later(d.closePASESessions)
	d.log("commissioning complete")
	d.advertise()
	return clusters.CommissioningOK
}

func (d *Device) closePASESessions(now time.Time) {
	for _, s := range d.M.Sessions() {
		if s.AuthMode == exchange.AuthPASE {
			d.M.CloseSession(now, s)
		}
	}
}

func (d *Device) closeFabricSessions(now time.Time, index uint8) {
	for _, s := range d.M.Sessions() {
		if s.IsSecure() && s.FabricIndex == index {
			d.M.CloseSession(now, s)
		}
	}
}

func (d *Device) mrp() dnssd.MRP {
	p := securechannel.DefaultSessionParams.MRP
	return dnssd.MRP{Idle: p.IdleInterval, Active: p.ActiveInterval, ActiveThreshold: p.ActiveThreshold}
}

// advertise publishes the current DNS-SD services.
func (d *Device) advertise() {
	if d.cfg.Advertiser == nil {
		return
	}
	var svcs []dnssd.Service
	if d.PASE.WindowOpen() {
		c := dnssd.Commissionable{
			Instance: d.instance, Port: d.cfg.Port, Discriminator: d.windowDisc,
			VendorID: d.cfg.Basic.VendorID, ProductID: d.cfg.Basic.ProductID,
			DeviceType: d.cfg.DeviceType, DeviceName: d.cfg.Basic.ProductName, MRP: d.mrp(), Mode: d.windowMode,
		}
		svcs = append(svcs, c.Service())
	}
	for _, f := range d.Fabrics.Fabrics() {
		o := dnssd.Operational{CompressedFabricID: f.CompressedFabricID, NodeID: f.NodeID, Port: d.cfg.Port, MRP: d.mrp()}
		svcs = append(svcs, o.Service())
	}
	d.cfg.Advertiser.Advertise(svcs)
}
