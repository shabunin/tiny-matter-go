// Package device assembles a Matter node: the session layer, PASE and CASE
// session establishment, the Interaction Model server with the root-node
// clusters, fabrics, access control, the commissioning fail-safe and DNS-SD
// advertising. Applications add their own endpoints to Node and drive the
// device with HandlePacket and Poll (sans-IO).
package device

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
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

	// Updates, if set, makes the node an OTA requestor: it adds the OTA
	// Software Update Requestor cluster, and images downloaded from a
	// provider are stored there and applied.
	Updates ImageStore
	// Resolve, if set, finds the address of another node on a fabric with
	// DNS-SD (mdns.NodeResolver does), for sessions the node opens itself,
	// such as to an OTA provider it has no session with. It is called
	// repeatedly until it reports the address.
	Resolve func(now time.Time, compressedFabricID [8]byte, nodeID uint64) (exchange.Addr, bool)
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
	// Software is the Software Diagnostics cluster, reporting the runtime's
	// heap.
	Software *clusters.SoftwareDiagnostics
	// WiFiDiagnostics is the Wi-Fi Network Diagnostics cluster (nil unless
	// Config.WiFi). Set its Status to report the association.
	WiFiDiagnostics *clusters.WiFiNetworkDiagnostics
	// Groups holds the group keys and memberships. Add a Groups cluster
	// (NewGroups) to each application endpoint that groups may address.
	Groups *clusters.GroupData
	// Resumptions keeps CASE resumption records, so controllers that
	// reconnect (also after a restart: they are saved) can skip the full
	// handshake.
	Resumptions *casesession.ResumptionStore
	// OnMulticast, if set, is called with the IPv6 multicast addresses of
	// the node's groups whenever they change; the network layer should
	// listen on exactly those (and on MulticastAddrs at start).
	OnMulticast func(addrs []netip.Addr)
	// OTA is the OTA Software Update Requestor cluster (nil unless
	// Config.Updates).
	OTA *clusters.OTARequestor
	// HoldSaves postpones writing the store while set, for example while a
	// BLE link would not survive the stall of a flash erase. Pending
	// changes are written by the first Poll after it is cleared.
	HoldSaves bool

	deferred []func(now time.Time)
	ota      *updater
	binder   *binder // commands on their way to bound nodes
	instance uint64  // commissionable instance name
	// The open commissioning window: its advertised discriminator and
	// commissioning mode, and when it closes (zero: no timeout).
	windowDisc     uint16
	windowMode     int
	windowDeadline time.Time
	dirty          bool     // persistent state changed since the last save
	stateBuf       []byte   // encoding buffer, reused (see encodeState)
	savedSum       [32]byte // SHA-256 of the last saved state
	started        bool     // the boot events were recorded
	eventLimit     uint64   // event numbers reserved in the store
	groupNext      uint32   // next group data message counter (0: not started)
	groupLimit     uint32   // group counter values from here on are unused (saved)
	// Application cluster state (im.Persister): stored entries not yet
	// restored into a cluster, and when changed state is next saved.
	appState   []appState
	appDirty   bool
	appWritten bool // a client wrote application state: save it now
	appSave    time.Time
}

// appSaveDelay is how long changes to application cluster state gather
// before they are saved, so a dimming transition costs one flash write.
const appSaveDelay = 3 * time.Second

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

		Resumptions: &casesession.ResumptionStore{Max: 2 * fabric.MaxFabrics},
	}
	// A new record is saved with the next batch of state changes: losing
	// it costs only a full handshake.
	d.Resumptions.OnChange = func() { d.appDirty = true }
	disp := securechannel.NewDispatcher(m)
	d.PASE, err = pase.NewResponder(m, disp, pase.ResponderConfig{
		Verifier: cfg.Verifier, Salt: cfg.Salt, Iterations: cfg.Iterations, Rand: cfg.Rand,
		OnEstablished:  func(now time.Time, s *exchange.Session) { d.log("PASE session established") },
		OnFailed:       func(now time.Time, err error) { d.log("PASE failed: " + err.Error()) },
		OnWindowClosed: d.closeWindow,
	})
	if err != nil {
		return nil, err
	}

	casesession.NewResponder(m, disp, casesession.ResponderConfig{
		Fabrics: d.Fabrics, Rand: cfg.Rand, Resumptions: d.Resumptions,
		OnEstablished: func(now time.Time, s *exchange.Session, f *fabric.Fabric) {
			if s.Resumed {
				d.log("CASE session resumed")
			} else {
				d.log("CASE session established")
			}
		},
		OnFailed: func(now time.Time, err error) { d.log("CASE failed: " + err.Error()) },
	})

	d.General = clusters.NewGeneralCommissioning(d.FailSafe)
	d.General.FabricIndex = func(ctx *im.Context) uint8 { return ctx.Session.FabricIndex }
	d.General.Complete = d.commissioningComplete
	d.General.WindowOpen = d.PASE.WindowOpen
	d.General.SetCountry = func(ctx *im.Context, code string) {
		if cfg.Basic.Location != code {
			cfg.Basic.Location = code
			ctx.Node.Changed(0, clusters.IDBasicInformation, 0x0006) // Location
		}
	}
	d.OpCreds = clusters.NewOperationalCredentials(cfg.Attestation, d.Fabrics, d.FailSafe, d.ACL, cfg.Rand)
	d.Groups = &clusters.GroupData{Fabrics: d.Fabrics}
	d.Groups.OnChange = func() {
		d.dirty = true
		if d.OnMulticast != nil {
			d.OnMulticast(d.Groups.MulticastAddrs())
		}
	}
	m.SetGroupKeys(d.Groups.Keys)
	d.OpCreds.OnFabricRemoved = func(now time.Time, index uint8) {
		d.Node.Events.RemoveFabric(index)
		d.Groups.RemoveFabric(index)
		d.Resumptions.ForgetFabric(index)
		d.removeFabricScenes(index)
		d.removeFabricBindings(index)
		if d.ota != nil {
			d.ota.removeFabric(now, index)
		}
		d.M.ForgetGroupPeers(index)
		d.later(func(now time.Time) {
			d.closeFabricSessions(now, index)
			d.Admin.ForgetFabric(d.Node, index)
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
		d.General.ResetBreadcrumb(d.Node)
		// The commissioner must prove the passcode again. Deferred so the
		// response to an ArmFailSafe(0) still goes out on the session.
		d.later(d.closePASESessions)
	})

	d.OpCreds.OnFabricLeave = func(now time.Time, index uint8) { cfg.Basic.Leave(d.Node, now, index) }
	d.OpCreds.OnFabricUpdated = func(now time.Time, index uint8, current *exchange.Session) {
		if current != nil {
			d.log("fabric credentials updated (pending commissioning complete)")
		} else {
			d.log("fabric credentials update rolled back")
		}
		d.Resumptions.ForgetFabric(index)
		// Sessions on the fabric belong to the old identity (or, on a
		// rollback, to the new one); the one carrying UpdateNOC stays for
		// its response.
		d.later(func(now time.Time) {
			for _, s := range d.M.Sessions() {
				if s.IsSecure() && s.FabricIndex == index && s != current {
					d.M.CloseSession(now, s)
				}
			}
		})
		d.advertise()
	}

	d.Admin = &clusters.AdminCommissioning{Open: d.adminOpen, Revoke: d.adminRevoke}
	d.Diagnostics = &clusters.GeneralDiagnostics{}
	d.Software = &clusters.SoftwareDiagnostics{Heap: clusters.RuntimeHeap}

	d.Root = d.Node.AddEndpoint(0, clusters.DeviceTypeRootNode)
	d.Node.AddCluster(d.Root, clusters.Descriptor{}, d.ACL, cfg.Basic, d.General, d.Diagnostics, d.Software, d.Admin, d.OpCreds,
		&clusters.GroupKeyManagement{Data: d.Groups})
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
		if cfg.WiFi {
			d.WiFiDiagnostics = &clusters.WiFiNetworkDiagnostics{}
			d.Node.AddCluster(d.Root, d.WiFiDiagnostics)
		}
	}
	if cfg.Updates != nil {
		d.enableOTA(cfg.Updates)
	}
	d.Server = im.NewServer(m, d.Node)
	d.Server.Access = d.ACL
	d.Server.GroupEndpoints = d.Groups.Endpoints
	// Clients write configuration (StartUpOnOff, OnLevel...) rarely, and
	// expect it kept across a restart right away: save without the delay.
	d.Server.OnWritten = func(p im.ConcretePath) {
		if d.persister(p.Endpoint, p.Cluster) != nil {
			d.appWritten = true
		}
	}
	d.Server.OnInvoked = func(ctx *im.Context, p im.CommandPath) {
		switch p.Cluster {
		case clusters.IDScenesManagement:
			// A scene table change is saved at once, like a write.
			if d.appDirty {
				d.appWritten = true
			}
		case clusters.IDOnOff, clusters.IDLevelControl, clusters.IDColorControl:
			// A command changing the lights makes the current scene
			// invalid (a recall changes them through Scenes Management).
			if e := d.Node.Endpoint(p.Endpoint); e != nil {
				if s, ok := e.Cluster(clusters.IDScenesManagement).(*clusters.ScenesManagement); ok {
					s.Invalidate(d.Node, p.Endpoint)
				}
			}
		}
	}
	serverHook := d.Node.OnChange // subscriptions
	d.Node.OnChange = func(p im.ConcretePath) {
		if persistent(p) {
			d.dirty = true
		} else if d.persister(p.Endpoint, p.Cluster) != nil {
			d.appDirty = true
		}
		serverHook(p)
	}
	d.Node.OnAddCluster = d.restoreCluster
	if cfg.Store != nil {
		if err := d.load(); err != nil {
			d.log("stored state ignored: " + err.Error())
		} else if n := d.Fabrics.Committed(); n > 0 {
			d.log("restored " + strconv.Itoa(n) + " fabric(s)")
		}
		d.savedSum = sha256.Sum256(d.encodeState())
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

// NewGroups returns a Groups cluster over the device's groups, for an
// application endpoint; identify, if not nil, is the endpoint's Identify
// cluster (for AddGroupIfIdentifying).
func (d *Device) NewGroups(identify *clusters.Identify) *clusters.Groups {
	return &clusters.Groups{Data: d.Groups, Identify: identify}
}

// NewScenes returns a Scenes Management cluster over the device's groups,
// for an application endpoint. Pass it to the endpoint's Groups cluster
// and On/Off cluster too (Groups.Scenes, OnOff.Scenes).
func (d *Device) NewScenes() *clusters.ScenesManagement { return clusters.NewScenes(d.Groups) }

// AddedEndpoint reports an application endpoint added after start, such
// as a newly bridged device: add the endpoint and its clusters to Node,
// then call this. Its saved state (if any) was restored as its clusters
// were added.
func (d *Device) AddedEndpoint(id uint16) { d.Node.EndpointAdded(id) }

// RemoveEndpoint removes an application endpoint and its descendants
// after start, such as a bridged device that is gone for good: their
// group memberships and saved state go with them.
func (d *Device) RemoveEndpoint(id uint16) {
	if id == 0 {
		return
	}
	var ids []uint16
	ids = append(d.Node.Parts(id, ids), id)
	d.Node.RemoveEndpoint(id)
	for _, ep := range ids {
		d.Groups.ForgetEndpoint(d.Node, ep)
	}
	d.dirty = true
}

// removeFabricScenes deletes a removed fabric's scenes on every endpoint.
func (d *Device) removeFabricScenes(index uint8) {
	for _, e := range d.Node.Endpoints() {
		if s, ok := e.Cluster(clusters.IDScenesManagement).(*clusters.ScenesManagement); ok {
			s.RemoveFabric(d.Node, e.ID, index)
		}
	}
}

// MulticastAddrs returns the IPv6 multicast addresses of the node's
// groups, which the network layer should listen on.
func (d *Device) MulticastAddrs() []netip.Addr { return d.Groups.MulticastAddrs() }

// Commissioned reports whether the node belongs to at least one fabric.
// Applications typically open the commissioning window when it does not.
func (d *Device) Commissioned() bool { return d.Fabrics.Committed() > 0 }

func (d *Device) log(msg string) {
	if d.cfg.Log != nil {
		d.cfg.Log(msg)
	}
}

func (d *Device) later(f func(now time.Time)) { d.deferred = append(d.deferred, f) }

func (d *Device) runDeferred(now time.Time) {
	for len(d.deferred) > 0 {
		f := d.deferred[0]
		d.deferred = d.deferred[1:]
		f(now)
	}
}

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
		if d.ota != nil && d.ota.updated() {
			d.Diagnostics.BootReason = clusters.BootSoftwareUpdate
		}
		d.cfg.Basic.StartUp(d.Node, now)
		d.Diagnostics.BootReasonEvent(d.Node, now)
		if d.ota != nil {
			d.ota.boot(now)
		}
	}
	d.runDeferred(now)
	if d.appDirty {
		d.appDirty = false
		if d.appSave.IsZero() {
			d.appSave = now.Add(appSaveDelay)
		}
	}
	if d.appWritten {
		d.appWritten = false
		d.appSave = now
	}
	if !d.appSave.IsZero() && !now.Before(d.appSave) {
		d.appSave = time.Time{}
		d.dirty = true
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
	if t := d.appSave; !t.IsZero() && (next.IsZero() || t.Before(next)) {
		next = t
	}
	if d.ota != nil {
		if t := d.ota.poll(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	if d.binder != nil {
		if t := d.binder.poll(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	d.runDeferred(now)
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
	if d.FailSafe.Armed(ctx.Now) {
		idx := d.FailSafe.FabricIndex()
		if idx == 0 {
			d.FailSafe.Expire(ctx.Now)
		} else if f := d.Fabrics.Get(idx); f != nil && f.Pending {
			d.FailSafe.Expire(ctx.Now)
		}
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
