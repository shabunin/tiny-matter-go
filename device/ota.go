package device

import (
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/bdx"
	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/ota"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// ImageStore keeps a downloaded software image until it is applied: a
// spare firmware slot, or a file on a host. The device checks the image's
// header (vendor, product, version) and its digest.
type ImageStore interface {
	// Begin starts storing the payload of an image.
	Begin(h *ota.Header) error
	// Write stores the next piece of the payload.
	Write(p []byte) error
	// Finish ends storing a complete payload whose digest matched.
	Finish() error
	// Abort discards a partly or completely stored image.
	Abort()
	// Apply makes the stored image the one to run and restarts the node
	// with it. It returns only if that failed.
	Apply() error
}

// OTA timing (as the SDK's requestor).
const (
	otaPeriodicQuery = 24 * time.Hour
	otaBusyRetry     = 2 * time.Minute
	otaMaxBusy       = 4
	otaStall         = 5 * time.Minute
	otaWatchdog      = 6 * time.Hour
	otaNotifyDelay   = 10 * time.Second
)

var errOTAProvider = errors.New("ota: unusable provider response")

// otaPending is the update being applied, saved before ApplyUpdateRequest
// so the node can tell the provider after it restarts.
type otaPending struct {
	provider clusters.ProviderLocation
	token    []byte
	target   uint32
	addr     netip.AddrPort // the provider's last address, if known
}

// updater drives the OTA requestor: it queries a provider, downloads the
// image over BDX into the ImageStore, and applies it.
type updater struct {
	d     *Device
	c     *clusters.OTARequestor
	store ImageStore

	provider clusters.ProviderLocation
	addr     netip.AddrPort // where the provider was last heard from
	busy     int            // Busy answers to the current query
	started  time.Time      // the attempt started (watchdog)

	// The next step and when to take it.
	at   time.Time
	step func(now time.Time)

	inv    *im.Invocation
	dl     *bdx.Download
	reader *ota.Reader
	stored bool // the store holds part of an image
	last   time.Time

	token      []byte
	target     uint32
	designator string

	quiet     bool        // failures are only logged (NotifyUpdateApplied)
	pending   *otaPending // saved while applying
	periodic  time.Time
	nextQuery int // round robin over default providers
}

// enableOTA adds the OTA Software Update Requestor cluster.
func (d *Device) enableOTA(store ImageStore) {
	u := &updater{d: d, c: clusters.NewOTARequestor(), store: store}
	u.c.Announce = u.announce
	u.c.OnChange = func() { d.dirty = true }
	d.ota = u
	d.OTA = u.c
	d.Root.DeviceTypes = append(d.Root.DeviceTypes, clusters.DeviceTypeOTARequestor)
	d.Node.AddCluster(d.Root, u.c)
}

// CheckForUpdate queries the default OTA providers for an update now,
// unless an update is in progress. It reports whether a query started.
func (d *Device) CheckForUpdate(now time.Time) bool {
	if d.ota == nil || d.ota.c.State() != clusters.OTAStateIdle || d.ota.step != nil {
		return false
	}
	return d.ota.queryDefault(now)
}

func (u *updater) log(msg string) { u.d.log("ota: " + msg) }

func (u *updater) schedule(at time.Time, f func(now time.Time)) { u.at, u.step = at, f }

func (u *updater) setState(now time.Time, state, reason uint8) {
	u.c.SetState(u.d.Node, now, state, reason, u.target)
}

// updated reports whether the node restarted into the version an update
// installed.
func (u *updater) updated() bool {
	return u.pending != nil && u.d.cfg.Basic.SoftwareVersion == u.pending.target
}

// boot finishes an update applied before the restart (first Poll).
func (u *updater) boot(now time.Time) {
	u.periodic = now.Add(otaPeriodicQuery)
	p := u.pending
	if p == nil {
		return
	}
	u.provider, u.addr, u.token, u.target = p.provider, p.addr, p.token, p.target
	basic := u.d.cfg.Basic
	if basic.SoftwareVersion != p.target {
		u.log("version " + strconv.FormatUint(uint64(p.target), 10) + " did not start; running " +
			strconv.FormatUint(uint64(basic.SoftwareVersion), 10))
		u.c.DownloadError(u.d.Node, now, p.target, 0, -1)
		u.setState(now, clusters.OTAStateIdle, clusters.OTAReasonFailure)
		u.pending = nil
		u.d.dirty = true
		return
	}
	u.log("running version " + basic.SoftwareVersionString)
	u.c.VersionApplied(u.d.Node, now, basic.SoftwareVersion, basic.ProductID)
	u.setState(now, clusters.OTAStateIdle, clusters.OTAReasonSuccess)
	u.pending = nil
	u.d.dirty = true
	// Tell the provider once the network is likely up.
	u.quiet = true
	u.schedule(now.Add(otaNotifyDelay), u.notify)
}

// notify sends NotifyUpdateApplied; failures are only logged.
func (u *updater) notify(now time.Time) {
	token, version := u.token, u.d.cfg.Basic.SoftwareVersion
	u.withSession(now, func(now time.Time, s *exchange.Session) {
		u.invoke(now, s, clusters.CmdNotifyUpdateApplied, clusters.EncodeTokenVersion(token, version),
			func(now time.Time, res im.InvokeResult) {
				u.log("provider notified")
				u.reset()
			})
	})
}

// announce takes AnnounceOTAProvider: query the announced provider soon,
// unless an update is under way.
func (u *updater) announce(ctx *im.Context, a *clusters.Announcement) {
	if u.c.State() != clusters.OTAStateIdle || u.step != nil {
		return
	}
	u.provider, u.addr = a.Provider, netip.AddrPort{}
	if s := ctx.Session; s != nil && s.PeerNodeID() == a.Provider.NodeID {
		u.addr = s.Peer
	}
	delay := time.Duration(0)
	if a.Reason == clusters.OTAAnnounceUrgent {
		delay = time.Second
	}
	u.log("provider announced: node " + strconv.FormatUint(a.Provider.NodeID, 16))
	u.schedule(ctx.Now.Add(delay), u.query)
}

// queryDefault queries the next default provider.
func (u *updater) queryDefault(now time.Time) bool {
	ps := u.c.Providers
	if len(ps) == 0 {
		return false
	}
	u.nextQuery %= len(ps)
	u.provider, u.addr = ps[u.nextQuery], netip.AddrPort{}
	u.nextQuery++
	u.schedule(now, u.query)
	return true
}

// reset ends the attempt.
func (u *updater) reset() {
	u.step, u.at, u.inv, u.dl, u.reader = nil, time.Time{}, nil, nil, nil
	u.busy, u.started, u.quiet = 0, time.Time{}, false
	u.token, u.target, u.designator = nil, 0, ""
}

// fail ends the attempt with an error.
func (u *updater) fail(now time.Time, reason uint8, err error) {
	if u.quiet {
		u.log("notifying the provider failed: " + err.Error())
		u.reset()
		return
	}
	u.log("update failed: " + err.Error())
	var received uint64
	progress := -1
	if u.reader != nil {
		received = u.reader.Received()
		if u.reader.HeaderParsed() && u.reader.Header.PayloadSize > 0 {
			progress = int(received * 100 / u.reader.Header.PayloadSize)
		}
	}
	if u.stored {
		u.store.Abort()
		u.stored = false
	}
	if u.pending != nil {
		u.pending = nil
		u.d.dirty = true
	}
	u.c.DownloadError(u.d.Node, now, u.target, received, progress)
	u.setState(now, clusters.OTAStateIdle, reason)
	u.reset()
}

// fabric returns the fabric of the current provider.
func (u *updater) fabric() *fabric.Fabric {
	f := u.d.Fabrics.Get(u.provider.FabricIndex)
	if f == nil || f.Pending {
		return nil
	}
	return f
}

// withSession runs f with a CASE session to the provider: an open one, or
// one established with the provider's last known address.
func (u *updater) withSession(now time.Time, f func(now time.Time, s *exchange.Session)) {
	fab := u.fabric()
	if fab == nil {
		u.fail(now, clusters.OTAReasonFailure, errors.New("provider fabric gone"))
		return
	}
	var best *exchange.Session
	for _, s := range u.d.M.Sessions() {
		if s.IsSecure() && !s.Closed() && s.AuthMode == exchange.AuthCASE && s.FabricIndex == fab.Index &&
			s.PeerNodeID() == u.provider.NodeID {
			best = s
		}
	}
	if best != nil {
		u.addr = best.Peer
		f(now, best)
		return
	}
	if !u.addr.IsValid() {
		u.fail(now, clusters.OTAReasonFailure, errors.New("no session to the provider and no address for it"))
		return
	}
	u.step = func(time.Time) {} // waiting
	u.at = time.Time{}
	err := casesession.Connect(now, u.d.M, u.addr, casesession.InitiatorConfig{
		Fabric: fab, PeerNodeID: u.provider.NodeID, Rand: u.d.cfg.Rand, Resumptions: u.d.Resumptions,
		Done: func(now time.Time, s *exchange.Session, err error) {
			if err != nil {
				u.fail(now, clusters.OTAReasonFailure, err)
				return
			}
			f(now, s)
		},
	})
	if err != nil {
		u.fail(now, clusters.OTAReasonFailure, err)
	}
}

// invoke calls a provider command, passing a successful result on.
func (u *updater) invoke(now time.Time, s *exchange.Session, cmd uint32, fields func(w *tlv.Writer), ok func(now time.Time, res im.InvokeResult)) {
	inv := &im.Invocation{Done: func(now time.Time, res im.InvokeResult, err error) {
		u.inv = nil
		if err == nil && res.Status != im.Success {
			err = res.Status
		}
		if err != nil {
			u.fail(now, clusters.OTAReasonFailure, err)
			return
		}
		ok(now, res)
	}}
	u.inv = inv
	u.step, u.at = func(time.Time) {}, time.Time{}
	p := im.CommandPath{Endpoint: u.provider.Endpoint, Cluster: clusters.IDOTAProvider, Command: cmd}
	if err := inv.Start(now, u.d.M, s, p, fields); err != nil {
		u.inv = nil
		u.fail(now, clusters.OTAReasonFailure, err)
	}
}

// query sends QueryImage.
func (u *updater) query(now time.Time) {
	if u.started.IsZero() {
		u.started = now
	}
	u.setState(now, clusters.OTAStateQuerying, clusters.OTAReasonSuccess)
	basic := u.d.cfg.Basic
	q := clusters.QueryImage{
		VendorID: basic.VendorID, ProductID: basic.ProductID, SoftwareVersion: basic.SoftwareVersion,
		Protocols:       []uint8{clusters.OTAProtocolBDXSynchronous},
		HardwareVersion: basic.HardwareVersion, HasHardwareVersion: true,
	}
	if len(basic.Location) == 2 {
		q.Location = basic.Location
	}
	u.withSession(now, func(now time.Time, s *exchange.Session) {
		u.invoke(now, s, clusters.CmdQueryImage, q.Encode, u.queried)
	})
}

// queried handles QueryImageResponse.
func (u *updater) queried(now time.Time, res im.InvokeResult) {
	r, err := clusters.DecodeQueryImageResponse(res.Fields)
	if err != nil {
		u.fail(now, clusters.OTAReasonFailure, err)
		return
	}
	delay := time.Duration(r.DelayedActionTime) * time.Second
	switch r.Status {
	case clusters.OTAUpdateAvailable:
	case clusters.OTABusy:
		if u.busy++; u.busy >= otaMaxBusy {
			u.fail(now, clusters.OTAReasonDelayByProvider, errors.New("provider busy"))
			return
		}
		u.setState(now, clusters.OTAStateDelayedOnQuery, clusters.OTAReasonDelayByProvider)
		u.schedule(now.Add(max(delay, otaBusyRetry)), u.query)
		return
	case clusters.OTANotAvailable:
		u.log("no update available")
		u.setState(now, clusters.OTAStateIdle, clusters.OTAReasonSuccess)
		u.reset()
		return
	default:
		u.fail(now, clusters.OTAReasonFailure, errors.New("provider status "+strconv.Itoa(int(r.Status))))
		return
	}
	node, designator, err := clusters.ParseBDXURI(r.ImageURI)
	switch {
	case err != nil:
		u.fail(now, clusters.OTAReasonFailure, err)
		return
	case node != u.provider.NodeID:
		u.fail(now, clusters.OTAReasonFailure, errors.New("image on another node"))
		return
	case r.SoftwareVersion <= u.d.cfg.Basic.SoftwareVersion:
		u.log("provider offers no newer version")
		u.setState(now, clusters.OTAStateIdle, clusters.OTAReasonSuccess)
		u.reset()
		return
	}
	u.token, u.target, u.designator = r.UpdateToken, r.SoftwareVersion, designator
	u.log("update to " + r.SoftwareVersionString + " available")
	u.schedule(now.Add(delay), u.download)
}

// download fetches the image over BDX.
func (u *updater) download(now time.Time) {
	u.setState(now, clusters.OTAStateDownloading, clusters.OTAReasonSuccess)
	basic := u.d.cfg.Basic
	u.reader = &ota.Reader{
		OnHeader: func(h *ota.Header) error {
			switch {
			case h.VendorID != basic.VendorID || h.ProductID != basic.ProductID:
				return &bdx.Error{Code: bdx.StatusBadMessageContents}
			case h.SoftwareVersion != u.target || !h.Applies(basic.SoftwareVersion) || h.PayloadSize == 0:
				return &bdx.Error{Code: bdx.StatusBadMessageContents}
			}
			if err := u.store.Begin(h); err != nil {
				return err
			}
			u.stored = true
			u.c.SetProgress(u.d.Node, 0, true)
			return nil
		},
		Payload: func(p []byte) error {
			if err := u.store.Write(p); err != nil {
				return err
			}
			h := &u.reader.Header
			u.c.SetProgress(u.d.Node, uint8(u.reader.Received()*100/h.PayloadSize), true)
			return nil
		},
	}
	u.withSession(now, func(now time.Time, s *exchange.Session) {
		u.last = now
		u.dl = &bdx.Download{
			Write: func(now time.Time, p []byte) error {
				u.last = now
				return u.reader.Write(p)
			},
			Done: u.downloaded,
		}
		u.step, u.at = func(time.Time) {}, time.Time{}
		if err := u.dl.Start(now, u.d.M, s, []byte(u.designator), 0); err != nil {
			u.dl = nil
			u.fail(now, clusters.OTAReasonFailure, err)
		}
	})
}

func (u *updater) downloaded(now time.Time, err error) {
	u.dl = nil
	if err == nil {
		err = u.reader.Close()
	}
	if err == nil {
		err = u.store.Finish()
	}
	if err != nil {
		u.fail(now, clusters.OTAReasonFailure, err)
		return
	}
	u.log("image downloaded and verified")
	u.applyRequest(now)
}

// applyRequest saves the update, then asks the provider to apply it.
func (u *updater) applyRequest(now time.Time) {
	u.setState(now, clusters.OTAStateApplying, clusters.OTAReasonSuccess)
	u.pending = &otaPending{provider: u.provider, token: u.token, target: u.target, addr: u.addr}
	u.d.save()
	u.withSession(now, func(now time.Time, s *exchange.Session) {
		u.invoke(now, s, clusters.CmdApplyUpdateRequest, clusters.EncodeTokenVersion(u.token, u.target), u.applyResponse)
	})
}

func (u *updater) applyResponse(now time.Time, res im.InvokeResult) {
	action, delay, err := clusters.DecodeApplyUpdateResponse(res.Fields)
	if err != nil {
		u.fail(now, clusters.OTAReasonFailure, err)
		return
	}
	wait := time.Duration(delay) * time.Second
	switch action {
	case clusters.OTAApplyProceed:
		u.log("applying the update")
		u.schedule(now.Add(wait), u.apply)
	case clusters.OTAApplyAwaitNextAction:
		u.setState(now, clusters.OTAStateDelayedOnApply, clusters.OTAReasonDelayByProvider)
		u.schedule(now.Add(max(wait, otaBusyRetry)), u.applyRequest)
	default:
		u.log("provider discontinued the update")
		u.store.Abort()
		u.stored = false
		u.pending = nil
		u.d.dirty = true
		u.setState(now, clusters.OTAStateIdle, clusters.OTAReasonSuccess)
		u.reset()
	}
}

// apply switches to the new image; on success the node restarts.
func (u *updater) apply(now time.Time) {
	u.d.dirty = true
	u.d.save()
	if err := u.store.Apply(); err != nil {
		u.fail(now, clusters.OTAReasonFailure, err)
	}
}

// poll runs the next step when due, and the timeouts.
func (u *updater) poll(now time.Time) time.Time {
	if !u.periodic.IsZero() && !now.Before(u.periodic) {
		u.periodic = now.Add(otaPeriodicQuery)
		if u.step == nil && u.c.State() == clusters.OTAStateIdle {
			u.queryDefault(now)
		}
	}
	if !u.started.IsZero() && now.Sub(u.started) > otaWatchdog {
		u.abortTransfer(now)
		u.fail(now, clusters.OTAReasonTimeOut, errors.New("update took too long"))
	}
	if u.dl != nil && now.Sub(u.last) > otaStall {
		u.abortTransfer(now)
		u.fail(now, clusters.OTAReasonTimeOut, errors.New("download stalled"))
	}
	if u.inv != nil {
		u.inv.Poll(now)
	}
	if u.step != nil && !u.at.IsZero() && !now.Before(u.at) {
		f := u.step
		u.step, u.at = nil, time.Time{}
		f(now)
	}
	next := u.periodic
	earlier := func(t time.Time) {
		if !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	earlier(u.at)
	if u.inv != nil {
		earlier(u.inv.Poll(now))
	}
	if u.dl != nil {
		earlier(u.last.Add(otaStall + time.Millisecond))
	}
	return next
}

func (u *updater) abortTransfer(now time.Time) {
	if dl := u.dl; dl != nil {
		u.dl = nil
		dl.Done = nil
		dl.Abort(now, bdx.StatusTransferFailedUnknownError)
	}
}

// removeFabric drops a removed fabric's provider, ending an update from it.
func (u *updater) removeFabric(now time.Time, index uint8) {
	u.c.RemoveFabric(u.d.Node, index)
	if u.step != nil && u.provider.FabricIndex == index {
		u.abortTransfer(now)
		u.fail(now, clusters.OTAReasonFailure, errors.New("provider fabric removed"))
	}
}

// ---- Persistence ----

// encode writes the requestor's state under tag:
//
//	{ 1: default providers, 2: { 1: fabric, 2: node, 3: endpoint,
//	  4: token, 5: target version, 6: provider address } }
func (u *updater) encode(w *tlv.Writer, tag tlv.Tag, keep func(uint8) bool) {
	if len(u.c.Providers) == 0 && u.pending == nil {
		return
	}
	w.StartStruct(tag)
	u.c.EncodeProviders(w, tlv.ContextTag(1), keep)
	if p := u.pending; p != nil {
		w.StartStruct(tlv.ContextTag(2))
		w.PutUint(tlv.ContextTag(1), uint64(p.provider.FabricIndex))
		w.PutUint(tlv.ContextTag(2), p.provider.NodeID)
		w.PutUint(tlv.ContextTag(3), uint64(p.provider.Endpoint))
		w.PutBytes(tlv.ContextTag(4), p.token)
		w.PutUint(tlv.ContextTag(5), uint64(p.target))
		if p.addr.IsValid() {
			w.PutString(tlv.ContextTag(6), p.addr.String())
		}
		w.EndContainer()
	}
	w.EndContainer()
}

func (u *updater) decode(r *tlv.Reader) error {
	return im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		switch tag {
		case 1:
			return u.c.DecodeProviders(r)
		case 2:
			p := &otaPending{}
			err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
				switch tag {
				case 1:
					p.provider.FabricIndex, err = r.Uint8()
				case 2:
					p.provider.NodeID, err = r.Uint()
				case 3:
					p.provider.Endpoint, err = r.Uint16()
				case 4:
					var b []byte
					b, err = r.Bytes()
					p.token = append([]byte(nil), b...)
				case 5:
					p.target, err = r.Uint32()
				case 6:
					var s string
					if s, err = r.String(); err == nil {
						p.addr, _ = netip.ParseAddrPort(s)
					}
				}
				return err
			})
			if err != nil {
				return err
			}
			if len(p.token) == 0 || p.target == 0 {
				return errState
			}
			u.pending = p
			u.c.InitState(clusters.OTAStateApplying)
		}
		return nil
	})
}
