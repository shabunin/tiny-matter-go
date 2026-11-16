package clusters

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// OTA Software Update Provider status (StatusEnum), apply actions
// (ApplyUpdateActionEnum) and download protocols (DownloadProtocolEnum).
const (
	OTAUpdateAvailable              = 0
	OTABusy                         = 1
	OTANotAvailable                 = 2
	OTADownloadProtocolNotSupported = 3

	OTAApplyProceed         = 0
	OTAApplyAwaitNextAction = 1
	OTAApplyDiscontinue     = 2

	OTAProtocolBDXSynchronous = 0
)

// OTA Software Update Requestor update states (UpdateStateEnum), state
// change reasons (ChangeReasonEnum) and announcement reasons
// (AnnouncementReasonEnum).
const (
	OTAStateUnknown              = 0
	OTAStateIdle                 = 1
	OTAStateQuerying             = 2
	OTAStateDelayedOnQuery       = 3
	OTAStateDownloading          = 4
	OTAStateApplying             = 5
	OTAStateDelayedOnApply       = 6
	OTAStateRollingBack          = 7
	OTAStateDelayedOnUserConsent = 8

	OTAReasonUnknown         = 0
	OTAReasonSuccess         = 1
	OTAReasonFailure         = 2
	OTAReasonTimeOut         = 3
	OTAReasonDelayByProvider = 4

	OTAAnnounceSimple          = 0
	OTAAnnounceUpdateAvailable = 1
	OTAAnnounceUrgent          = 2
)

// OTA requestor events.
const (
	EventStateTransition = 0x00
	EventVersionApplied  = 0x01
	EventDownloadError   = 0x02
)

// Field limits.
const (
	maxOTAMetadata   = 512
	maxImageURI      = 256
	minUpdateToken   = 8
	maxUpdateToken   = 32
	maxVersionString = 64
)

const (
	otaQueryImage          = 0x00
	otaQueryImageResponse  = 0x01
	otaApplyUpdateRequest  = 0x02
	otaApplyUpdateResponse = 0x03
	otaNotifyUpdateApplied = 0x04
	otaAnnounceProvider    = 0x00
	otaDefaultProviders    = 0
	otaUpdatePossible      = 1
	otaUpdateState         = 2
	otaUpdateStateProgress = 3
	otaFieldFabricIndex    = 0xFE
)

// Command IDs of the provider cluster, for clients.
const (
	CmdQueryImage          = otaQueryImage
	CmdApplyUpdateRequest  = otaApplyUpdateRequest
	CmdNotifyUpdateApplied = otaNotifyUpdateApplied
	CmdAnnounceOTAProvider = otaAnnounceProvider
)

var errOTAFields = errors.New("ota: bad command fields")

// ---- Commands ----

// QueryImage is the QueryImage command a requestor sends to a provider.
type QueryImage struct {
	VendorID           uint16
	ProductID          uint16
	SoftwareVersion    uint32
	Protocols          []uint8
	HardwareVersion    uint16
	HasHardwareVersion bool
	Location           string // ISO 3166-1 alpha-2, or empty
	CanConsent         bool
	Metadata           []byte
}

// Encode writes the command's fields.
func (q *QueryImage) Encode(w *tlv.Writer) {
	w.PutUint(tlv.ContextTag(0), uint64(q.VendorID))
	w.PutUint(tlv.ContextTag(1), uint64(q.ProductID))
	w.PutUint(tlv.ContextTag(2), uint64(q.SoftwareVersion))
	w.StartArray(tlv.ContextTag(3))
	for _, p := range q.Protocols {
		w.PutUint(tlv.Anonymous, uint64(p))
	}
	w.EndContainer()
	if q.HasHardwareVersion {
		w.PutUint(tlv.ContextTag(4), uint64(q.HardwareVersion))
	}
	if q.Location != "" {
		w.PutString(tlv.ContextTag(5), q.Location)
	}
	w.PutBool(tlv.ContextTag(6), q.CanConsent)
	if q.Metadata != nil {
		w.PutBytes(tlv.ContextTag(7), q.Metadata)
	}
}

// DecodeQueryImage decodes the fields structure r is positioned on,
// checking them as the SDK's provider does.
func DecodeQueryImage(r *tlv.Reader) (q QueryImage, err error) {
	var have uint8
	err = im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			q.VendorID, err = r.Uint16()
			have |= 1
		case 1:
			q.ProductID, err = r.Uint16()
			have |= 2
		case 2:
			q.SoftwareVersion, err = r.Uint32()
			have |= 4
		case 3:
			have |= 8
			return eachItem(r, func() error {
				p, err := r.Uint8()
				q.Protocols = append(q.Protocols, p)
				return err
			})
		case 4:
			q.HardwareVersion, err = r.Uint16()
			q.HasHardwareVersion = true
		case 5:
			q.Location, err = r.String()
			if err == nil && len(q.Location) != 2 {
				err = errOTAFields
			}
		case 6:
			q.CanConsent, err = r.Bool()
		case 7:
			var b []byte
			b, err = r.Bytes()
			q.Metadata = append([]byte(nil), b...)
			if len(b) > maxOTAMetadata {
				err = errOTAFields
			}
		}
		return err
	})
	if err == nil && have != 15 {
		err = errOTAFields
	}
	return q, err
}

// QueryImageResponse is a provider's answer to QueryImage.
type QueryImageResponse struct {
	Status                uint8
	DelayedActionTime     uint32 // seconds
	ImageURI              string
	SoftwareVersion       uint32
	SoftwareVersionString string
	UpdateToken           []byte
	UserConsentNeeded     bool
}

// Encode writes the response's fields; the image fields only with
// OTAUpdateAvailable.
func (q *QueryImageResponse) Encode(w *tlv.Writer) {
	w.PutUint(tlv.ContextTag(0), uint64(q.Status))
	if q.Status == OTAUpdateAvailable || q.Status == OTABusy {
		w.PutUint(tlv.ContextTag(1), uint64(q.DelayedActionTime))
	}
	if q.Status != OTAUpdateAvailable {
		return
	}
	w.PutString(tlv.ContextTag(2), q.ImageURI)
	w.PutUint(tlv.ContextTag(3), uint64(q.SoftwareVersion))
	w.PutString(tlv.ContextTag(4), q.SoftwareVersionString)
	w.PutBytes(tlv.ContextTag(5), q.UpdateToken)
	w.PutBool(tlv.ContextTag(6), q.UserConsentNeeded)
}

// DecodeQueryImageResponse decodes a QueryImageResponse's fields (raw
// structure, as im.InvokeResult.Fields), requiring what an available
// update needs.
func DecodeQueryImageResponse(b []byte) (q QueryImageResponse, err error) {
	var have uint8
	err = im.ForEachField(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		if tag <= 7 {
			have |= 1 << tag
		}
		switch tag {
		case 0:
			q.Status, err = r.Uint8()
		case 1:
			q.DelayedActionTime, err = r.Uint32()
		case 2:
			q.ImageURI, err = r.String()
		case 3:
			q.SoftwareVersion, err = r.Uint32()
		case 4:
			q.SoftwareVersionString, err = r.String()
		case 5:
			var t []byte
			t, err = r.Bytes()
			q.UpdateToken = append([]byte(nil), t...)
		case 6:
			q.UserConsentNeeded, err = r.Bool()
		}
		return err
	})
	switch {
	case err != nil:
	case have&1 == 0:
		err = errOTAFields
	case q.Status == OTAUpdateAvailable && have&0x2C != 0x2C: // URI, version, token
		err = errOTAFields
	case q.Status == OTAUpdateAvailable && (len(q.UpdateToken) < minUpdateToken || len(q.UpdateToken) > maxUpdateToken ||
		len(q.ImageURI) > maxImageURI || len(q.SoftwareVersionString) > maxVersionString):
		err = errOTAFields
	}
	return q, err
}

// EncodeTokenVersion writes the fields of ApplyUpdateRequest and
// NotifyUpdateApplied: the update token and a software version.
func EncodeTokenVersion(token []byte, version uint32) func(w *tlv.Writer) {
	return func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), token)
		w.PutUint(tlv.ContextTag(1), uint64(version))
	}
}

func decodeTokenVersion(r *tlv.Reader) (token []byte, version uint32, err error) {
	var have uint8
	err = im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			token, err = r.Bytes()
			have |= 1
		case 1:
			version, err = r.Uint32()
			have |= 2
		}
		return err
	})
	if err == nil && (have != 3 || len(token) < minUpdateToken || len(token) > maxUpdateToken) {
		err = errOTAFields
	}
	return token, version, err
}

// DecodeApplyUpdateResponse decodes an ApplyUpdateResponse's fields.
func DecodeApplyUpdateResponse(b []byte) (action uint8, delay uint32, err error) {
	var have uint8
	err = im.ForEachField(tlv.NewReader(b), func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			action, err = r.Uint8()
			have |= 1
		case 1:
			delay, err = r.Uint32()
			have |= 2
		}
		return err
	})
	if err == nil && have != 3 {
		err = errOTAFields
	}
	return action, delay, err
}

// BDXURI returns the image URI of a file served over BDX by node.
func BDXURI(node uint64, designator string) string {
	s := strings.ToUpper(strconv.FormatUint(node, 16))
	return "bdx://" + strings.Repeat("0", 16-len(s)) + s + "/" + designator
}

// ParseBDXURI splits a bdx://<node ID, 16 hex digits>/<file designator>
// image URI.
func ParseBDXURI(uri string) (node uint64, designator string, err error) {
	rest, ok := strings.CutPrefix(uri, "bdx://")
	if !ok || len(rest) < 18 || rest[16] != '/' {
		return 0, "", errors.New("ota: not a BDX URI")
	}
	node, err = strconv.ParseUint(rest[:16], 16, 64)
	if err != nil || len(rest) == 17 {
		return 0, "", errors.New("ota: bad BDX URI")
	}
	return node, rest[17:], nil
}

// ---- Provider ----

// OTAProvider is the OTA Software Update Provider cluster (spec 11.20.6),
// which serves images to requestors. The callbacks implement it; unset
// ones fail their command.
type OTAProvider struct {
	im.ClusterBase
	QueryImage          func(ctx *im.Context, q *QueryImage) QueryImageResponse
	ApplyUpdate         func(ctx *im.Context, token []byte, version uint32) (action uint8, delay uint32)
	NotifyUpdateApplied func(ctx *im.Context, token []byte, version uint32)
}

var (
	otaProviderAccepted  = []uint32{otaQueryImage, otaApplyUpdateRequest, otaNotifyUpdateApplied}
	otaProviderGenerated = []uint32{otaQueryImageResponse, otaApplyUpdateResponse}
)

func (*OTAProvider) ID() uint32                  { return IDOTAProvider }
func (*OTAProvider) Revision() uint16            { return 1 }
func (*OTAProvider) Attributes() []uint32        { return nil }
func (*OTAProvider) AcceptedCommands() []uint32  { return otaProviderAccepted }
func (*OTAProvider) GeneratedCommands() []uint32 { return otaProviderGenerated }

func (*OTAProvider) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*OTAProvider) WritePrivilege(uint32) im.Privilege  { return im.Operate }
func (*OTAProvider) InvokePrivilege(uint32) im.Privilege { return im.Operate }

func (*OTAProvider) ReadAttribute(*im.Context, uint32, *tlv.Writer, tlv.Tag) im.Status {
	return im.UnsupportedAttribute
}

func (p *OTAProvider) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	switch cmd {
	case otaQueryImage:
		q, err := DecodeQueryImage(r)
		if err != nil {
			return im.InvalidCommand
		}
		if p.QueryImage == nil {
			return im.Failure
		}
		res := p.QueryImage(ctx, &q)
		res.Encode(resp.Fields(otaQueryImageResponse))
		return im.Success
	case otaApplyUpdateRequest, otaNotifyUpdateApplied:
		token, version, err := decodeTokenVersion(r)
		if err != nil {
			return im.InvalidCommand
		}
		if cmd == otaNotifyUpdateApplied {
			if p.NotifyUpdateApplied != nil {
				p.NotifyUpdateApplied(ctx, token, version)
			}
			return im.Success
		}
		if p.ApplyUpdate == nil {
			return im.Failure
		}
		action, delay := p.ApplyUpdate(ctx, token, version)
		w := resp.Fields(otaApplyUpdateResponse)
		w.PutUint(tlv.ContextTag(0), uint64(action))
		w.PutUint(tlv.ContextTag(1), uint64(delay))
		return im.Success
	}
	return im.UnsupportedCommand
}

// ---- Requestor ----

// ProviderLocation is a provider a requestor may query
// (ProviderLocationStruct).
type ProviderLocation struct {
	FabricIndex uint8
	NodeID      uint64
	Endpoint    uint16
}

// Announcement is an AnnounceOTAProvider command.
type Announcement struct {
	Provider ProviderLocation
	VendorID uint16
	Reason   uint8
	Metadata []byte
}

// OTARequestor is the OTA Software Update Requestor cluster (spec
// 11.20.7) on the root endpoint. It holds the attributes and records the
// events; the update itself is driven elsewhere (device.Updater).
type OTARequestor struct {
	im.ClusterBase
	// Providers is DefaultOTAProviders: at most one per fabric.
	Providers []ProviderLocation
	// Announce, if set, takes AnnounceOTAProvider commands.
	Announce func(ctx *im.Context, a *Announcement)
	// OnChange, if set, is called after Providers changes, so it can be
	// saved.
	OnChange func()

	state       uint8
	progress    uint8
	hasProgress bool
}

// NewOTARequestor returns the cluster in the Idle state.
func NewOTARequestor() *OTARequestor { return &OTARequestor{state: OTAStateIdle} }

var (
	otaRequestorAttrs    = []uint32{otaDefaultProviders, otaUpdatePossible, otaUpdateState, otaUpdateStateProgress}
	otaRequestorAccepted = []uint32{otaAnnounceProvider}
	otaRequestorEvents   = []uint32{EventStateTransition, EventVersionApplied, EventDownloadError}
)

func (*OTARequestor) ID() uint32                 { return IDOTARequestor }
func (*OTARequestor) Revision() uint16           { return 1 }
func (*OTARequestor) Attributes() []uint32       { return otaRequestorAttrs }
func (*OTARequestor) AcceptedCommands() []uint32 { return otaRequestorAccepted }
func (*OTARequestor) Events() []uint32           { return otaRequestorEvents }

func (*OTARequestor) ReadPrivilege(uint32) im.Privilege   { return im.View }
func (*OTARequestor) WritePrivilege(uint32) im.Privilege  { return im.Administer }
func (*OTARequestor) InvokePrivilege(uint32) im.Privilege { return im.Administer }

// State returns UpdateState.
func (o *OTARequestor) State() uint8 { return o.state }

// InitState sets UpdateState without an event, as restored at start.
func (o *OTARequestor) InitState(state uint8) { o.state = state }

func (o *OTARequestor) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case otaDefaultProviders:
		w.StartArray(tag)
		for _, p := range o.Providers {
			if ctx.FabricFiltered && p.FabricIndex != accessingFabric(ctx) {
				continue
			}
			encodeProviderLocation(w, tlv.Anonymous, &p)
		}
		w.EndContainer()
	case otaUpdatePossible:
		w.PutBool(tag, true)
	case otaUpdateState:
		w.PutUint(tag, uint64(o.state))
	case otaUpdateStateProgress:
		if o.hasProgress {
			w.PutUint(tag, uint64(o.progress))
		} else {
			w.PutNull(tag)
		}
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func encodeProviderLocation(w *tlv.Writer, tag tlv.Tag, p *ProviderLocation) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(1), p.NodeID)
	w.PutUint(tlv.ContextTag(2), uint64(p.Endpoint))
	w.PutUint(tlv.ContextTag(otaFieldFabricIndex), uint64(p.FabricIndex))
	w.EndContainer()
}

func decodeProviderLocation(r *tlv.Reader) (p ProviderLocation, err error) {
	var have uint8
	err = im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			p.NodeID, err = r.Uint()
			have |= 1
		case 2:
			p.Endpoint, err = r.Uint16()
			have |= 2
		case otaFieldFabricIndex:
			p.FabricIndex, err = r.Uint8()
		}
		return err
	})
	if err == nil && have != 3 {
		err = errOTAFields
	}
	return p, err
}

// Provider returns the default provider of a fabric.
func (o *OTARequestor) Provider(fabricIndex uint8) (ProviderLocation, bool) {
	for _, p := range o.Providers {
		if p.FabricIndex == fabricIndex {
			return p, true
		}
	}
	return ProviderLocation{}, false
}

func (o *OTARequestor) changed(n *im.Node) {
	n.Changed(0, IDOTARequestor, otaDefaultProviders)
	if o.OnChange != nil {
		o.OnChange()
	}
}

// WriteAttribute sets the accessing fabric's default provider: a list
// holds at most one entry per fabric.
func (o *OTARequestor) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != otaDefaultProviders {
		return im.UnsupportedWrite
	}
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return im.UnsupportedAccess
	}
	others := func() []ProviderLocation {
		return filter(o.Providers, func(p *ProviderLocation) bool { return p.FabricIndex != fabric })
	}
	if appendItem {
		p, err := decodeProviderLocation(r)
		if err != nil {
			return im.InvalidDataType
		}
		if _, ok := o.Provider(fabric); ok {
			return im.ConstraintError
		}
		p.FabricIndex = fabric
		o.Providers = append(o.Providers, p)
		o.changed(ctx.Node)
		return im.Success
	}
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return im.InvalidDataType
	}
	var fresh []ProviderLocation
	for r.Next() == nil {
		p, err := decodeProviderLocation(r)
		if err != nil {
			return im.InvalidDataType
		}
		p.FabricIndex = fabric
		fresh = append(fresh, p)
	}
	if r.ExitContainer() != nil {
		return im.InvalidDataType
	}
	if len(fresh) > 1 {
		return im.ConstraintError
	}
	o.Providers = append(others(), fresh...)
	o.changed(ctx.Node)
	return im.Success
}

// RemoveFabric drops a removed fabric's default provider.
func (o *OTARequestor) RemoveFabric(n *im.Node, index uint8) {
	before := len(o.Providers)
	o.Providers = filter(o.Providers, func(p *ProviderLocation) bool { return p.FabricIndex != index })
	if len(o.Providers) != before {
		o.changed(n)
	}
}

func (o *OTARequestor) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	if cmd != otaAnnounceProvider {
		return im.UnsupportedCommand
	}
	fabric := accessingFabric(ctx)
	if fabric == 0 {
		return im.UnsupportedAccess
	}
	a := Announcement{Provider: ProviderLocation{FabricIndex: fabric}}
	var have uint8
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 0:
			a.Provider.NodeID, err = r.Uint()
			have |= 1
		case 1:
			a.VendorID, err = r.Uint16()
			have |= 2
		case 2:
			a.Reason, err = r.Uint8()
			have |= 4
		case 3:
			var b []byte
			b, err = r.Bytes()
			a.Metadata = append([]byte(nil), b...)
		case 4:
			a.Provider.Endpoint, err = r.Uint16()
			have |= 8
		}
		return err
	})
	if err != nil || have != 15 {
		return im.InvalidCommand
	}
	if a.Reason > OTAAnnounceUrgent || len(a.Metadata) > maxOTAMetadata {
		return im.ConstraintError
	}
	if o.Announce != nil {
		o.Announce(ctx, &a)
	}
	return im.Success
}

// SetState changes UpdateState, recording a StateTransition event.
// target is the version being downloaded or applied, reported for those
// states. Leaving Downloading clears UpdateStateProgress.
func (o *OTARequestor) SetState(n *im.Node, now time.Time, state, reason uint8, target uint32) {
	if state == o.state {
		return
	}
	prev := o.state
	o.state = state
	n.Changed(0, IDOTARequestor, otaUpdateState)
	if prev == OTAStateDownloading || state == OTAStateDownloading {
		o.SetProgress(n, 0, false)
	}
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: 0, Cluster: IDOTARequestor, Event: EventStateTransition},
		Priority: im.PriorityInfo,
		Fields: func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), uint64(prev))
			w.PutUint(tlv.ContextTag(1), uint64(state))
			w.PutUint(tlv.ContextTag(2), uint64(reason))
			switch state {
			case OTAStateDownloading, OTAStateApplying, OTAStateRollingBack:
				w.PutUint(tlv.ContextTag(3), uint64(target))
			default:
				w.PutNull(tlv.ContextTag(3))
			}
		},
	})
}

// SetProgress sets UpdateStateProgress (percent), or makes it null.
func (o *OTARequestor) SetProgress(n *im.Node, percent uint8, valid bool) {
	if !valid {
		percent = 0
	}
	if percent == o.progress && valid == o.hasProgress {
		return
	}
	o.progress, o.hasProgress = percent, valid
	n.Changed(0, IDOTARequestor, otaUpdateStateProgress)
}

// VersionApplied records the VersionApplied event after a node started
// the version an update installed.
func (o *OTARequestor) VersionApplied(n *im.Node, now time.Time, version uint32, productID uint16) {
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: 0, Cluster: IDOTARequestor, Event: EventVersionApplied},
		Priority: im.PriorityCritical,
		Fields: func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), uint64(version))
			w.PutUint(tlv.ContextTag(1), uint64(productID))
		},
	})
}

// DownloadError records the DownloadError event. progress is a percentage,
// or negative if unknown.
func (o *OTARequestor) DownloadError(n *im.Node, now time.Time, version uint32, bytes uint64, progress int) {
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: 0, Cluster: IDOTARequestor, Event: EventDownloadError},
		Priority: im.PriorityInfo,
		Fields: func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), uint64(version))
			w.PutUint(tlv.ContextTag(1), bytes)
			if progress >= 0 {
				w.PutUint(tlv.ContextTag(2), uint64(progress))
			} else {
				w.PutNull(tlv.ContextTag(2))
			}
			w.PutNull(tlv.ContextTag(3))
		},
	})
}

// EncodeProviders writes Providers under tag for persistent storage, for
// the fabrics keep accepts.
func (o *OTARequestor) EncodeProviders(w *tlv.Writer, tag tlv.Tag, keep func(fabric uint8) bool) {
	w.StartArray(tag)
	for _, p := range o.Providers {
		if keep(p.FabricIndex) {
			encodeProviderLocation(w, tlv.Anonymous, &p)
		}
	}
	w.EndContainer()
}

// DecodeProviders restores what EncodeProviders wrote; r is positioned on
// the array.
func (o *OTARequestor) DecodeProviders(r *tlv.Reader) error {
	var ps []ProviderLocation
	err := eachItem(r, func() error {
		p, err := decodeProviderLocation(r)
		ps = append(ps, p)
		return err
	})
	if err != nil {
		return err
	}
	o.Providers = ps
	return nil
}
