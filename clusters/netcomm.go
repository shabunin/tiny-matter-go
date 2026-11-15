package clusters

import (
	"bytes"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/thread"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// NetworkingStatus is the Network Commissioning status code.
type NetworkingStatus uint8

const (
	NetworkOK                     NetworkingStatus = 0
	NetworkOutOfRange             NetworkingStatus = 1
	NetworkBoundsExceeded         NetworkingStatus = 2
	NetworkIDNotFound             NetworkingStatus = 3
	NetworkDuplicateID            NetworkingStatus = 4
	NetworkNotFound               NetworkingStatus = 5
	NetworkRegulatoryError        NetworkingStatus = 6
	NetworkAuthFailure            NetworkingStatus = 7
	NetworkUnsupportedSecurity    NetworkingStatus = 8
	NetworkOtherConnectionFailure NetworkingStatus = 9
	NetworkIPv6Failed             NetworkingStatus = 10
	NetworkIPBindFailed           NetworkingStatus = 11
	NetworkUnknownError           NetworkingStatus = 12
)

// Wi-Fi security types (WiFiSecurityBitmap).
const (
	WiFiUnencrypted = 0x01
	WiFiWEP         = 0x02
	WiFiWPAPersonal = 0x04
	WiFiWPA2        = 0x08
	WiFiWPA3        = 0x10
)

// Wi-Fi bands (WiFiBandEnum).
const (
	WiFiBand2G4 = 0
	WiFiBand5G  = 2
)

// WiFiNetwork is a configured network. For Wi-Fi, its network ID is the
// SSID and Credentials the passphrase or PSK. For Thread, SSID holds the
// network ID, the extended PAN ID, and Credentials the operational dataset.
type WiFiNetwork struct {
	SSID        []byte
	Credentials []byte
}

// WiFiScanResult is one network found by a scan.
type WiFiScanResult struct {
	Security uint8
	SSID     []byte
	BSSID    [6]byte
	Channel  uint16
	Band     uint8
	RSSI     int8
}

// ThreadScanResult is one Thread network found by a scan.
type ThreadScanResult struct {
	PANID           uint16
	ExtendedPANID   uint64
	NetworkName     string
	Channel         uint16
	Version         uint8
	ExtendedAddress [8]byte
	RSSI            int8
	LQI             uint8
}

// Thread feature bits (SupportedThreadFeatures).
const (
	ThreadBorderRouter = 1 << 0
	ThreadRouter       = 1 << 1
	ThreadSleepy       = 1 << 2
	ThreadFTD          = 1 << 3
	ThreadSynchronized = 1 << 4
)

// NetworkCommissioning is the Network Commissioning cluster with the Wi-Fi
// or, with Thread set, the Thread feature (spec 11.9). Changes made under
// the fail-safe are kept apart from the committed networks until Commit,
// and Rollback discards them.
//
// Only non-concurrent operation is supported: ConnectNetwork answers at
// once, and the application joins the network afterwards (dropping the BLE
// commissioning link). General Commissioning's SupportsConcurrentConnection
// must then be false.
type NetworkCommissioning struct {
	im.ClusterBase
	FailSafe *FailSafe

	MaxNetworks      uint8 // default 1
	ScanMaxTime      uint8 // seconds
	ConnectMaxTime   uint8 // seconds
	InterfaceEnabled bool
	Bands            []uint8 // default 2.4 GHz only

	// Thread makes it a Thread interface (feature TH) rather than Wi-Fi:
	// networks are added with operational datasets and named by their
	// extended PAN IDs. Set it before the cluster is added to a node.
	Thread bool
	// ThreadFeatures (SupportedThreadFeatures) and ThreadVersion (4 for
	// Thread 1.3) describe a Thread interface.
	ThreadFeatures uint16
	ThreadVersion  uint16

	// Networks is the current list, including uncommitted changes.
	Networks []WiFiNetwork
	// Connected is the SSID of the network the interface is connected to.
	Connected []byte

	// Last connection attempt; LastStatus < 0 is null.
	LastStatus       int16
	LastNetworkID    []byte // nil is null
	LastConnectError int32
	HasConnectError  bool

	// FabricIndex returns the accessing fabric of a request, to check it
	// is the one that armed the fail-safe.
	FabricIndex func(ctx *im.Context) uint8
	// Scan scans for networks (ssid nil: all). Nil reports no results.
	Scan func(ctx *im.Context, ssid []byte) ([]WiFiScanResult, NetworkingStatus)
	// ScanThread scans for Thread networks. Nil reports no results.
	ScanThread func(ctx *im.Context) ([]ThreadScanResult, NetworkingStatus)
	// Connect is called while ConnectNetwork is being answered; it must
	// join the network only after the response has gone out.
	Connect func(now time.Time, n WiFiNetwork)

	committed []WiFiNetwork
	staged    bool // Networks differs from committed under the fail-safe
}

// NewNetworkCommissioning returns the cluster with the committed networks.
func NewNetworkCommissioning(fs *FailSafe, networks []WiFiNetwork) *NetworkCommissioning {
	n := &NetworkCommissioning{
		FailSafe: fs, MaxNetworks: 1, ScanMaxTime: 10, ConnectMaxTime: 20,
		InterfaceEnabled: true, Bands: []uint8{WiFiBand2G4}, LastStatus: -1,
	}
	n.Restore(networks)
	return n
}

// Restore replaces both the current and the committed networks, as when
// loading them from storage. The networks are copied.
func (n *NetworkCommissioning) Restore(networks []WiFiNetwork) {
	n.committed = cloneNetworks(networks)
	n.Networks = cloneNetworks(networks)
	n.staged = false
}

func cloneNetworks(ns []WiFiNetwork) []WiFiNetwork {
	out := make([]WiFiNetwork, len(ns))
	for i, n := range ns {
		out[i] = WiFiNetwork{SSID: bytes.Clone(n.SSID), Credentials: bytes.Clone(n.Credentials)}
	}
	return out
}

// Committed returns the committed networks (those to persist).
func (n *NetworkCommissioning) Committed() []WiFiNetwork { return n.committed }

// Commit makes the current networks permanent (on CommissioningComplete).
// It reports whether the committed list changed.
func (n *NetworkCommissioning) Commit() bool {
	if !n.staged {
		return false
	}
	n.staged = false
	n.committed = cloneNetworks(n.Networks)
	return true
}

// Rollback discards uncommitted changes (on fail-safe expiry), reporting
// whether there were any.
func (n *NetworkCommissioning) Rollback(node *im.Node) bool {
	if !n.staged {
		return false
	}
	n.staged = false
	n.Networks = cloneNetworks(n.committed)
	if node != nil {
		node.Changed(0, IDNetworkCommissioning, ncNetworks)
	}
	return true
}

// SetConnected records the connected network (nil when disconnected).
func (n *NetworkCommissioning) SetConnected(node *im.Node, ssid []byte) {
	if bytes.Equal(ssid, n.Connected) && (ssid == nil) == (n.Connected == nil) {
		return
	}
	n.Connected = bytes.Clone(ssid)
	if node != nil {
		node.Changed(0, IDNetworkCommissioning, ncNetworks)
	}
}

// SetLastConnect records the outcome of a connection attempt.
func (n *NetworkCommissioning) SetLastConnect(node *im.Node, ssid []byte, st NetworkingStatus, errValue int32, hasErr bool) {
	n.LastStatus, n.LastNetworkID = int16(st), bytes.Clone(ssid)
	n.LastConnectError, n.HasConnectError = errValue, hasErr
	if node != nil {
		for _, a := range []uint32{ncLastNetworkingStatus, ncLastNetworkID, ncLastConnectErrorValue} {
			node.Changed(0, IDNetworkCommissioning, a)
		}
	}
}

func (*NetworkCommissioning) ID() uint32       { return IDNetworkCommissioning }
func (*NetworkCommissioning) Revision() uint16 { return 2 }

func (n *NetworkCommissioning) FeatureMap() uint32 {
	if n.Thread {
		return 2 // TH
	}
	return 1 // WI
}

const (
	ncMaxNetworks           = 0
	ncNetworks              = 1
	ncScanMaxTimeSeconds    = 2
	ncConnectMaxTimeSeconds = 3
	ncInterfaceEnabled      = 4
	ncLastNetworkingStatus  = 5
	ncLastNetworkID         = 6
	ncLastConnectErrorValue = 7
	ncSupportedWiFiBands    = 8
	ncSupportedThreadFeats  = 9
	ncThreadVersion         = 10

	ncScanNetworks             = 0
	ncScanNetworksResponse     = 1
	ncAddOrUpdateWiFiNetwork   = 2
	ncAddOrUpdateThreadNetwork = 3
	ncRemoveNetwork            = 4
	ncNetworkConfigResponse    = 5
	ncConnectNetwork           = 6
	ncConnectNetworkResponse   = 7
	ncReorderNetwork           = 8

	maxSSID        = 32
	maxCredentials = 64
)

var (
	ncAttrs          = []uint32{0, 1, 2, 3, 4, 5, 6, 7, ncSupportedWiFiBands}
	ncThreadAttrs    = []uint32{0, 1, 2, 3, 4, 5, 6, 7, ncSupportedThreadFeats, ncThreadVersion}
	ncAccepted       = []uint32{ncScanNetworks, ncAddOrUpdateWiFiNetwork, ncRemoveNetwork, ncConnectNetwork, ncReorderNetwork}
	ncThreadAccepted = []uint32{ncScanNetworks, ncAddOrUpdateThreadNetwork, ncRemoveNetwork, ncConnectNetwork, ncReorderNetwork}
	ncGenerated      = []uint32{ncScanNetworksResponse, ncNetworkConfigResponse, ncConnectNetworkResponse}
)

func (n *NetworkCommissioning) Attributes() []uint32 {
	if n.Thread {
		return ncThreadAttrs
	}
	return ncAttrs
}

func (n *NetworkCommissioning) AcceptedCommands() []uint32 {
	if n.Thread {
		return ncThreadAccepted
	}
	return ncAccepted
}

func (*NetworkCommissioning) GeneratedCommands() []uint32 { return ncGenerated }

func (*NetworkCommissioning) ReadPrivilege(attr uint32) im.Privilege {
	switch attr {
	case ncMaxNetworks, ncNetworks, ncLastNetworkingStatus, ncLastNetworkID, ncLastConnectErrorValue:
		return im.Administer
	}
	return im.View
}
func (*NetworkCommissioning) WritePrivilege(uint32) im.Privilege  { return im.Administer }
func (*NetworkCommissioning) InvokePrivilege(uint32) im.Privilege { return im.Administer }

func (n *NetworkCommissioning) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case ncMaxNetworks:
		w.PutUint(tag, uint64(n.MaxNetworks))
	case ncNetworks:
		w.StartArray(tag)
		for _, nw := range n.Networks {
			w.StartStruct(tlv.Anonymous)
			w.PutBytes(tlv.ContextTag(0), nw.SSID)
			w.PutBool(tlv.ContextTag(1), n.Connected != nil && bytes.Equal(nw.SSID, n.Connected))
			w.EndContainer()
		}
		w.EndContainer()
	case ncScanMaxTimeSeconds:
		w.PutUint(tag, uint64(n.ScanMaxTime))
	case ncConnectMaxTimeSeconds:
		w.PutUint(tag, uint64(n.ConnectMaxTime))
	case ncInterfaceEnabled:
		w.PutBool(tag, n.InterfaceEnabled)
	case ncLastNetworkingStatus:
		if n.LastStatus < 0 {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(n.LastStatus))
		}
	case ncLastNetworkID:
		if n.LastNetworkID == nil {
			w.PutNull(tag)
		} else {
			w.PutBytes(tag, n.LastNetworkID)
		}
	case ncLastConnectErrorValue:
		if !n.HasConnectError {
			w.PutNull(tag)
		} else {
			w.PutInt(tag, int64(n.LastConnectError))
		}
	case ncSupportedWiFiBands:
		if n.Thread {
			return im.UnsupportedAttribute
		}
		w.StartArray(tag)
		for _, b := range n.Bands {
			w.PutUint(tlv.Anonymous, uint64(b))
		}
		w.EndContainer()
	case ncSupportedThreadFeats, ncThreadVersion:
		if !n.Thread {
			return im.UnsupportedAttribute
		}
		v := n.ThreadFeatures
		if attr == ncThreadVersion {
			v = n.ThreadVersion
		}
		w.PutUint(tag, uint64(v))
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (n *NetworkCommissioning) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr != ncInterfaceEnabled {
		return im.UnsupportedWrite
	}
	v, err := r.Bool()
	if err != nil || appendItem {
		return im.InvalidDataType
	}
	if v != n.InterfaceEnabled {
		n.InterfaceEnabled = v
		ctx.Node.Changed(ctx.Endpoint, IDNetworkCommissioning, ncInterfaceEnabled)
	}
	return im.Success
}

// armed reports whether the fail-safe is armed by the accessing fabric.
func (n *NetworkCommissioning) armed(ctx *im.Context) bool {
	if n.FailSafe == nil || !n.FailSafe.Armed(ctx.Now) {
		return false
	}
	var f uint8
	if n.FabricIndex != nil {
		f = n.FabricIndex(ctx)
	}
	return f == n.FailSafe.FabricIndex()
}

func (n *NetworkCommissioning) find(id []byte) int {
	for i, nw := range n.Networks {
		if bytes.Equal(nw.SSID, id) {
			return i
		}
	}
	return -1
}

// changed marks the list as modified under the fail-safe.
func (n *NetworkCommissioning) changed(ctx *im.Context) {
	n.staged = true
	ctx.Node.Changed(ctx.Endpoint, IDNetworkCommissioning, ncNetworks)
}

func configResponse(resp *im.Response, st NetworkingStatus, index int) im.Status {
	w := resp.Fields(ncNetworkConfigResponse)
	w.PutUint(tlv.ContextTag(0), uint64(st))
	if index >= 0 {
		w.PutUint(tlv.ContextTag(2), uint64(index))
	}
	return im.Success
}

// scanThread answers ScanNetworks on a Thread interface.
func (n *NetworkCommissioning) scanThread(ctx *im.Context, resp *im.Response, crumb func()) im.Status {
	var (
		results []ThreadScanResult
		st      NetworkingStatus
	)
	if n.ScanThread != nil {
		results, st = n.ScanThread(ctx)
	}
	n.LastStatus = int16(st)
	ctx.Node.Changed(ctx.Endpoint, IDNetworkCommissioning, ncLastNetworkingStatus)
	w := resp.Fields(ncScanNetworksResponse)
	w.PutUint(tlv.ContextTag(0), uint64(st))
	if st == NetworkOK {
		w.StartArray(tlv.ContextTag(3))
		for _, s := range results {
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(0), uint64(s.PANID))
			w.PutUint(tlv.ContextTag(1), s.ExtendedPANID)
			w.PutString(tlv.ContextTag(2), s.NetworkName)
			w.PutUint(tlv.ContextTag(3), uint64(s.Channel))
			w.PutUint(tlv.ContextTag(4), uint64(s.Version))
			w.PutBytes(tlv.ContextTag(5), s.ExtendedAddress[:])
			w.PutInt(tlv.ContextTag(6), int64(s.RSSI))
			w.PutUint(tlv.ContextTag(7), uint64(s.LQI))
			w.EndContainer()
		}
		w.EndContainer()
		crumb()
	}
	return im.Success
}

// validCredentials checks the credential lengths spec 11.9.7.3 allows:
// open, WEP-64, a WPA passphrase of 8 to 63 bytes, or a 64-digit hex PSK.
func validCredentials(c []byte) bool {
	switch {
	case len(c) == 0, len(c) == 5, len(c) >= 8 && len(c) <= 63:
		return true
	case len(c) == 64:
		for _, b := range c {
			if !('0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F') {
				return false
			}
		}
		return true
	}
	return false
}

func (n *NetworkCommissioning) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	var (
		id, creds  []byte
		breadcrumb uint64
		hasCrumb   bool
		index      uint64
		have       uint8
		pdc        bool
	)
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch {
		case tag == 0:
			if !(cmd == ncScanNetworks && r.IsNull()) { // null SSID: scan all
				var v []byte
				v, err = r.Bytes()
				id = bytes.Clone(v)
			}
			have |= 1
		case tag == 1 && cmd == ncAddOrUpdateWiFiNetwork:
			var v []byte
			v, err = r.Bytes()
			creds = bytes.Clone(v)
			have |= 2
		case tag == 1 && cmd == ncReorderNetwork:
			index, err = r.Uint()
			have |= 2
		case tag == 1 && (cmd == ncScanNetworks || cmd == ncRemoveNetwork || cmd == ncConnectNetwork ||
			cmd == ncAddOrUpdateThreadNetwork),
			tag == 2 && (cmd == ncAddOrUpdateWiFiNetwork || cmd == ncReorderNetwork):
			breadcrumb, err = r.Uint()
			hasCrumb = true
		case tag >= 3 && tag <= 5 && cmd == ncAddOrUpdateWiFiNetwork:
			pdc = true // per-device credentials: not supported
		}
		return err
	})
	if err != nil {
		return im.InvalidCommand
	}
	crumb := func() {
		if hasCrumb && ctx.Node != nil {
			if g, ok := ctx.Node.Endpoint(0).Cluster(IDGeneralCommissioning).(*GeneralCommissioning); ok {
				g.setBreadcrumb(ctx, breadcrumb, true)
			}
		}
	}

	if cmd == ncAddOrUpdateWiFiNetwork && n.Thread || cmd == ncAddOrUpdateThreadNetwork && !n.Thread {
		return im.UnsupportedCommand
	}
	switch cmd {
	case ncScanNetworks:
		if n.Thread {
			return n.scanThread(ctx, resp, crumb)
		}
		if len(id) > maxSSID {
			return im.ConstraintError
		}
		var (
			results []WiFiScanResult
			st      NetworkingStatus
		)
		if n.Scan != nil {
			results, st = n.Scan(ctx, id)
		}
		if st == NetworkOK && len(id) > 0 && len(results) == 0 {
			st = NetworkNotFound
		}
		n.LastStatus = int16(st)
		ctx.Node.Changed(ctx.Endpoint, IDNetworkCommissioning, ncLastNetworkingStatus)
		w := resp.Fields(ncScanNetworksResponse)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		if st == NetworkOK {
			w.StartArray(tlv.ContextTag(2))
			for _, s := range results {
				w.StartStruct(tlv.Anonymous)
				w.PutUint(tlv.ContextTag(0), uint64(s.Security))
				w.PutBytes(tlv.ContextTag(1), s.SSID)
				w.PutBytes(tlv.ContextTag(2), s.BSSID[:])
				w.PutUint(tlv.ContextTag(3), uint64(s.Channel))
				w.PutUint(tlv.ContextTag(4), uint64(s.Band))
				w.PutInt(tlv.ContextTag(5), int64(s.RSSI))
				w.EndContainer()
			}
			w.EndContainer()
			crumb()
		}
		return im.Success

	case ncAddOrUpdateWiFiNetwork:
		if have != 3 || pdc {
			return im.InvalidCommand
		}
		if !n.armed(ctx) {
			return im.FailsafeRequired
		}
		if len(id) == 0 || len(id) > maxSSID || !validCredentials(creds) {
			return im.ConstraintError
		}
		i := n.find(id)
		if i < 0 {
			if len(n.Networks) >= int(n.MaxNetworks) {
				return configResponse(resp, NetworkBoundsExceeded, -1)
			}
			n.Networks = append(n.Networks, WiFiNetwork{SSID: id, Credentials: creds})
			i = len(n.Networks) - 1
		} else {
			n.Networks[i].Credentials = creds
		}
		n.changed(ctx)
		crumb()
		return configResponse(resp, NetworkOK, i)

	case ncAddOrUpdateThreadNetwork:
		if have != 1 {
			return im.InvalidCommand
		}
		if !n.armed(ctx) {
			return im.FailsafeRequired
		}
		if len(id) > thread.MaxDatasetLen {
			return im.ConstraintError
		}
		ds, err := thread.ParseDataset(id)
		if err != nil {
			return configResponse(resp, NetworkOutOfRange, -1)
		}
		xpan := bytes.Clone(ds.ExtendedPANID[:])
		i := n.find(xpan)
		if i < 0 {
			if len(n.Networks) >= int(n.MaxNetworks) {
				return configResponse(resp, NetworkBoundsExceeded, -1)
			}
			n.Networks = append(n.Networks, WiFiNetwork{SSID: xpan, Credentials: id})
			i = len(n.Networks) - 1
		} else {
			n.Networks[i].Credentials = id
		}
		n.changed(ctx)
		crumb()
		return configResponse(resp, NetworkOK, i)

	case ncRemoveNetwork:
		if have != 1 {
			return im.InvalidCommand
		}
		if !n.armed(ctx) {
			return im.FailsafeRequired
		}
		i := n.find(id)
		if i < 0 {
			return configResponse(resp, NetworkIDNotFound, -1)
		}
		n.Networks = append(n.Networks[:i], n.Networks[i+1:]...)
		n.changed(ctx)
		crumb()
		if len(n.Networks) == 0 && (n.LastStatus >= 0 || n.LastNetworkID != nil || n.HasConnectError) {
			n.LastStatus, n.LastNetworkID, n.HasConnectError = -1, nil, false
			for _, a := range []uint32{ncLastNetworkingStatus, ncLastNetworkID, ncLastConnectErrorValue} {
				ctx.Node.Changed(ctx.Endpoint, IDNetworkCommissioning, a)
			}
		}
		return configResponse(resp, NetworkOK, i)

	case ncConnectNetwork:
		if have != 1 {
			return im.InvalidCommand
		}
		if len(id) > maxSSID {
			return im.ConstraintError
		}
		if !n.armed(ctx) {
			return im.FailsafeRequired
		}
		i := n.find(id)
		st := NetworkOK
		if i < 0 {
			st = NetworkIDNotFound
		}
		w := resp.Fields(ncConnectNetworkResponse)
		w.PutUint(tlv.ContextTag(0), uint64(st))
		w.PutNull(tlv.ContextTag(2)) // ErrorValue
		if st == NetworkOK {
			crumb()
			nw := n.Networks[i]
			nw = WiFiNetwork{SSID: bytes.Clone(nw.SSID), Credentials: bytes.Clone(nw.Credentials)}
			if n.Connect != nil {
				n.Connect(ctx.Now, nw)
			}
		}
		return im.Success

	case ncReorderNetwork:
		if have != 3 {
			return im.InvalidCommand
		}
		if !n.armed(ctx) {
			return im.FailsafeRequired
		}
		i := n.find(id)
		if i < 0 {
			return configResponse(resp, NetworkIDNotFound, -1)
		}
		if index >= uint64(len(n.Networks)) {
			return configResponse(resp, NetworkOutOfRange, -1)
		}
		if int(index) != i {
			nw := n.Networks[i]
			n.Networks = append(n.Networks[:i], n.Networks[i+1:]...)
			n.Networks = append(n.Networks[:index], append([]WiFiNetwork{nw}, n.Networks[index:]...)...)
			n.changed(ctx)
		}
		crumb()
		return configResponse(resp, NetworkOK, int(index))
	}
	return im.UnsupportedCommand
}
