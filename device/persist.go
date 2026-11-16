package device

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Persisted state layout (TLV, anonymous struct):
//
//	1: format version (1)
//	2: last fabric index
//	3: [ { 1: index, 2: vendor ID, 3: label, 4: RCAC, 5: ICAC (optional),
//	       6: NOC, 7: operational private key, 8: IPK epoch key } ]
//	4: ACL entries (AccessControlEntryStruct with fabric index)
//	5: networks [ { 1: network ID, 2: credentials } ] (committed): Wi-Fi
//	   SSIDs and passphrases, or Thread extended PAN IDs and datasets
//	6: first event number after a restart (reserved before it)
//	7: reboot count
//	8: groups: key sets, the group key map and the group table (see
//	   clusters.GroupData.Encode)
//	9: application cluster state [ { 1: endpoint, 2: cluster, 3: state } ]
//	   (see im.Persister)
//	10: OTA requestor: default providers and an update being applied
const stateVersion = 1

var errState = errors.New("device: malformed stored state")

// encodeState serializes committed fabrics and their ACL entries.
func (d *Device) encodeState() []byte {
	w := tlv.NewWriter(make([]byte, 0, 1024))
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(1), stateVersion)
	w.PutUint(tlv.ContextTag(2), uint64(d.Fabrics.LastIndex()))
	w.StartArray(tlv.ContextTag(3))
	for _, f := range d.Fabrics.Fabrics() {
		if f.Pending {
			continue
		}
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), uint64(f.Index))
		w.PutUint(tlv.ContextTag(2), uint64(f.VendorID))
		w.PutString(tlv.ContextTag(3), f.Label)
		w.PutBytes(tlv.ContextTag(4), f.RCAC)
		if f.ICAC != nil {
			w.PutBytes(tlv.ContextTag(5), f.ICAC)
		}
		w.PutBytes(tlv.ContextTag(6), f.NOC)
		w.PutBytes(tlv.ContextTag(7), f.Key.Bytes())
		w.PutBytes(tlv.ContextTag(8), f.IPK[:])
		w.EndContainer()
	}
	w.EndContainer()
	d.ACL.EncodeEntries(w, tlv.ContextTag(4), func(index uint8) bool {
		f := d.Fabrics.Get(index)
		return f != nil && !f.Pending
	})
	if d.Net != nil && len(d.Net.Committed()) > 0 {
		w.StartArray(tlv.ContextTag(5))
		for _, n := range d.Net.Committed() {
			w.StartStruct(tlv.Anonymous)
			w.PutBytes(tlv.ContextTag(1), n.SSID)
			w.PutBytes(tlv.ContextTag(2), n.Credentials)
			w.EndContainer()
		}
		w.EndContainer()
	}
	if d.eventLimit != 0 {
		w.PutUint(tlv.ContextTag(6), d.eventLimit)
	}
	if d.Diagnostics.RebootCount != 0 {
		w.PutUint(tlv.ContextTag(7), uint64(d.Diagnostics.RebootCount))
	}
	if len(d.Groups.KeySets) > 0 || len(d.Groups.KeyMap) > 0 || len(d.Groups.Groups) > 0 {
		d.Groups.Encode(w, tlv.ContextTag(8), func(index uint8) bool {
			f := d.Fabrics.Get(index)
			return f != nil && !f.Pending
		})
	}
	d.encodeAppState(w)
	if d.ota != nil {
		d.ota.encode(w, tlv.ContextTag(10), func(index uint8) bool {
			f := d.Fabrics.Get(index)
			return f != nil && !f.Pending
		})
	}
	w.EndContainer()
	return w.Bytes()
}

type appState struct {
	endpoint uint16
	cluster  uint32
	state    []byte // the raw element
}

// persister returns the cluster on an application endpoint whose state is
// saved, or nil.
func (d *Device) persister(endpoint uint16, cluster uint32) im.Persister {
	if endpoint == 0 {
		return nil
	}
	e := d.Node.Endpoint(endpoint)
	if e == nil {
		return nil
	}
	p, _ := e.Cluster(cluster).(im.Persister)
	return p
}

// encodeAppState writes the state of the application clusters, and the
// stored state of clusters not (yet) added, so that it is kept.
func (d *Device) encodeAppState(w *tlv.Writer) {
	started := false
	start := func() {
		if !started {
			started = true
			w.StartArray(tlv.ContextTag(9))
		}
	}
	for _, e := range d.Node.Endpoints() {
		if e.ID == 0 {
			continue
		}
		var ids [16]uint32
		for _, id := range e.ClusterIDs(ids[:0]) {
			if p, ok := e.Cluster(id).(im.Persister); ok {
				start()
				w.StartStruct(tlv.Anonymous)
				w.PutUint(tlv.ContextTag(1), uint64(e.ID))
				w.PutUint(tlv.ContextTag(2), uint64(id))
				p.EncodeState(w, tlv.ContextTag(3))
				w.EndContainer()
			}
		}
	}
	for _, a := range d.appState {
		start()
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), uint64(a.endpoint))
		w.PutUint(tlv.ContextTag(2), uint64(a.cluster))
		w.PutRaw(a.state) // tagged 3 as read
		w.EndContainer()
	}
	if started {
		w.EndContainer()
	}
}

func (d *Device) decodeAppState(r *tlv.Reader) error {
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return errState
	}
	for r.Next() == nil {
		var a appState
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
			switch tag {
			case 1:
				a.endpoint, err = r.Uint16()
			case 2:
				var v uint64
				v, err = r.Uint()
				a.cluster = uint32(v)
			case 3:
				a.state, err = r.RawElement()
				a.state = append([]byte(nil), a.state...)
			}
			return err
		})
		if err != nil || a.state == nil {
			return errState
		}
		d.appState = append(d.appState, a)
	}
	return r.ExitContainer()
}

// restoreCluster restores the stored state of a cluster as it is added.
func (d *Device) restoreCluster(endpoint uint16, c im.Cluster) {
	p, ok := c.(im.Persister)
	if !ok || endpoint == 0 {
		return
	}
	for i, a := range d.appState {
		if a.endpoint != endpoint || a.cluster != c.ID() {
			continue
		}
		d.appState = append(d.appState[:i], d.appState[i+1:]...)
		r := tlv.NewReader(a.state)
		if r.Next() != nil || p.DecodeState(r) != nil {
			d.log("stored cluster state ignored")
		}
		return
	}
}

// decodeState restores fabrics and ACL entries into an empty device.
func (d *Device) decodeState(b []byte) error {
	r := tlv.NewReader(b)
	var last uint8
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		switch tag {
		case 1:
			if v, err := r.Uint(); err != nil || v != stateVersion {
				return errors.New("device: unsupported stored state version")
			}
		case 2:
			v, err := r.Uint8()
			last = v
			return err
		case 3:
			if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
				return errState
			}
			for r.Next() == nil {
				if err := d.decodeFabric(r); err != nil {
					return err
				}
			}
			return r.ExitContainer()
		case 4:
			return d.ACL.DecodeEntries(r)
		case 5:
			return d.decodeNetworks(r)
		case 6:
			v, err := r.Uint()
			d.eventLimit = v
			return err
		case 7:
			v, err := r.Uint16()
			d.Diagnostics.RebootCount = v
			return err
		case 8:
			return d.Groups.Decode(r)
		case 9:
			return d.decodeAppState(r)
		case 10:
			if d.ota != nil {
				return d.ota.decode(r)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	d.Fabrics.SetLastIndex(last)
	return nil
}

func (d *Device) decodeFabric(r *tlv.Reader) error {
	var (
		index         uint8
		vendor        uint16
		label         string
		rcac, icac    []byte
		noc, key, ipk []byte
	)
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			index, err = r.Uint8()
		case 2:
			vendor, err = r.Uint16()
		case 3:
			label, err = r.String()
		case 4, 5, 6, 7, 8:
			var v []byte
			if v, err = r.Bytes(); err != nil {
				return err
			}
			v = append([]byte(nil), v...)
			switch tag {
			case 4:
				rcac = v
			case 5:
				icac = v
			case 6:
				noc = v
			case 7:
				key = v
			case 8:
				ipk = v
			}
		}
		return err
	})
	if err != nil {
		return err
	}
	k, err := p256.NewPrivateKey(key)
	if err != nil {
		return err
	}
	_, err = d.Fabrics.Restore(index, rcac, icac, noc, k, ipk, vendor, label)
	return err
}

func (d *Device) decodeNetworks(r *tlv.Reader) error {
	if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
		return errState
	}
	var ns []clusters.WiFiNetwork
	for r.Next() == nil {
		var n clusters.WiFiNetwork
		err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
			if tag != 1 && tag != 2 {
				return nil
			}
			v, err := r.Bytes()
			if tag == 1 {
				n.SSID = v
			} else {
				n.Credentials = v
			}
			return err
		})
		if err != nil || len(n.SSID) == 0 {
			return errState
		}
		ns = append(ns, n)
	}
	if d.Net != nil {
		d.Net.Restore(ns)
	}
	return r.ExitContainer()
}

// load restores state from the store.
func (d *Device) load() error {
	b, err := d.cfg.Store.Load()
	if err != nil || len(b) == 0 {
		return err
	}
	if err := d.decodeState(b); err != nil {
		// Start clean rather than half-restored.
		for _, f := range append(d.Fabrics.Fabrics()[:0:0], d.Fabrics.Fabrics()...) {
			d.Fabrics.Remove(f.Index)
		}
		d.ACL.Entries = nil
		if d.Net != nil {
			d.Net.Restore(nil)
		}
		d.eventLimit, d.Diagnostics.RebootCount = 0, 0
		*d.Groups = clusters.GroupData{Fabrics: d.Fabrics, OnChange: d.Groups.OnChange}
		d.appState = nil
		if d.ota != nil {
			d.ota.c.Providers, d.ota.pending = nil, nil
			d.ota.c.InitState(clusters.OTAStateIdle)
		}
		return err
	}
	return nil
}

// save writes the state if it changed since the last save.
func (d *Device) save() {
	if d.cfg.Store == nil {
		return
	}
	b := d.encodeState()
	if string(b) == string(d.saved) {
		return
	}
	if err := d.cfg.Store.Save(b); err != nil {
		d.log("saving state failed: " + err.Error())
		return
	}
	d.saved = b
	d.log("state saved")
}

// persistent reports whether a change to p affects stored state.
func persistent(p im.ConcretePath) bool {
	return p.Endpoint == 0 && (p.Cluster == clusters.IDAccessControl || p.Cluster == clusters.IDOperationalCredentials)
}
