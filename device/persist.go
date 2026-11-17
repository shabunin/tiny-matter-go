package device

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/storage"
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
//	11: Basic Information { 1: NodeLabel, 2: Location }
//	12: CASE resumption records (see casesession.ResumptionStore.Encode)
//	13: group data message counter: values from here on are unused
const stateVersion = 1

var errState = errors.New("device: malformed stored state")

// encodeState writes the persistent state (committed fabrics, ACL,
// networks, groups, application state...) to w. The state can be tens of
// KB (scene tables, five fabrics), a block a small, fragmented heap does not
// have once the node runs, so it is never held whole: save streams it
// through stateBuf, a small buffer allocated at start.
func (d *Device) encodeState(w *tlv.Writer) {
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
		icac, noc, key := f.CommittedCredentials()
		if icac != nil {
			w.PutBytes(tlv.ContextTag(5), icac)
		}
		w.PutBytes(tlv.ContextTag(6), noc)
		w.PutBytes(tlv.ContextTag(7), key.Bytes())
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
	if d.groupLimit != 0 {
		w.PutUint(tlv.ContextTag(13), uint64(d.groupLimit))
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
	// Basic Information's nonvolatile, writable attributes.
	w.StartStruct(tlv.ContextTag(11))
	w.PutString(tlv.ContextTag(1), d.cfg.Basic.NodeLabel)
	w.PutString(tlv.ContextTag(2), d.cfg.Basic.Location)
	w.EndContainer()
	// CASE resumption records, so controllers resume sessions (no
	// certificate exchange or signatures) after a restart.
	if d.Resumptions.Len() > 0 {
		d.Resumptions.Encode(w, tlv.ContextTag(12), func(index uint8) bool {
			f := d.Fabrics.Get(index)
			return f != nil && !f.Pending
		})
	}
	// Subscriptions, resumed after a restart.
	if d.Server.Subscriptions() > 0 {
		d.Server.EncodeSubscriptions(w, tlv.ContextTag(14), func(index uint8) bool {
			f := d.Fabrics.Get(index)
			return f != nil && !f.Pending
		})
	}
	w.EndContainer()
}

// stateBufSize is the size of stateBuf, through which the state is hashed
// and saved.
const stateBufSize = 512

// stateSum returns the SHA-256 of the encoded state, which save compares
// with that of the state last saved.
func (d *Device) stateSum() [32]byte {
	h := sha256.New()
	w := tlv.NewStreamWriter(d.stateBuf[:0], func(p []byte) error { h.Write(p); return nil })
	d.encodeState(w)
	w.Flush()
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// decodeBasic restores Basic Information's NodeLabel and Location.
func (d *Device) decodeBasic(r *tlv.Reader) error {
	return im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			d.cfg.Basic.NodeLabel, err = r.String()
		case 2:
			d.cfg.Basic.Location, err = r.String()
		}
		return err
	})
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
			return
		}
		// Start-up behaviour (StartUpOnOff Toggle, StartUpCurrentLevel...)
		// may have changed the state: save it before another restart
		// applies it to the old state again.
		w := tlv.NewWriter(nil)
		p.EncodeState(w, tlv.ContextTag(3)) // as stored, see encodeAppState
		if !bytes.Equal(w.Bytes(), a.state) {
			d.appWritten = true
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
		case 11:
			return d.decodeBasic(r)
		case 12:
			return d.Resumptions.Decode(r)
		case 13:
			v, err := r.Uint32()
			d.groupLimit = v
			return err
		case 14:
			return d.Server.DecodeSubscriptions(r)
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
		*d.Resumptions = casesession.ResumptionStore{Max: d.Resumptions.Max, OnChange: d.Resumptions.OnChange}
		if d.ota != nil {
			d.ota.c.Providers, d.ota.pending = nil, nil
			d.ota.c.InitState(clusters.OTAStateIdle)
		}
		return err
	}
	return nil
}

// Flush saves state changes that are still waiting (application state
// gathers for appSaveDelay): call it before a planned shutdown or restart.
func (d *Device) Flush() {
	d.appDirty, d.appWritten, d.appSave, d.dirty = false, false, time.Time{}, false
	d.save()
}

// save writes the state if it changed since the last save.
func (d *Device) save() {
	if d.cfg.Store == nil {
		return
	}
	sum := d.stateSum()
	if sum == d.savedSum {
		return
	}
	var err error
	n := 0
	if st, ok := d.cfg.Store.(storage.Streamer); ok {
		err = st.SaveFunc(func(write func([]byte) error) error {
			w := tlv.NewStreamWriter(d.stateBuf[:0], func(p []byte) error { n += len(p); return write(p) })
			d.encodeState(w)
			return w.Flush()
		})
	} else {
		// A Store that wants the whole blob (a host's file): only hosts
		// have the memory for it.
		w := tlv.NewWriter(nil)
		d.encodeState(w)
		n = w.Len()
		err = d.cfg.Store.Save(w.Bytes())
	}
	if err != nil {
		d.log("saving state failed: " + err.Error())
		return
	}
	d.savedSum = sum
	d.log("state saved, " + strconv.Itoa(n) + " bytes")
}

// persistent reports whether a change to p affects stored state.
func persistent(p im.ConcretePath) bool {
	return p.Endpoint == 0 && (p.Cluster == clusters.IDAccessControl || p.Cluster == clusters.IDOperationalCredentials ||
		p.Cluster == clusters.IDBasicInformation && (p.Attribute == 0x0005 || p.Attribute == 0x0006)) // NodeLabel, Location
}
