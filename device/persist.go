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
	w.EndContainer()
	return w.Bytes()
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
