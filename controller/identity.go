package controller

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// A running controller's CASE identity is a node ID (with the
// administrator CAT) and the resumption records of the sessions it opened
// under it. Identities are kept in slots in the state directory, each
// locked by the controller using it: controllers run one after another
// take the first slot and resume their sessions with nodes instead of
// repeating the full handshake, and controllers running at once get
// distinct node IDs.
const (
	identityDir   = "identities"
	identitySlots = 8
)

type identity struct {
	NodeID      uint64 `json:"nodeId"`
	Resumptions []byte `json:"resumptions,omitempty"` // casesession.ResumptionStore.Encode, TLV

	dir  string   // "" when not saved (no slot was free)
	name string   // slot file name
	lock *os.File // held while the controller runs
}

// claimIdentity takes the first free identity slot in dir, creating its
// node ID if the slot is new, and restores its resumption records into
// rs. With every slot taken, or no locking on this system, it returns a
// new identity that is not saved.
func claimIdentity(dir string, rs *casesession.ResumptionStore) (*identity, error) {
	idDir := filepath.Join(dir, identityDir)
	if err := os.MkdirAll(idDir, 0o700); err != nil {
		return nil, err
	}
	for i := 0; i < identitySlots; i++ {
		name := strconv.Itoa(i)
		lock, err := os.OpenFile(filepath.Join(idDir, name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if !tryLock(lock) {
			lock.Close()
			continue
		}
		id := &identity{dir: idDir, name: name + ".json", lock: lock}
		b, err := os.ReadFile(filepath.Join(idDir, id.name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			lock.Close()
			return nil, err
		default:
			if err := json.Unmarshal(b, id); err != nil {
				lock.Close()
				return nil, err
			}
		}
		if id.NodeID == 0 {
			id.NodeID = controllerNodeID()
			if err := id.save(nil); err != nil {
				lock.Close()
				return nil, err
			}
		}
		if len(id.Resumptions) > 0 {
			r := tlv.NewReader(id.Resumptions)
			if r.Next() != nil || rs.Decode(r) != nil {
				*rs = casesession.ResumptionStore{Max: rs.Max} // unreadable: start afresh
			}
		}
		return id, nil
	}
	return &identity{NodeID: controllerNodeID()}, nil
}

// save writes the identity with rs's records, if it has a slot.
func (id *identity) save(rs *casesession.ResumptionStore) error {
	if id.dir == "" {
		return nil
	}
	if rs != nil {
		w := tlv.NewWriter(nil)
		rs.Encode(w, tlv.Anonymous, nil)
		id.Resumptions = w.Bytes()
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(id.dir, id.name, append(b, '\n'))
}

// release unlocks the slot.
func (id *identity) release() {
	if id.lock != nil {
		id.lock.Close()
		id.lock = nil
	}
}
