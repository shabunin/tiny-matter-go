package controller

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// TestVendorID is the vendor ID the controller gives itself as an
// administrator (a test vendor ID, as the controller is not certified).
const TestVendorID = 0xFFF1

// Node is a device commissioned onto the controller's fabric.
type Node struct {
	ID        uint64    `json:"id"`
	Label     string    `json:"label,omitempty"`
	VendorID  uint16    `json:"vendorId"`
	ProductID uint16    `json:"productId"`
	Addr      string    `json:"addr,omitempty"` // last address that worked
	Added     time.Time `json:"added"`
}

// state is the controller's persistent state: its fabric (root CA,
// operational key and administrator CAT) and the nodes on it.
type state struct {
	FabricID uint64 `json:"fabricId"`
	VendorID uint16 `json:"vendorId"`
	// AdminCAT is the CASE Authenticated Tag that commissioned nodes
	// grant Administer to. Each running controller gets its own node ID
	// with this tag in its NOC, so several (such as one subscribing and
	// another invoking) are distinct peers to a node.
	AdminCAT   uint32  `json:"adminCat"`
	RootKey    []byte  `json:"rootKey"` // P-256 private scalar of the root CA
	Root       []byte  `json:"root"`    // root certificate (Matter TLV)
	Key        []byte  `json:"key"`     // the controller's operational key
	IPK        []byte  `json:"ipk"`     // identity protection epoch key
	NextNodeID uint64  `json:"nextNodeId"`
	Nodes      []*Node `json:"nodes"`

	Groups  []Group       `json:"groups,omitempty"`
	KeySets []GroupKeySet `json:"groupKeySets,omitempty"`
	// GroupNodeID is the node ID group messages are sent from, and
	// GroupCounter the last group data message counter used.
	GroupNodeID  uint64 `json:"groupNodeId,omitempty"`
	GroupCounter uint32 `json:"groupCounter,omitempty"`
}

// DefaultAdminCAT is the administrator CAT of new fabrics: identifier 1,
// version 1.
const DefaultAdminCAT = 0x0001_0001

// catSubject is the ACL subject of a CAT.
func catSubject(cat uint32) uint64 { return 0xFFFFFFFD_00000000 | uint64(cat) }

const stateFile = "controller.json"

func randUint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// newState creates a fabric: a root CA, an operational key and an IPK.
func newState() (*state, error) {
	rootKey, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	st := &state{
		FabricID:   randUint64()>>1 | 1,
		VendorID:   TestVendorID,
		AdminCAT:   DefaultAdminCAT,
		RootKey:    rootKey.Bytes(),
		Key:        key.Bytes(),
		IPK:        make([]byte, 16),
		NextNodeID: 1,
	}
	rand.Read(st.IPK)
	root, err := credentials.IssueRoot(rootKey, randUint64()>>1|1)
	if err != nil {
		return nil, err
	}
	st.Root = root.Encode()
	return st, nil
}

// controllerNodeID returns a random operational node ID (spec 2.5.5.1)
// for a running controller, far from the small IDs given to devices.
func controllerNodeID() uint64 { return randUint64()>>4 | 1<<59 }

// loadState reads the state in dir, creating a new fabric if there is
// none.
func loadState(dir string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		st, err := newState()
		if err != nil {
			return nil, err
		}
		return st, st.save(dir)
	}
	if err != nil {
		return nil, err
	}
	st := &state{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	if len(st.RootKey) == 0 || len(st.Root) == 0 || len(st.Key) == 0 || len(st.IPK) != 16 {
		return nil, errors.New("controller: incomplete state in " + dir)
	}
	if st.AdminCAT == 0 {
		return nil, errors.New("controller: state in " + dir + " is from an older version without an administrator CAT")
	}
	return st, nil
}

// save writes the state atomically, readable only by the owner: it holds
// the fabric's private keys.
func (st *state) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sort.Slice(st.Nodes, func(i, j int) bool { return st.Nodes[i].ID < st.Nodes[j].ID })
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, stateFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, stateFile))
}

func (st *state) node(id uint64) *Node {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// nextNodeID returns a free node ID.
func (st *state) nextNodeID() uint64 {
	for st.node(st.NextNodeID) != nil || st.NextNodeID == 0 {
		st.NextNodeID++
	}
	return st.NextNodeID
}
