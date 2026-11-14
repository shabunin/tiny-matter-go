// Package fabric keeps the fabrics a node belongs to (spec 2.5.1, 11.18):
// their trusted roots, operational certificates and keys, and the identity
// protection key, with the pending state used during commissioning.
package fabric

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// MaxFabrics is the number of fabrics a node supports (spec minimum 5).
const MaxFabrics = 5

var (
	ErrTableFull = errors.New("fabric: table full")
	ErrConflict  = errors.New("fabric: fabric already present")
	ErrNotFound  = errors.New("fabric: no such fabric")
)

// Fabric is one fabric the node is a member of.
type Fabric struct {
	Index    uint8
	VendorID uint16
	FabricID uint64
	NodeID   uint64
	Label    string

	RootPublicKey []byte
	RCAC, ICAC    []byte // Matter TLV certificates; ICAC may be nil
	NOC           []byte
	Key           *p256.PrivateKey // operational key

	// IPK is the identity protection key epoch key; OperationalIPK is the
	// derived operational group key used in CASE destination IDs.
	IPK                [16]byte
	OperationalIPK     [16]byte
	CompressedFabricID [8]byte

	// Pending is set while the fabric was added under the fail-safe and not
	// yet committed by CommissioningComplete.
	Pending bool
}

// CompressedFabricID derives the compressed fabric identifier from the root
// public key and fabric ID (spec 4.3.2.2).
func CompressedFabricID(rootPub []byte, fabricID uint64) ([8]byte, error) {
	var out [8]byte
	if len(rootPub) != 65 {
		return out, errors.New("fabric: bad root public key")
	}
	salt := binary.BigEndian.AppendUint64(nil, fabricID)
	b, err := hkdf.Key(sha256.New, rootPub[1:], salt, "CompressedFabric", 8)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// OperationalGroupKey derives an operational group key from an epoch key
// (spec 4.17.2).
func OperationalGroupKey(epochKey []byte, compressedFabricID [8]byte) ([16]byte, error) {
	var out [16]byte
	b, err := hkdf.Key(sha256.New, epochKey, compressedFabricID[:], "GroupKey v1.0", 16)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// Table is the fabric table.
type Table struct {
	fabrics   []*Fabric
	lastIndex uint8
}

// Fabrics returns the fabrics, including a pending one.
func (t *Table) Fabrics() []*Fabric { return t.fabrics }

// Get returns the fabric with the given index, or nil.
func (t *Table) Get(index uint8) *Fabric {
	for _, f := range t.fabrics {
		if f.Index == index {
			return f
		}
	}
	return nil
}

// Committed returns the number of committed fabrics.
func (t *Table) Committed() int {
	n := 0
	for _, f := range t.fabrics {
		if !f.Pending {
			n++
		}
	}
	return n
}

// Add adds a pending fabric from a validated NOC chain. The caller supplies
// the operational key, IPK and admin vendor ID; Add assigns the index.
func (t *Table) Add(rcac, icac, noc []byte, key *p256.PrivateKey, ipk []byte, vendorID uint16) (*Fabric, error) {
	if len(t.fabrics) >= MaxFabrics {
		return nil, ErrTableFull
	}
	id, err := credentials.ValidateNOCChain(noc, icac, rcac)
	if err != nil {
		return nil, err
	}
	for _, f := range t.fabrics {
		if f.FabricID == id.FabricID && string(f.RootPublicKey) == string(id.RootPublic) {
			return nil, ErrConflict
		}
	}
	f := &Fabric{
		VendorID: vendorID, FabricID: id.FabricID, NodeID: id.NodeID,
		RootPublicKey: id.RootPublic, RCAC: rcac, ICAC: icac, NOC: noc, Key: key,
		Pending: true,
	}
	if f.CompressedFabricID, err = CompressedFabricID(id.RootPublic, id.FabricID); err != nil {
		return nil, err
	}
	if len(ipk) != 16 {
		return nil, errors.New("fabric: IPK must be 16 bytes")
	}
	copy(f.IPK[:], ipk)
	if f.OperationalIPK, err = OperationalGroupKey(ipk, f.CompressedFabricID); err != nil {
		return nil, err
	}
	f.Index = t.nextIndex()
	t.fabrics = append(t.fabrics, f)
	return f, nil
}

func (t *Table) nextIndex() uint8 {
	for {
		t.lastIndex++
		if t.lastIndex == 0 || t.lastIndex == 255 {
			t.lastIndex = 1
		}
		if t.Get(t.lastIndex) == nil {
			return t.lastIndex
		}
	}
}

// Commit makes pending fabrics permanent.
func (t *Table) Commit() {
	for _, f := range t.fabrics {
		f.Pending = false
	}
}

// RevertPending removes pending fabrics, returning their indexes.
func (t *Table) RevertPending() []uint8 {
	var removed []uint8
	out := t.fabrics[:0]
	for _, f := range t.fabrics {
		if f.Pending {
			removed = append(removed, f.Index)
			continue
		}
		out = append(out, f)
	}
	t.fabrics = out
	return removed
}

// Remove deletes a fabric.
func (t *Table) Remove(index uint8) error {
	for i, f := range t.fabrics {
		if f.Index == index {
			t.fabrics = append(t.fabrics[:i], t.fabrics[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

// Restore adds a committed fabric loaded from storage, keeping its index.
// The certificate chain is validated again.
func (t *Table) Restore(index uint8, rcac, icac, noc []byte, key *p256.PrivateKey, ipk []byte, vendorID uint16, label string) (*Fabric, error) {
	if index == 0 || index == 255 || t.Get(index) != nil {
		return nil, errors.New("fabric: bad or duplicate index")
	}
	saved := t.lastIndex
	f, err := t.Add(rcac, icac, noc, key, ipk, vendorID)
	t.lastIndex = saved
	if err != nil {
		return nil, err
	}
	f.Index, f.Label, f.Pending = index, label, false
	return f, nil
}

// LastIndex returns the most recently assigned fabric index, which is
// persisted so indexes are not reused soon after a removal.
func (t *Table) LastIndex() uint8 { return t.lastIndex }

// SetLastIndex restores LastIndex.
func (t *Table) SetLastIndex(i uint8) { t.lastIndex = i }
