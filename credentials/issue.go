package credentials

import (
	"crypto/rand"
	"crypto/sha1"
	"math"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// keyID is the subject key identifier of a public key (SHA-1, RFC 5280
// method 1).
func keyID(pub []byte) []byte {
	h := sha1.Sum(pub)
	return h[:]
}

// serial returns a random positive 8-byte serial number, so the
// certificates an issuer signs are told apart.
func serial() []byte {
	b := make([]byte, 8)
	rand.Read(b)
	b[0] = b[0]&0x7F | 0x40
	return b
}

// validFrom is the not-before time of issued certificates: an hour ago,
// against clock skew, or zero (no well-defined time) on a device whose
// clock is not set. They do not expire.
func validFrom() uint32 {
	t := time.Now().Add(-time.Hour).Unix() - MatterEpoch
	if t <= 0 || t > math.MaxUint32 {
		return 0
	}
	return uint32(t)
}

// IssueRoot returns a self-signed root (RCAC) for rcacID.
func IssueRoot(key *p256.PrivateKey, rcacID uint64) (*Cert, error) {
	pub := key.PublicKey().Bytes()
	c := &Cert{
		SerialNumber: serial(),
		NotBefore:    validFrom(),
		Issuer:       DN{{Tag: DNMatterRCACID, Uint: rcacID}},
		Subject:      DN{{Tag: DNMatterRCACID, Uint: rcacID}},
		PublicKey:    pub,
		IsCA:         true, PathLen: -1,
		KeyUsage:       KeyUsageKeyCertSign | KeyUsageCRLSign,
		SubjectKeyID:   keyID(pub),
		AuthorityKeyID: keyID(pub),
	}
	return c, c.Sign(rand.Reader, key)
}

// IssueNOC returns a node operational certificate for nodePub signed by
// the issuer (a root or ICA).
func IssueNOC(issuer *Cert, issuerKey *p256.PrivateKey, nodePub []byte, fabricID, nodeID uint64, cats ...uint32) (*Cert, error) {
	subj := DN{{Tag: DNMatterNodeID, Uint: nodeID}, {Tag: DNMatterFabricID, Uint: fabricID}}
	for _, c := range cats {
		subj = append(subj, DNAttr{Tag: DNMatterNOCCAT, Uint: uint64(c)})
	}
	c := &Cert{
		SerialNumber:   serial(),
		NotBefore:      validFrom(),
		Issuer:         issuer.Subject,
		Subject:        subj,
		PublicKey:      nodePub,
		PathLen:        -1,
		KeyUsage:       KeyUsageDigitalSignature,
		ExtKeyUsage:    []uint8{EKUClientAuth, EKUServerAuth},
		SubjectKeyID:   keyID(nodePub),
		AuthorityKeyID: issuer.SubjectKeyID,
	}
	return c, c.Sign(rand.Reader, issuerKey)
}

// NewFabric issues a root and a NOC (for tests and simple controllers),
// returning their TLV forms.
func NewFabric(rootKey, nodeKey *p256.PrivateKey, fabricID, nodeID uint64) (root, noc []byte, err error) {
	rc, err := IssueRoot(rootKey, 1)
	if err != nil {
		return nil, nil, err
	}
	nc, err := IssueNOC(rc, rootKey, nodeKey.PublicKey().Bytes(), fabricID, nodeID)
	if err != nil {
		return nil, nil, err
	}
	return rc.Encode(), nc.Encode(), nil
}
