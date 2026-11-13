package credentials

import (
	"crypto/rand"
	"crypto/sha1"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// keyID is the subject key identifier of a public key (SHA-1, RFC 5280
// method 1).
func keyID(pub []byte) []byte {
	h := sha1.Sum(pub)
	return h[:]
}

// IssueRoot returns a self-signed root (RCAC) for rcacID.
func IssueRoot(key *p256.PrivateKey, rcacID uint64) (*Cert, error) {
	pub := key.PublicKey().Bytes()
	c := &Cert{
		SerialNumber: []byte{1},
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
		SerialNumber:   []byte{2},
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
