package credentials

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

func loadVectors(t *testing.T) map[string]map[string][]byte {
	b, err := os.ReadFile("testdata/chip_certs.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]string
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string][]byte{}
	for name, kinds := range raw {
		out[name] = map[string][]byte{}
		for k, v := range kinds {
			out[name][k], _ = hex.DecodeString(v)
		}
	}
	return out
}

// TestSDKVectors checks TLV decoding, re-encoding and the X.509
// reconstruction against the connectedhomeip certificate test vectors.
func TestSDKVectors(t *testing.T) {
	vec := loadVectors(t)
	certs := map[string]*Cert{}
	var names []string
	for name, v := range vec {
		c, err := DecodeCert(v["Chip"])
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := c.Encode(); !bytes.Equal(got, v["Chip"]) {
			t.Errorf("%s: re-encoding differs", name)
		}
		if got := c.X509(); !bytes.Equal(got, v["DER"]) {
			t.Errorf("%s: X.509 differs\n got %x\nwant %x", name, got, v["DER"])
		}
		certs[name] = c
		names = append(names, name)
	}
	sort.Strings(names)
	// Every certificate's signature verifies under some certificate in the
	// set whose subject is its issuer.
	for _, name := range names {
		c := certs[name]
		ok := false
		for _, is := range certs {
			if dnEqual(c.Issuer, is.Subject) && c.VerifySignature(is.PublicKey) == nil {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: no issuer verifies its signature", name)
		}
	}
	// Chain validation: Node01_01 is issued by ICA01 under Root01.
	id, err := ValidateNOCChain(vec["Node01_01"]["Chip"], vec["ICA01"]["Chip"], vec["Root01"]["Chip"])
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID == 0 || id.FabricID == 0 {
		t.Fatalf("identity %+v", id)
	}
	if _, err := ValidateNOCChain(vec["Node01_01"]["Chip"], nil, vec["Root02"]["Chip"]); err == nil {
		t.Fatal("chain to the wrong root accepted")
	}
	// A flipped signature byte is caught.
	bad := bytes.Clone(vec["Node01_01"]["Chip"])
	bad[len(bad)-3] ^= 1
	if _, err := ValidateNOCChain(bad, vec["ICA01"]["Chip"], vec["Root01"]["Chip"]); err == nil {
		t.Fatal("bad signature accepted")
	}

	// The CASE peer variant gives the same identity, remembering the NOC's
	// and ICAC's signatures; what it remembers lets no other certificate
	// through.
	var cache SignatureCache
	for i := 0; i < 2; i++ {
		got, err := ValidatePeerNOCChain(vec["Node01_01"]["Chip"], vec["ICA01"]["Chip"], vec["Root01"]["Chip"], &cache)
		if err != nil || got.NodeID != id.NodeID || got.FabricID != id.FabricID || !bytes.Equal(got.PublicKey, id.PublicKey) {
			t.Fatalf("peer chain, pass %d: %+v %v", i, got, err)
		}
	}
	if cache.n != 2 {
		t.Fatalf("%d signatures cached, want the ICAC's and the NOC's", cache.n)
	}
	if _, err := ValidatePeerNOCChain(bad, vec["ICA01"]["Chip"], vec["Root01"]["Chip"], &cache); err == nil {
		t.Fatal("bad signature accepted with the good one cached")
	}
	if _, err := ValidatePeerNOCChain(vec["Node01_01"]["Chip"], vec["ICA01"]["Chip"], vec["Root02"]["Chip"], &cache); err == nil {
		t.Fatal("cached chain accepted under another root")
	}
	if _, err := ValidatePeerNOCChain(vec["Node01_02"]["Chip"], nil, vec["Root01"]["Chip"], &cache); err != nil {
		t.Fatalf("a NOC issued by the root itself: %v", err)
	}
	if cache.n != 3 {
		t.Fatalf("%d signatures cached after a second NOC", cache.n)
	}
}

func TestSignatureDER(t *testing.T) {
	k, _ := p256.GenerateKey(rand.Reader)
	for i := 0; i < 50; i++ {
		sig, _ := k.SignMessage(rand.Reader, []byte{byte(i)})
		d := SignatureToDER(sig)
		back, ok := SignatureFromDER(d)
		if !ok || !bytes.Equal(back, sig) {
			t.Fatalf("round trip failed for %x", sig)
		}
	}
}

// TestIssue builds a root and NOC in code and checks them with crypto/x509.
func TestIssue(t *testing.T) {
	rootKey, _ := p256.GenerateKey(rand.Reader)
	nodeKey, _ := p256.GenerateKey(rand.Reader)
	root, noc, err := NewFabric(rootKey, nodeKey, 0x1234, 0xABCDEF)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ValidateNOCChain(noc, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID != 0xABCDEF || id.FabricID != 0x1234 || !bytes.Equal(id.PublicKey, nodeKey.PublicKey().Bytes()) {
		t.Fatalf("identity %+v", id)
	}
	rc, _ := DecodeCert(root)
	nc, _ := DecodeCert(noc)
	xr, err := x509.ParseCertificate(rc.X509())
	if err != nil {
		t.Fatal(err)
	}
	xn, err := x509.ParseCertificate(nc.X509())
	if err != nil {
		t.Fatal(err)
	}
	if err := xn.CheckSignatureFrom(xr); err != nil {
		t.Fatal(err)
	}
}

func TestCSR(t *testing.T) {
	k, _ := p256.GenerateKey(rand.Reader)
	b, err := NewCSR(rand.Reader, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.Organization[0] != "CSR" {
		t.Fatalf("subject %v", csr.Subject)
	}
}

// A zero validity time is "no well-defined time" for not-before as well
// as not-after: X.509 99991231235959Z, as the SDK's ChipEpochToASN1Time
// and matter.js convert it. Signatures cover this form.
func TestZeroValidityDER(t *testing.T) {
	c := &Cert{SerialNumber: []byte{1}, PathLen: -1, NotBefore: 0, NotAfter: 0}
	never := "180f39393939313233313233353935395a" // GeneralizedTime 99991231235959Z
	if !strings.Contains(hex.EncodeToString(c.TBS()), "30"+"22"+never+never) {
		t.Errorf("zero validity: %x", c.TBS())
	}
	c.NotBefore, c.NotAfter = 1, 0x7FFFFFFF // 2000-01-01T00:00:01Z, 2068-01-19T03:14:07Z
	want := "3020" + hex.EncodeToString(append([]byte{0x17, 13}, "000101000001Z"...)) +
		hex.EncodeToString(append([]byte{0x18, 15}, "20680119031407Z"...))
	if !strings.Contains(hex.EncodeToString(c.TBS()), want) {
		t.Errorf("validity: %x, want %s", c.TBS(), want)
	}
}

func TestIssuedValidity(t *testing.T) {
	key, _ := p256.GenerateKey(rand.Reader)
	root, err := IssueRoot(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := uint32(time.Now().Unix() - MatterEpoch)
	if root.NotBefore == 0 || root.NotBefore > now || now-root.NotBefore > 2*3600 || root.NotAfter != 0 {
		t.Errorf("validity %d..%d, now %d", root.NotBefore, root.NotAfter, now)
	}
	if err := root.VerifySignature(root.PublicKey); err != nil {
		t.Error(err)
	}
}

func TestValidateNOCChainRejectsBadUsageAndConstraints(t *testing.T) {
	now := uint32(1)
	signCert := func(t *testing.T, c *Cert, pub *p256.PublicKey, signer *p256.PrivateKey) []byte {
		t.Helper()
		c.SerialNumber = []byte{1}
		c.NotBefore = now
		c.PublicKey = pub.Bytes()
		if err := c.Sign(rand.Reader, signer); err != nil {
			t.Fatal(err)
		}
		return c.Encode()
	}

	rootKey, _ := p256.GenerateKey(rand.Reader)
	icaKey, _ := p256.GenerateKey(rand.Reader)
	nodeKey, _ := p256.GenerateKey(rand.Reader)
	rootDN := DN{{Tag: DNMatterRCACID, Uint: 1}}
	icaDN := DN{{Tag: DNMatterICACID, Uint: 2}}
	nocDN := DN{{Tag: DNMatterFabricID, Uint: 0x1234}, {Tag: DNMatterNodeID, Uint: 0x5678}}

	// Baseline valid chain with PathLen=1 root -> PathLen=0 ICAC -> NOC.
	validRoot := signCert(t, &Cert{
		Issuer: rootDN, Subject: rootDN, IsCA: true, PathLen: 1, KeyUsage: KeyUsageKeyCertSign | KeyUsageCRLSign,
	}, rootKey.PublicKey(), rootKey)
	validICA := signCert(t, &Cert{
		Issuer: rootDN, Subject: icaDN, IsCA: true, PathLen: 0, KeyUsage: KeyUsageKeyCertSign,
	}, icaKey.PublicKey(), rootKey)
	validNOC := signCert(t, &Cert{
		Issuer: rootDN, Subject: nocDN, PathLen: -1,
		KeyUsage: KeyUsageDigitalSignature, ExtKeyUsage: []uint8{EKUClientAuth, EKUServerAuth},
	}, nodeKey.PublicKey(), rootKey)
	validICANNOC := signCert(t, &Cert{
		Issuer: icaDN, Subject: nocDN, PathLen: -1,
		KeyUsage: KeyUsageDigitalSignature, ExtKeyUsage: []uint8{EKUClientAuth, EKUServerAuth},
	}, nodeKey.PublicKey(), icaKey)

	if _, err := ValidateNOCChain(validICANNOC, validICA, validRoot); err != nil {
		t.Fatalf("valid chain failed: %v", err)
	}

	// 1. RCAC missing KeyUsageKeyCertSign.
	noCertSignRoot := signCert(t, &Cert{
		Issuer: rootDN, Subject: rootDN, IsCA: true, PathLen: -1, KeyUsage: KeyUsageDigitalSignature,
	}, rootKey.PublicKey(), rootKey)
	if _, err := ValidateNOCChain(validNOC, nil, noCertSignRoot); err == nil {
		t.Fatal("accepted RCAC without KeyUsageKeyCertSign")
	}

	// 2. Non-self-issued RCAC (Issuer != Subject, even if self-signed).
	nonSelfIssuedRoot := signCert(t, &Cert{
		Issuer: DN{{Tag: DNMatterRCACID, Uint: 99}}, Subject: rootDN,
		IsCA: true, PathLen: -1, KeyUsage: KeyUsageKeyCertSign,
	}, rootKey.PublicKey(), rootKey)
	if _, err := ValidateNOCChain(validNOC, nil, nonSelfIssuedRoot); err == nil {
		t.Fatal("accepted non-self-issued RCAC")
	}

	// 3. RCAC with PathLen=0 cannot authorize an ICAC.
	pathLen0Root := signCert(t, &Cert{
		Issuer: rootDN, Subject: rootDN, IsCA: true, PathLen: 0, KeyUsage: KeyUsageKeyCertSign,
	}, rootKey.PublicKey(), rootKey)
	if _, err := ValidateNOCChain(validICANNOC, validICA, pathLen0Root); err == nil {
		t.Fatal("accepted ICAC under RCAC with PathLen=0")
	}

	// 4. NOC with partial ExtKeyUsage (missing EKUClientAuth).
	partialEKUNOC := signCert(t, &Cert{
		Issuer: rootDN, Subject: nocDN, PathLen: -1,
		KeyUsage: KeyUsageDigitalSignature, ExtKeyUsage: []uint8{EKUServerAuth},
	}, nodeKey.PublicKey(), rootKey)
	if _, err := ValidateNOCChain(partialEKUNOC, nil, validRoot); err == nil {
		t.Fatal("accepted NOC missing EKUClientAuth")
	}
}
