package credentials

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"

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
