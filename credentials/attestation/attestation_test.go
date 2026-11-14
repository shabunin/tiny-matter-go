package attestation

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// devInfo returns the attestation of a device with the SDK development
// credentials, as a commissioner gathers it.
func devInfo(t *testing.T) (*Info, *p256.PrivateKey) {
	t.Helper()
	dacKey, err := p256.NewPrivateKey(devcreds.DACPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, 32)
	challenge := bytes.Repeat([]byte{9}, 16)
	elems := credentials.AttestationElements(devcreds.CertificationDeclaration, nonce, 0, nil)
	sig, err := credentials.SignWithChallenge(rand.Reader, dacKey, elems, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return &Info{DAC: devcreds.DACCert, PAI: devcreds.PAICert, Elements: elems, Signature: sig,
		Nonce: nonce, Challenge: challenge, VendorID: devcreds.VendorID, ProductID: devcreds.ProductID}, dacKey
}

func TestVerifyDevelopmentDevice(t *testing.T) {
	info, _ := devInfo(t)
	v := &Verifier{PAAs: TestPAAs(), AllowTestCD: true}
	res, err := v.Verify(info)
	if err != nil {
		t.Fatal(err)
	}
	if res.VendorID != devcreds.VendorID || res.ProductID != devcreds.ProductID || !res.DevelopmentCredentials ||
		res.CD.VendorID != devcreds.VendorID || res.CD.CertificationType != CertificationDevelopment {
		t.Fatalf("result: %+v, CD %+v", res, res.CD)
	}
	if !strings.Contains(res.PAA.Subject.CommonName, "Test PAA") {
		t.Fatalf("PAA %s", res.PAA.Subject)
	}
}

func TestVerifyFailures(t *testing.T) {
	cases := []struct {
		name   string
		change func(v *Verifier, info *Info)
		want   string
	}{
		{"untrusted PAA", func(v *Verifier, _ *Info) { v.PAAs = nil }, "not trusted"},
		{"nonce", func(_ *Verifier, i *Info) { i.Nonce = bytes.Repeat([]byte{8}, 32) }, "nonce"},
		{"challenge", func(_ *Verifier, i *Info) { i.Challenge = []byte("other") }, "signature"},
		{"signature", func(_ *Verifier, i *Info) { i.Signature = bytes.Clone(i.Signature); i.Signature[3] ^= 1 }, "signature"},
		{"vendor", func(_ *Verifier, i *Info) { i.VendorID = 0xFFF2 }, "vendor"},
		{"product", func(_ *Verifier, i *Info) { i.ProductID = 0x8123 }, "product"},
		{"swapped chain", func(_ *Verifier, i *Info) { i.DAC, i.PAI = i.PAI, i.DAC }, "basic constraints"},
		{"not yet valid", func(v *Verifier, _ *Info) {
			v.Now = func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }
		}, "not valid"},
	}
	for _, c := range cases {
		info, _ := devInfo(t)
		v := &Verifier{PAAs: TestPAAs(), AllowTestCD: true}
		c.change(v, info)
		_, err := v.Verify(info)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestSDKCertificationDeclarations(t *testing.T) {
	b, err := os.ReadFile("testdata/Chip-Test-CD-FFF2-8001-8002.der")
	if err != nil {
		t.Fatal(err)
	}
	cd, err := VerifyCD(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if cd.VendorID != 0xFFF2 || len(cd.ProductIDs) != 2 || !cd.hasProduct(0x8001) || !cd.hasProduct(0x8002) ||
		!cd.TestKey || cd.HasDACOrigin || cd.FormatVersion != 1 {
		t.Fatalf("%+v", cd)
	}
	if _, err := VerifyCD(b, false); err == nil {
		t.Fatal("test key accepted")
	}
	// The content is signed: changing the certificate ID breaks it.
	bad := bytes.Clone(b)
	i := bytes.Index(bad, []byte(cd.CertificateID))
	bad[i] ^= 1
	if _, err := VerifyCD(bad, true); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered CD: %v", err)
	}

	b, err = os.ReadFile("testdata/Chip-Test-CD-FFF2-8001-8002-WithDACOrigin.der")
	if err != nil {
		t.Fatal(err)
	}
	cd, err = VerifyCD(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if !cd.HasDACOrigin || cd.DACOriginVendorID != 0xFFF1 {
		t.Fatalf("%+v", cd)
	}
}

func TestNOCSR(t *testing.T) {
	_, dacKey := devInfo(t)
	opKey, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := credentials.NewCSR(rand.Reader, opKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{5}, 32)
	challenge := []byte("challenge")
	elems := credentials.NOCSRElements(csr, nonce)
	sig, err := credentials.SignWithChallenge(rand.Reader, dacKey, elems, challenge)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := VerifyNOCSR(devcreds.DACCert, elems, sig, challenge, nonce)
	if err != nil || !bytes.Equal(pub, opKey.PublicKey().Bytes()) {
		t.Fatalf("%x %v", pub, err)
	}
	if _, err := VerifyNOCSR(devcreds.DACCert, elems, sig, challenge, bytes.Repeat([]byte{6}, 32)); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	if _, err := VerifyNOCSR(devcreds.DACCert, elems, sig, []byte("other"), nonce); err == nil {
		t.Fatal("wrong challenge accepted")
	}
}

func TestLoadPAAs(t *testing.T) {
	dir := t.TempDir()
	for i, c := range TestPAAs() {
		name := []string{"a.der", "b.der"}[i]
		if err := os.WriteFile(dir+"/"+name, c.Raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(dir+"/README", []byte("not a certificate"), 0o644)
	paas, err := LoadPAAs(dir)
	if err != nil || len(paas) != 2 {
		t.Fatalf("%d PAAs, %v", len(paas), err)
	}
	var _ []*x509.Certificate = paas
}

func TestProductionPAAs(t *testing.T) {
	paas := ProductionPAAs()
	if len(paas) != 73 {
		t.Fatalf("%d production PAAs, want 73", len(paas))
	}
	seen := map[string]bool{}
	for _, c := range paas {
		name := c.Subject.String()
		if err := c.CheckSignatureFrom(c); err != nil {
			t.Errorf("%s: not self-signed: %v", name, err)
		}
		if !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 || c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Errorf("%s: not an ECDSA-SHA256 signing CA", name)
		}
		if len(c.SubjectKeyId) == 0 || seen[string(c.SubjectKeyId)] {
			t.Errorf("%s: missing or duplicate subject key ID", name)
		}
		seen[string(c.SubjectKeyId)] = true
		if _, _, _, hasPID, err := vidPID(c); err != nil || hasPID {
			t.Errorf("%s: a PAA carries no product ID (err %v)", name, err)
		}
	}
	// None of the SDK test PAAs is among them.
	for _, tp := range TestPAAs() {
		if seen[string(tp.SubjectKeyId)] {
			t.Errorf("test PAA %s in the production set", tp.Subject)
		}
	}
}
