package devcreds

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

func TestCredentials(t *testing.T) {
	k, err := p256.NewPrivateKey(DACPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.PublicKey().Bytes(), DACPublicKey) {
		t.Fatal("DAC key pair mismatch")
	}
	dac, err := x509.ParseCertificate(DACCert)
	if err != nil {
		t.Fatal(err)
	}
	pai, err := x509.ParseCertificate(PAICert)
	if err != nil {
		t.Fatal(err)
	}
	if err := dac.CheckSignatureFrom(pai); err != nil {
		t.Fatal(err)
	}
	// The CD's TLV payload starts with format version 1, vendor 0xFFF1.
	if !bytes.Contains(CertificationDeclaration, []byte{0x15, 0x24, 0x00, 0x01, 0x25, 0x01, 0xF1, 0xFF}) {
		t.Fatal("CD is not for vendor 0xFFF1")
	}
}
