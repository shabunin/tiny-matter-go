// Package attestation verifies device attestation for a commissioner
// (spec 6.2): the device attestation certificate (DAC) chain up to a
// trusted product attestation authority (PAA), the attestation and NOCSR
// signatures, and the certification declaration (CD). It follows the
// checks of the Matter SDK's default verifier. It uses crypto/x509 and is
// meant for hosts, not microcontrollers.
package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/tlv"
)

// Certification types of a CD.
const (
	CertificationDevelopment = 0 // development and test
	CertificationProvisional = 1
	CertificationOfficial    = 2
)

// Error is a failed attestation check.
type Error struct{ Reason string }

func (e *Error) Error() string { return "attestation: " + e.Reason }

func fail(format string, args ...any) error { return &Error{fmt.Sprintf(format, args...)} }

// Matter attribute types in certificate subjects.
var (
	oidVendorID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 2, 1}
	oidProductID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 2, 2}
)

// vidPID returns the vendor and product IDs in a certificate subject,
// from the Matter attribute types or, for legacy certificates, from
// "Mvid:XXXX" and "Mpid:XXXX" in the common name.
func vidPID(c *x509.Certificate) (vid, pid uint16, hasVID, hasPID bool, err error) {
	parse := func(v any) (uint16, error) {
		s, ok := v.(string)
		if !ok || len(s) != 4 || strings.ToUpper(s) != s {
			return 0, fail("malformed vendor or product ID %v", v)
		}
		n, err := strconv.ParseUint(s, 16, 16)
		if err != nil {
			return 0, fail("malformed vendor or product ID %q", s)
		}
		return uint16(n), nil
	}
	for _, n := range c.Subject.Names {
		switch {
		case n.Type.Equal(oidVendorID):
			vid, err = parse(n.Value)
			hasVID = true
		case n.Type.Equal(oidProductID):
			pid, err = parse(n.Value)
			hasPID = true
		}
		if err != nil {
			return
		}
	}
	if hasVID || hasPID {
		return
	}
	cn := c.Subject.CommonName
	if i := strings.Index(cn, "Mvid:"); i >= 0 && i+9 <= len(cn) {
		if vid, err = parse(cn[i+5 : i+9]); err != nil {
			return
		}
		hasVID = true
	}
	if i := strings.Index(cn, "Mpid:"); i >= 0 && i+9 <= len(cn) {
		if pid, err = parse(cn[i+5 : i+9]); err != nil {
			return
		}
		hasPID = true
	}
	return
}

//go:embed testpaa/*.der
var testPAAFiles embed.FS

//go:embed prodpaa/*.der
var prodPAAFiles embed.FS

// TestPAAs returns the SDK's test PAAs, which issue the PAIs of
// development devices (vendor IDs 0xFFF1 to 0xFFF4).
func TestPAAs() []*x509.Certificate { return embedded(testPAAFiles, "testpaa") }

// ProductionPAAs returns the production PAAs of certified devices: the
// Distributed Compliance Ledger's PAA roots as mirrored in the Matter SDK
// (credentials/production/paa-root-certs; see prodpaa/SOURCE.md for the
// version). PAAs approved since then are added with LoadPAAs.
func ProductionPAAs() []*x509.Certificate { return embedded(prodPAAFiles, "prodpaa") }

func embedded(fsys embed.FS, dir string) []*x509.Certificate {
	entries, _ := fsys.ReadDir(dir)
	var out []*x509.Certificate
	for _, e := range entries {
		b, _ := fsys.ReadFile(dir + "/" + e.Name())
		if c, err := x509.ParseCertificate(b); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// LoadPAAs reads the PAA certificates (DER or PEM) in a directory, such as
// the SDK's credentials/production/paa-root-certs. Files that are not
// certificates are skipped.
func LoadPAAs(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if p, _ := pem.Decode(b); p != nil {
			b = p.Bytes
		}
		if c, err := x509.ParseCertificate(b); err == nil && c.IsCA {
			out = append(out, c)
		}
	}
	return out, nil
}

// CD signing keys: the SDK's test key, then the CSA's official keys (from
// the SDK's DefaultDeviceAttestationVerifier).
var cdKeys = []struct{ kid, pub string }{
	{"62fa823359acfaa9963e1cfa140addf504f37160", "043c398922452b55caf389c25bd1bca4656952ccb90e8869249ad8474653014cbf95d687965e036b521c51037e6b8cedefca1eb44046694fa08882eed6519decba"},
	{"fe343f959947763b61ee4539131338494fe67d8e", "04cdeee93e44f8b72be3d1a9c07e21968b9afff3b403f05e1669d7b1e5caee6fc7714b42e7e23695e92cd7635473a280ae688f37bb9489e11629b9b94ff7b09929"},
	{"dd04db585b214c1c581587e6568df487b6ddc701", "04031937e8f94251045df27457bb46253ee3754e8c12ae28557d8027b9d4c356d91b408cff32275017b25f8c8ba20516d5c83af2b724128013dfcc8f95d200a90b"},
	{"471035e7c04eaaa8be7c4d4c13e3e4c20995a84b", "049f575cd5fdb7521f10a4df31f073912b614728f2d37f5b6b96bc2cbf7c0b119690577d555d21a09660a8b082a339ea530f7a812d8693b56fd764185fabcd32f5"},
	{"f68603a3692e981072419ea1e1ab3854bd7795d3", "047cfc8d8810a89cf4fa191778f2afec78f8517a97a3e57fc213bad888e3611e74ffb684bdeba8a68b25234a5c358f373bab9b6d304e1306dd7620a528d1161c0b"},
	{"637f2634ad62eafe6af662efb96f6fd2fcbffc2f", "04438a52c662a2a6d72647f95eb753136ee4ae0fdb3aa9c16931426b3d0867f9103ae7d7a1b887e9f813a6f26f76bbcda93593787c12778ca8f2975dc45a2042f9"},
}

const testCDKeyID = "62fa823359acfaa9963e1cfa140addf504f37160"

// CD is a decoded certification declaration (spec 6.3.1).
type CD struct {
	FormatVersion     uint8
	VendorID          uint16
	ProductIDs        []uint16
	DeviceTypeID      uint32
	CertificateID     string
	CertificationType uint8
	// DAC origin, if present: the IDs in the DAC and PAI of a product
	// built on another vendor's certified module.
	DACOriginVendorID, DACOriginProductID uint16
	HasDACOrigin                          bool
	// AuthorizedPAAs, if any, are the subject key IDs of the only PAAs
	// allowed to issue the product's PAI.
	AuthorizedPAAs [][]byte
	// TestKey reports whether the CD was signed with the SDK's test key.
	TestKey bool
}

// CMS structures (RFC 5652) of a CD: SignedData without certificates or
// signed attributes, signed by one signer identified by subject key ID.
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContent     cmsEncapContent
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

type cmsEncapContent struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,tag:0"`
}

type cmsSignerInfo struct {
	Version            int
	SubjectKeyID       []byte `asn1:"tag:0"`
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// VerifyCD checks the CMS signature of a certification declaration with
// the CSA's keys (and the SDK test key if allowTestKey) and decodes it. A
// CD signed with the test key must be of the development type.
func VerifyCD(cms []byte, allowTestKey bool) (*CD, error) {
	var ci cmsContentInfo
	if rest, err := asn1.Unmarshal(cms, &ci); err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) {
		return nil, fail("certification declaration is not CMS signed data")
	}
	var sd cmsSignedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil, fail("malformed certification declaration: %v", err)
	}
	if !sd.EncapContent.ContentType.Equal(oidData) || len(sd.SignerInfos) != 1 {
		return nil, fail("malformed certification declaration")
	}
	si := sd.SignerInfos[0]
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) || !si.SignatureAlgorithm.Algorithm.Equal(oidECDSA256) {
		return nil, fail("certification declaration not signed with ECDSA-SHA256")
	}
	kid := hex.EncodeToString(si.SubjectKeyID)
	var pub *ecdsa.PublicKey
	for _, k := range cdKeys {
		if k.kid == kid {
			b, _ := hex.DecodeString(k.pub)
			pub, _ = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
		}
	}
	test := kid == testCDKeyID
	if pub == nil || test && !allowTestKey {
		return nil, fail("certification declaration signed by unknown key %s", kid)
	}
	digest := sha256.Sum256(sd.EncapContent.Content)
	if !ecdsa.VerifyASN1(pub, digest[:], si.Signature) {
		return nil, fail("certification declaration signature invalid")
	}
	cd, err := decodeCD(sd.EncapContent.Content)
	if err != nil {
		return nil, err
	}
	cd.TestKey = test
	if test && cd.CertificationType != CertificationDevelopment {
		return nil, fail("test key signed a certification declaration of type %d", cd.CertificationType)
	}
	return cd, nil
}

func decodeCD(b []byte) (*CD, error) {
	cd := &CD{}
	r := tlv.NewReader(b)
	if r.Next() != nil || r.Type() != tlv.TypeStruct || r.EnterContainer() != nil {
		return nil, fail("malformed certification declaration content")
	}
	var have uint16
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return nil, fail("malformed certification declaration content")
		}
		if r.Tag().Kind != tlv.TagContext {
			continue
		}
		tag := r.Tag().Number
		have |= 1 << tag
		switch tag {
		case 0:
			cd.FormatVersion, err = r.Uint8()
		case 1:
			cd.VendorID, err = r.Uint16()
		case 2:
			err = r.EnterContainer()
			for err == nil {
				if err = r.Next(); err != nil {
					break
				}
				var pid uint16
				if pid, err = r.Uint16(); err == nil {
					cd.ProductIDs = append(cd.ProductIDs, pid)
				}
			}
			if err == tlv.ErrEndOfContainer {
				err = r.ExitContainer()
			}
		case 3:
			cd.DeviceTypeID, err = r.Uint32()
		case 4:
			cd.CertificateID, err = r.String()
		case 8:
			cd.CertificationType, err = r.Uint8()
		case 9:
			cd.DACOriginVendorID, err = r.Uint16()
		case 10:
			cd.DACOriginProductID, err = r.Uint16()
		case 11:
			err = r.EnterContainer()
			for err == nil {
				if err = r.Next(); err != nil {
					break
				}
				var kid []byte
				if kid, err = r.Bytes(); err == nil {
					cd.AuthorizedPAAs = append(cd.AuthorizedPAAs, bytes.Clone(kid))
				}
			}
			if err == tlv.ErrEndOfContainer {
				err = r.ExitContainer()
			}
		}
		if err != nil {
			return nil, fail("malformed certification declaration content")
		}
	}
	const required = 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<8
	if have&required != required || len(cd.ProductIDs) == 0 {
		return nil, fail("certification declaration lacks required fields")
	}
	if origin := have & (1<<9 | 1<<10); origin != 0 {
		if origin != 1<<9|1<<10 {
			return nil, fail("certification declaration has half a DAC origin")
		}
		cd.HasDACOrigin = true
	}
	if cd.FormatVersion != 1 || cd.CertificationType > CertificationOfficial {
		return nil, fail("unsupported certification declaration (format %d, type %d)", cd.FormatVersion, cd.CertificationType)
	}
	return cd, nil
}

func (cd *CD) hasProduct(pid uint16) bool {
	for _, p := range cd.ProductIDs {
		if p == pid {
			return true
		}
	}
	return false
}

// Verifier checks device attestation against a trust store.
type Verifier struct {
	// PAAs are the trusted product attestation authorities.
	PAAs []*x509.Certificate
	// AllowTestCD accepts certification declarations signed with the SDK
	// test key, as development devices carry.
	AllowTestCD bool
	// Now returns the current time (time.Now if nil).
	Now func() time.Time
}

// Info is what a commissioner gathers for attestation.
type Info struct {
	DAC, PAI []byte // DER, from CertificateChainRequest
	// Elements and Signature are from AttestationResponse; Nonce is the
	// AttestationNonce sent with the request.
	Elements, Signature, Nonce []byte
	// Challenge is the attestation challenge of the PASE session.
	Challenge []byte
	// VendorID and ProductID are the device's Basic Information
	// attributes.
	VendorID, ProductID uint16
}

// Result describes a device that passed attestation.
type Result struct {
	DAC                 *x509.Certificate
	VendorID, ProductID uint16 // from the DAC
	PAA                 *x509.Certificate
	CD                  *CD
	FirmwareInfo        []byte
	// DevelopmentCredentials reports a CD of the development and test
	// type, as the SDK examples and test devices carry.
	DevelopmentCredentials bool
}

// Verify checks the attestation of a device.
func (v *Verifier) Verify(info *Info) (*Result, error) {
	if len(info.Nonce) != 32 || len(info.Challenge) == 0 {
		return nil, fail("missing nonce or challenge")
	}
	dac, err := x509.ParseCertificate(info.DAC)
	if err != nil {
		return nil, fail("malformed DAC: %v", err)
	}
	pai, err := x509.ParseCertificate(info.PAI)
	if err != nil {
		return nil, fail("malformed PAI: %v", err)
	}
	if err := checkFormat(dac, false); err != nil {
		return nil, fail("DAC: %v", err)
	}
	if err := checkFormat(pai, true); err != nil {
		return nil, fail("PAI: %v", err)
	}
	dacVID, dacPID, hasDACVID, hasDACPID, err := vidPID(dac)
	if err != nil {
		return nil, err
	}
	paiVID, paiPID, hasPAIVID, hasPAIPID, err := vidPID(pai)
	if err != nil {
		return nil, err
	}
	if !hasDACVID || !hasPAIVID || paiVID != dacVID {
		return nil, fail("DAC and PAI vendor IDs differ")
	}
	if !hasDACPID || hasPAIPID && paiPID != dacPID {
		return nil, fail("DAC and PAI product IDs differ")
	}

	// The attestation signature covers the elements and the challenge.
	dacKey, ok := dac.PublicKey.(*ecdsa.PublicKey)
	if !ok || dacKey.Curve != elliptic.P256() {
		return nil, fail("DAC key is not P-256")
	}
	if !verifyRaw(dacKey, info.Elements, info.Challenge, info.Signature) {
		return nil, fail("attestation signature invalid")
	}

	// The PAI chains up to a trusted PAA.
	var paa *x509.Certificate
	for _, c := range v.PAAs {
		if len(pai.AuthorityKeyId) > 0 && bytes.Equal(c.SubjectKeyId, pai.AuthorityKeyId) {
			paa = c
			break
		}
	}
	if paa == nil {
		return nil, fail("PAA %X not trusted", pai.AuthorityKeyId)
	}
	paaVID, _, hasPAAVID, hasPAAPID, err := vidPID(paa)
	if err != nil {
		return nil, err
	}
	if hasPAAVID && paaVID != paiVID {
		return nil, fail("PAA and PAI vendor IDs differ")
	}
	if hasPAAPID {
		return nil, fail("PAA has a product ID")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if now.Before(dac.NotBefore) || now.After(dac.NotAfter) {
		return nil, fail("DAC not valid now")
	}
	// The issuers must have been valid when the DAC was issued.
	for _, c := range []*x509.Certificate{pai, paa} {
		if dac.NotBefore.Before(c.NotBefore) || dac.NotBefore.After(c.NotAfter) {
			return nil, fail("%s not valid when the DAC was issued", c.Subject.CommonName)
		}
	}
	if err := dac.CheckSignatureFrom(pai); err != nil {
		return nil, fail("DAC not signed by the PAI: %v", err)
	}
	if err := pai.CheckSignatureFrom(paa); err != nil {
		return nil, fail("PAI not signed by the PAA: %v", err)
	}

	cdCMS, nonce, firmware, err := decodeElements(info.Elements)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(nonce, info.Nonce) {
		return nil, fail("attestation nonce mismatch")
	}
	cd, err := VerifyCD(cdCMS, v.AllowTestCD)
	if err != nil {
		return nil, err
	}
	if cd.VendorID != info.VendorID {
		return nil, fail("CD vendor ID %#04x is not the device's %#04x", cd.VendorID, info.VendorID)
	}
	if !cd.hasProduct(info.ProductID) {
		return nil, fail("CD does not cover the device's product ID %#04x", info.ProductID)
	}
	if cd.HasDACOrigin {
		if dacVID != cd.DACOriginVendorID || paiVID != cd.DACOriginVendorID {
			return nil, fail("DAC vendor ID differs from the CD's DAC origin")
		}
		if dacPID != cd.DACOriginProductID || hasPAIPID && paiPID != cd.DACOriginProductID {
			return nil, fail("DAC product ID differs from the CD's DAC origin")
		}
	} else {
		if dacVID != cd.VendorID || paiVID != cd.VendorID {
			return nil, fail("DAC vendor ID differs from the CD's")
		}
		if !cd.hasProduct(dacPID) || hasPAIPID && !cd.hasProduct(paiPID) {
			return nil, fail("CD does not cover the DAC's product ID")
		}
	}
	if len(cd.AuthorizedPAAs) > 0 {
		ok := false
		for _, kid := range cd.AuthorizedPAAs {
			ok = ok || bytes.Equal(kid, paa.SubjectKeyId)
		}
		if !ok {
			return nil, fail("PAA not authorized by the CD")
		}
	}
	return &Result{DAC: dac, VendorID: dacVID, ProductID: dacPID, PAA: paa, CD: cd,
		FirmwareInfo: firmware, DevelopmentCredentials: cd.CertificationType == CertificationDevelopment}, nil
}

// checkFormat checks the parts of the attestation certificate profile
// that matter for the chain: P-256 ECDSA keys and the CA flags.
func checkFormat(c *x509.Certificate, ca bool) error {
	if c.Version != 3 || c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return errors.New("not an X.509v3 ECDSA-SHA256 certificate")
	}
	if k, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		return errors.New("key is not P-256")
	}
	if !c.BasicConstraintsValid || c.IsCA != ca {
		return errors.New("wrong basic constraints")
	}
	if ca && (c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0) {
		return errors.New("PAI may not issue CAs or does not sign certificates")
	}
	if !ca && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("DAC does not sign")
	}
	return nil
}

// verifyRaw checks a Matter (raw r||s) ECDSA-SHA256 signature over
// msg || challenge.
func verifyRaw(pub *ecdsa.PublicKey, msg, challenge, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(challenge)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h.Sum(nil), r, s)
}

// decodeElements decodes attestation-elements: the CD, the nonce and the
// optional firmware information.
func decodeElements(b []byte) (cd, nonce, firmware []byte, err error) {
	var have uint8
	err = structFields(b, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			cd, err = r.Bytes()
		case 2:
			nonce, err = r.Bytes()
		case 3:
			_, err = r.Uint32()
		case 4:
			firmware, err = r.Bytes()
		}
		if tag < 8 {
			have |= 1 << tag
		}
		return err
	})
	if err != nil || have&0b1110 != 0b1110 {
		return nil, nil, nil, fail("malformed attestation elements")
	}
	return cd, nonce, firmware, nil
}

// VerifyNOCSR checks the NOCSR elements of a CSRResponse, signed by the
// DAC over the elements and the attestation challenge, and returns the
// operational public key of the CSR they carry (65 bytes, uncompressed).
func VerifyNOCSR(dacDER, elements, signature, challenge, nonce []byte) ([]byte, error) {
	dac, err := x509.ParseCertificate(dacDER)
	if err != nil {
		return nil, fail("malformed DAC: %v", err)
	}
	dacKey, ok := dac.PublicKey.(*ecdsa.PublicKey)
	if !ok || !verifyRaw(dacKey, elements, challenge, signature) {
		return nil, fail("NOCSR signature invalid")
	}
	var csrDER, got []byte
	var have uint8
	err = structFields(elements, func(r *tlv.Reader, tag uint8) (err error) {
		switch tag {
		case 1:
			csrDER, err = r.Bytes()
			have |= 1
		case 2:
			got, err = r.Bytes()
			have |= 2
		}
		return err
	})
	if err != nil || have != 3 {
		return nil, fail("malformed NOCSR elements")
	}
	if len(nonce) != 32 || !bytes.Equal(got, nonce) {
		return nil, fail("CSR nonce mismatch")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fail("CSR invalid")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fail("CSR key is not P-256")
	}
	return key.Bytes()
}

func structFields(b []byte, f func(r *tlv.Reader, tag uint8) error) error {
	r := tlv.NewReader(b)
	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.TypeStruct {
		return errors.New("not a structure")
	}
	if err := r.EnterContainer(); err != nil {
		return err
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			return nil
		}
		if err != nil {
			return err
		}
		if r.Tag().Kind == tlv.TagContext {
			if err := f(r, uint8(r.Tag().Number)); err != nil {
				return err
			}
		}
	}
}
