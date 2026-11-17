// Package credentials handles Matter operational certificates (the compact
// TLV form of spec 6.5, its X.509 reconstruction for signature checks, and
// chain validation), certificate signing requests and attestation helpers.
package credentials

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/tlv"
)

var (
	ErrCertFormat    = errors.New("credentials: malformed certificate")
	ErrCertSignature = errors.New("credentials: certificate signature invalid")
	ErrCertChain     = errors.New("credentials: invalid certificate chain")
)

// Distinguished name attribute tags (spec 6.5.6). OR-ing PrintableFlag into
// a string attribute tag selects PrintableString encoding.
const (
	DNCommonName          = 1
	DNSurname             = 2
	DNSerialNumber        = 3
	DNCountry             = 4
	DNLocality            = 5
	DNState               = 6
	DNOrganization        = 7
	DNOrganizationalUnit  = 8
	DNTitle               = 9
	DNName                = 10
	DNGivenName           = 11
	DNInitials            = 12
	DNGenerationQualifier = 13
	DNQualifier           = 14
	DNPseudonym           = 15
	DNDomainComponent     = 16
	DNMatterNodeID        = 17
	DNMatterFWSigningID   = 18
	DNMatterICACID        = 19
	DNMatterRCACID        = 20
	DNMatterFabricID      = 21
	DNMatterNOCCAT        = 22

	PrintableFlag = 0x80
)

// Key usage flags.
const (
	KeyUsageDigitalSignature = 0x0001
	KeyUsageNonRepudiation   = 0x0002
	KeyUsageKeyEncipherment  = 0x0004
	KeyUsageDataEncipherment = 0x0008
	KeyUsageKeyAgreement     = 0x0010
	KeyUsageKeyCertSign      = 0x0020
	KeyUsageCRLSign          = 0x0040
)

// Extended key usage purposes.
const (
	EKUServerAuth = 1
	EKUClientAuth = 2
)

// DNAttr is one distinguished name attribute: Uint for Matter attributes
// (tags 17-22), Str otherwise.
type DNAttr struct {
	Tag  uint8
	Uint uint64
	Str  string
}

// DN is a distinguished name.
type DN []DNAttr

// Get returns the integer value of a Matter attribute.
func (d DN) Get(tag uint8) (uint64, bool) {
	for _, a := range d {
		if a.Tag == tag {
			return a.Uint, true
		}
	}
	return 0, false
}

// CATs returns the CASE Authenticated Tags in d.
func (d DN) CATs() []uint32 {
	var out []uint32
	for _, a := range d {
		if a.Tag == DNMatterNOCCAT {
			out = append(out, uint32(a.Uint))
		}
	}
	return out
}

func isMatterAttr(tag uint8) bool { return tag >= DNMatterNodeID && tag <= DNMatterNOCCAT }

// Extension tags, in the order they appear in a certificate.
const (
	extBasicConstraints = 1
	extKeyUsage         = 2
	extExtKeyUsage      = 3
	extSubjectKeyID     = 4
	extAuthorityKeyID   = 5
	extFuture           = 6
)

// Cert is a Matter certificate (spec 6.5.2).
type Cert struct {
	SerialNumber []byte
	Issuer       DN
	NotBefore    uint32 // Matter epoch seconds
	NotAfter     uint32 // 0: no expiry
	Subject      DN
	PublicKey    []byte // uncompressed P-256 point

	IsCA        bool
	PathLen     int // -1 when absent
	KeyUsage    uint16
	ExtKeyUsage []uint8
	SubjectKeyID,
	AuthorityKeyID []byte
	FutureExtensions [][]byte // raw DER Extension elements

	Signature []byte // raw r||s

	extOrder []uint8
}

// Tags of the certificate structure.
const (
	certSerial     = 1
	certSigAlgo    = 2
	certIssuer     = 3
	certNotBefore  = 4
	certNotAfter   = 5
	certSubject    = 6
	certPubKeyAlgo = 7
	certCurve      = 8
	certPubKey     = 9
	certExtensions = 10
	certSignature  = 11
)

// DecodeCert decodes a Matter TLV certificate.
func DecodeCert(b []byte) (*Cert, error) {
	c := &Cert{PathLen: -1}
	r := tlv.NewReader(b)
	if r.Next() != nil || r.Type() != tlv.TypeStruct || r.EnterContainer() != nil {
		return nil, ErrCertFormat
	}
	var seen uint16
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return nil, err
		}
		if r.Tag().Kind != tlv.TagContext {
			return nil, ErrCertFormat
		}
		tag := r.Tag().Number
		seen |= 1 << tag
		switch tag {
		case certSerial:
			v, err := r.Bytes()
			if err != nil || len(v) > 20 {
				return nil, ErrCertFormat
			}
			c.SerialNumber = append([]byte{}, v...)
		case certSigAlgo, certPubKeyAlgo, certCurve:
			if v, err := r.Uint(); err != nil || v != 1 {
				return nil, ErrCertFormat // ecdsa-with-SHA256, EC, prime256v1
			}
		case certIssuer, certSubject:
			dn, err := decodeDN(r)
			if err != nil {
				return nil, err
			}
			if tag == certIssuer {
				c.Issuer = dn
			} else {
				c.Subject = dn
			}
		case certNotBefore:
			if c.NotBefore, err = r.Uint32(); err != nil {
				return nil, ErrCertFormat
			}
		case certNotAfter:
			if c.NotAfter, err = r.Uint32(); err != nil {
				return nil, ErrCertFormat
			}
		case certPubKey:
			v, err := r.Bytes()
			if err != nil || len(v) != 65 {
				return nil, ErrCertFormat
			}
			c.PublicKey = append([]byte{}, v...)
		case certExtensions:
			if err := c.decodeExtensions(r); err != nil {
				return nil, err
			}
		case certSignature:
			v, err := r.Bytes()
			if err != nil || len(v) != 64 {
				return nil, ErrCertFormat
			}
			c.Signature = append([]byte{}, v...)
		default:
			return nil, ErrCertFormat
		}
	}
	if seen != 0b1111_1111_1110 || r.ExitContainer() != nil {
		return nil, ErrCertFormat
	}
	return c, nil
}

func decodeDN(r *tlv.Reader) (DN, error) {
	if r.Type() != tlv.TypeList || r.EnterContainer() != nil {
		return nil, ErrCertFormat
	}
	var dn DN
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil || r.Tag().Kind != tlv.TagContext || r.Tag().Number > 0xFF {
			return nil, ErrCertFormat
		}
		a := DNAttr{Tag: uint8(r.Tag().Number)}
		base := a.Tag &^ PrintableFlag
		switch {
		case a.Tag&PrintableFlag == 0 && isMatterAttr(a.Tag):
			if a.Uint, err = r.Uint(); err != nil {
				return nil, ErrCertFormat
			}
			if a.Tag == DNMatterNOCCAT && a.Uint > 0xFFFFFFFF {
				return nil, ErrCertFormat
			}
		case base >= DNCommonName && base <= DNDomainComponent:
			if a.Str, err = r.String(); err != nil {
				return nil, ErrCertFormat
			}
		default:
			return nil, ErrCertFormat
		}
		dn = append(dn, a)
	}
	if r.ExitContainer() != nil {
		return nil, ErrCertFormat
	}
	return dn, nil
}

func (c *Cert) decodeExtensions(r *tlv.Reader) error {
	if r.Type() != tlv.TypeList || r.EnterContainer() != nil {
		return ErrCertFormat
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil || r.Tag().Kind != tlv.TagContext {
			return ErrCertFormat
		}
		tag := uint8(r.Tag().Number)
		switch tag {
		case extBasicConstraints:
			if r.Type() != tlv.TypeStruct || r.EnterContainer() != nil {
				return ErrCertFormat
			}
			for {
				if err := r.Next(); err == tlv.ErrEndOfContainer {
					break
				} else if err != nil {
					return ErrCertFormat
				}
				switch {
				case r.Tag().IsContext(1):
					if c.IsCA, err = r.Bool(); err != nil {
						return ErrCertFormat
					}
				case r.Tag().IsContext(2):
					v, err := r.Uint8()
					if err != nil {
						return ErrCertFormat
					}
					c.PathLen = int(v)
				default:
					return ErrCertFormat
				}
			}
			if r.ExitContainer() != nil {
				return ErrCertFormat
			}
		case extKeyUsage:
			if c.KeyUsage, err = r.Uint16(); err != nil {
				return ErrCertFormat
			}
		case extExtKeyUsage:
			if r.Type() != tlv.TypeArray || r.EnterContainer() != nil {
				return ErrCertFormat
			}
			for {
				if err := r.Next(); err == tlv.ErrEndOfContainer {
					break
				} else if err != nil {
					return ErrCertFormat
				}
				v, err := r.Uint8()
				if err != nil || v < 1 || v > 6 {
					return ErrCertFormat
				}
				c.ExtKeyUsage = append(c.ExtKeyUsage, v)
			}
			if r.ExitContainer() != nil {
				return ErrCertFormat
			}
		case extSubjectKeyID, extAuthorityKeyID:
			v, err := r.Bytes()
			if err != nil || len(v) != 20 {
				return ErrCertFormat
			}
			if tag == extSubjectKeyID {
				c.SubjectKeyID = append([]byte{}, v...)
			} else {
				c.AuthorityKeyID = append([]byte{}, v...)
			}
		case extFuture:
			v, err := r.Bytes()
			if err != nil {
				return ErrCertFormat
			}
			c.FutureExtensions = append(c.FutureExtensions, append([]byte{}, v...))
		default:
			return ErrCertFormat
		}
		c.extOrder = append(c.extOrder, tag)
	}
	return r.ExitContainer()
}

// Encode returns the Matter TLV encoding of c.
func (c *Cert) Encode() []byte {
	w := tlv.NewWriter(make([]byte, 0, 400))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(certSerial), c.SerialNumber)
	w.PutUint(tlv.ContextTag(certSigAlgo), 1)
	encodeDN(w, certIssuer, c.Issuer)
	w.PutUint(tlv.ContextTag(certNotBefore), uint64(c.NotBefore))
	w.PutUint(tlv.ContextTag(certNotAfter), uint64(c.NotAfter))
	encodeDN(w, certSubject, c.Subject)
	w.PutUint(tlv.ContextTag(certPubKeyAlgo), 1)
	w.PutUint(tlv.ContextTag(certCurve), 1)
	w.PutBytes(tlv.ContextTag(certPubKey), c.PublicKey)
	w.StartList(tlv.ContextTag(certExtensions))
	future := 0
	for _, e := range c.extensionOrder() {
		switch e {
		case extBasicConstraints:
			w.StartStruct(tlv.ContextTag(extBasicConstraints))
			w.PutBool(tlv.ContextTag(1), c.IsCA)
			if c.PathLen >= 0 {
				w.PutUint(tlv.ContextTag(2), uint64(c.PathLen))
			}
			w.EndContainer()
		case extKeyUsage:
			w.PutUint(tlv.ContextTag(extKeyUsage), uint64(c.KeyUsage))
		case extExtKeyUsage:
			w.StartArray(tlv.ContextTag(extExtKeyUsage))
			for _, u := range c.ExtKeyUsage {
				w.PutUint(tlv.Anonymous, uint64(u))
			}
			w.EndContainer()
		case extSubjectKeyID:
			w.PutBytes(tlv.ContextTag(extSubjectKeyID), c.SubjectKeyID)
		case extAuthorityKeyID:
			w.PutBytes(tlv.ContextTag(extAuthorityKeyID), c.AuthorityKeyID)
		case extFuture:
			w.PutBytes(tlv.ContextTag(extFuture), c.FutureExtensions[future])
			future++
		}
	}
	w.EndContainer()
	w.PutBytes(tlv.ContextTag(certSignature), c.Signature)
	w.EndContainer()
	return w.Bytes()
}

// extensionOrder returns the order of extensions: as decoded, or the
// canonical order for certificates built in code.
func (c *Cert) extensionOrder() []uint8 {
	if c.extOrder != nil {
		return c.extOrder
	}
	var o []uint8
	o = append(o, extBasicConstraints)
	if c.KeyUsage != 0 {
		o = append(o, extKeyUsage)
	}
	if len(c.ExtKeyUsage) > 0 {
		o = append(o, extExtKeyUsage)
	}
	if c.SubjectKeyID != nil {
		o = append(o, extSubjectKeyID)
	}
	if c.AuthorityKeyID != nil {
		o = append(o, extAuthorityKeyID)
	}
	for range c.FutureExtensions {
		o = append(o, extFuture)
	}
	return o
}

func encodeDN(w *tlv.Writer, tag uint8, dn DN) {
	w.StartList(tlv.ContextTag(tag))
	for _, a := range dn {
		if a.Tag&PrintableFlag == 0 && isMatterAttr(a.Tag) {
			w.PutUint(tlv.ContextTag(a.Tag), a.Uint)
		} else {
			w.PutString(tlv.ContextTag(a.Tag), a.Str)
		}
	}
	w.EndContainer()
}

// ---- X.509 reconstruction ----

var (
	oidECDSAWithSHA256 = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}
	oidECPublicKey     = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}
	oidPrime256v1      = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	oidMatterPrefix    = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01}
	oidDomainComponent = []byte{0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19}
	oidBasicConstr     = []byte{0x55, 0x1D, 0x13}
	oidKeyUsage        = []byte{0x55, 0x1D, 0x0F}
	oidExtKeyUsage     = []byte{0x55, 0x1D, 0x25}
	oidSubjectKeyID    = []byte{0x55, 0x1D, 0x0E}
	oidAuthorityKeyID  = []byte{0x55, 0x1D, 0x23}
	oidKPPrefix        = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03}
)

// X.520 attribute type (2.5.4.x) for standard DN tags 1-15.
var x520 = [...]byte{0, 3, 4, 5, 6, 7, 8, 10, 11, 12, 41, 42, 43, 44, 46, 65}

// ekuOID maps Matter key purpose IDs to the last arc of id-kp.
var ekuOID = [...]byte{0, 1, 2, 3, 4, 8, 9}

func dnAttrDER(a DNAttr) []byte {
	base := a.Tag &^ PrintableFlag
	var oid, val []byte
	switch {
	case a.Tag&PrintableFlag == 0 && isMatterAttr(a.Tag):
		oid = append(append([]byte{}, oidMatterPrefix...), a.Tag-DNMatterNodeID+1)
		width := 16
		if a.Tag == DNMatterNOCCAT {
			width = 8
		}
		val = der(derUTF8String, hexUpper(a.Uint, width))
	case base == DNDomainComponent:
		oid, val = oidDomainComponent, der(derIA5String, []byte(a.Str))
	default:
		oid = []byte{0x55, 0x04, x520[base]}
		t := byte(derUTF8String)
		if a.Tag&PrintableFlag != 0 {
			t = derPrintable
		}
		val = der(t, []byte(a.Str))
	}
	return der(derSet, der(derSequence, der(derOID, oid), val))
}

func hexUpper(v uint64, width int) []byte {
	const digits = "0123456789ABCDEF"
	b := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		b[i] = digits[v&0xF]
		v >>= 4
	}
	return b
}

func nameDER(dn DN) []byte {
	parts := make([][]byte, len(dn))
	for i, a := range dn {
		parts[i] = dnAttrDER(a)
	}
	return der(derSequence, parts...)
}

// MatterEpoch is the start of Matter epoch time (2000-01-01T00:00:00Z) as
// Unix seconds.
const MatterEpoch = 946684800

// timeDER converts a validity time to X.509. Zero, "no well-defined
// time", becomes 99991231235959Z (RFC 5280 4.1.2.5) for not-before as
// well as not-after, as the Matter SDK and matter.js convert it.
func timeDER(v uint32) []byte {
	if v == 0 {
		return der(derGenTime, []byte("99991231235959Z"))
	}
	t := time.Unix(MatterEpoch+int64(v), 0).UTC()
	y, mo, d := t.Date()
	h, mi, s := t.Clock()
	b := make([]byte, 0, 15)
	tag := byte(derUTCTime)
	if y >= 2050 {
		tag = derGenTime
		b = append(b, byte('0'+y/1000), byte('0'+y/100%10))
	}
	for _, v := range [...]int{y % 100, int(mo), d, h, mi, s} {
		b = append(b, byte('0'+v/10), byte('0'+v%10))
	}
	return der(tag, append(b, 'Z'))
}

func extensionDER(oid []byte, critical bool, value []byte) []byte {
	if critical {
		return der(derSequence, der(derOID, oid), []byte{derBoolean, 1, 0xFF}, der(derOctetString, value))
	}
	return der(derSequence, der(derOID, oid), der(derOctetString, value))
}

func keyUsageBits(ku uint16) []byte {
	var b [2]byte
	high := -1
	for i := 0; i < 9; i++ {
		if ku&(1<<i) != 0 {
			b[i/8] |= 0x80 >> (i % 8)
			high = i
		}
	}
	if high < 0 {
		return der(derBitString, []byte{0})
	}
	n := high/8 + 1
	return der(derBitString, []byte{byte(7 - high%8)}, b[:n])
}

// TBS returns the DER TBSCertificate of the X.509 form of c, the data its
// signature covers.
func (c *Cert) TBS() []byte {
	var exts [][]byte
	future := 0
	for _, e := range c.extensionOrder() {
		switch e {
		case extBasicConstraints:
			var v []byte
			if c.IsCA {
				v = append(v, derBoolean, 1, 0xFF)
			}
			if c.PathLen >= 0 {
				v = append(v, derUint([]byte{byte(c.PathLen)})...)
			}
			exts = append(exts, extensionDER(oidBasicConstr, true, der(derSequence, v)))
		case extKeyUsage:
			exts = append(exts, extensionDER(oidKeyUsage, true, keyUsageBits(c.KeyUsage)))
		case extExtKeyUsage:
			var oids [][]byte
			for _, u := range c.ExtKeyUsage {
				oids = append(oids, der(derOID, oidKPPrefix, []byte{ekuOID[u]}))
			}
			exts = append(exts, extensionDER(oidExtKeyUsage, true, der(derSequence, oids...)))
		case extSubjectKeyID:
			exts = append(exts, extensionDER(oidSubjectKeyID, false, der(derOctetString, c.SubjectKeyID)))
		case extAuthorityKeyID:
			exts = append(exts, extensionDER(oidAuthorityKeyID, false, der(derSequence, der(0x80, c.AuthorityKeyID))))
		case extFuture:
			exts = append(exts, c.FutureExtensions[future])
			future++
		}
	}
	return der(derSequence,
		[]byte{0xA0, 0x03, 0x02, 0x01, 0x02}, // version v3
		der(derInteger, c.SerialNumber),
		der(derSequence, der(derOID, oidECDSAWithSHA256)),
		nameDER(c.Issuer),
		der(derSequence, timeDER(c.NotBefore), timeDER(c.NotAfter)),
		nameDER(c.Subject),
		der(derSequence,
			der(derSequence, der(derOID, oidECPublicKey), der(derOID, oidPrime256v1)),
			der(derBitString, []byte{0}, c.PublicKey)),
		der(0xA3, der(derSequence, exts...)),
	)
}

// X509 returns the DER X.509 form of c.
func (c *Cert) X509() []byte {
	return der(derSequence, c.TBS(),
		der(derSequence, der(derOID, oidECDSAWithSHA256)),
		der(derBitString, []byte{0}, SignatureToDER(c.Signature)))
}

// Sign sets c's signature using the issuer key.
func (c *Cert) Sign(rand interface{ Read([]byte) (int, error) }, issuer *p256.PrivateKey) error {
	sig, err := issuer.SignMessage(rand, c.TBS())
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}

// VerifySignature checks c's signature with the issuer's public key.
func (c *Cert) VerifySignature(issuerKey []byte) error {
	pub, err := p256.NewPublicKey(issuerKey)
	if err != nil {
		return ErrCertFormat
	}
	h := sha256.Sum256(c.TBS())
	if !pub.Verify(h[:], c.Signature) {
		return ErrCertSignature
	}
	return nil
}

// ---- chains ----

// OperationalIdentity is what a validated NOC chain establishes.
type OperationalIdentity struct {
	NodeID     uint64
	FabricID   uint64
	CATs       []uint32
	PublicKey  []byte // the node's operational public key
	RootPublic []byte // the trusted root's public key
}

// IsOperationalNodeID reports whether id is in the operational node ID range.
func IsOperationalNodeID(id uint64) bool { return id >= 1 && id <= 0xFFFFFFEFFFFFFFFF }

func validNOCEKU(eku []uint8) bool {
	if len(eku) == 0 {
		return true
	}
	var hasServer, hasClient bool
	for _, u := range eku {
		switch u {
		case EKUServerAuth:
			hasServer = true
		case EKUClientAuth:
			hasClient = true
		}
	}
	return hasServer && hasClient
}

// ValidateNOCChain validates noc (issued by icac, if present, else by root)
// against the trusted root certificate, all in Matter TLV form. Validity
// periods are not checked: devices commonly lack a trusted clock.
func ValidateNOCChain(noc, icac, root []byte) (*OperationalIdentity, error) {
	rc, err := DecodeCert(root)
	if err != nil {
		return nil, err
	}
	if _, ok := rc.Subject.Get(DNMatterRCACID); !ok || !rc.IsCA || rc.KeyUsage&KeyUsageKeyCertSign == 0 || !dnEqual(rc.Issuer, rc.Subject) {
		return nil, ErrCertChain
	}
	if err := rc.VerifySignature(rc.PublicKey); err != nil {
		return nil, err
	}
	issuer := rc
	if icac != nil {
		if rc.PathLen == 0 {
			return nil, ErrCertChain
		}
		ic, err := DecodeCert(icac)
		if err != nil {
			return nil, err
		}
		if _, ok := ic.Subject.Get(DNMatterICACID); !ok || !ic.IsCA || ic.KeyUsage&KeyUsageKeyCertSign == 0 {
			return nil, ErrCertChain
		}
		if err := checkIssued(ic, rc); err != nil {
			return nil, err
		}
		issuer = ic
	}
	nc, err := DecodeCert(noc)
	if err != nil {
		return nil, err
	}
	if nc.IsCA || nc.KeyUsage&KeyUsageDigitalSignature == 0 || !validNOCEKU(nc.ExtKeyUsage) {
		return nil, ErrCertChain
	}
	if err := checkIssued(nc, issuer); err != nil {
		return nil, err
	}
	id := &OperationalIdentity{PublicKey: nc.PublicKey, RootPublic: rc.PublicKey, CATs: nc.Subject.CATs()}
	var ok bool
	if id.NodeID, ok = nc.Subject.Get(DNMatterNodeID); !ok || !IsOperationalNodeID(id.NodeID) {
		return nil, ErrCertChain
	}
	if id.FabricID, ok = nc.Subject.Get(DNMatterFabricID); !ok || id.FabricID == 0 {
		return nil, ErrCertChain
	}
	// Fabric IDs present higher up the chain must match.
	for _, c := range []*Cert{issuer, rc} {
		if f, ok := c.Subject.Get(DNMatterFabricID); ok && f != id.FabricID {
			return nil, ErrCertChain
		}
	}
	return id, nil
}

// checkIssued checks that c was issued and signed by issuer.
func checkIssued(c, issuer *Cert) error {
	if !dnEqual(c.Issuer, issuer.Subject) {
		return ErrCertChain
	}
	if c.AuthorityKeyID != nil && issuer.SubjectKeyID != nil && !bytes.Equal(c.AuthorityKeyID, issuer.SubjectKeyID) {
		return ErrCertChain
	}
	return c.VerifySignature(issuer.PublicKey)
}

func dnEqual(a, b DN) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// String returns a short description of a DN, for logs.
func (d DN) String() string {
	s := ""
	for _, a := range d {
		if s != "" {
			s += ","
		}
		s += strconv.Itoa(int(a.Tag)) + "="
		if a.Str != "" || !isMatterAttr(a.Tag) {
			s += a.Str
		} else {
			s += string(hexUpper(a.Uint, 16))
		}
	}
	return s
}
