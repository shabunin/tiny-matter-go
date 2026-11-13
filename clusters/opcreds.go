package clusters

import (
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// NOC status codes (NodeOperationalCertStatusEnum).
const (
	NOCOK                  = 0
	NOCInvalidPublicKey    = 1
	NOCInvalidNodeOpID     = 2
	NOCInvalidNOC          = 3
	NOCMissingCsr          = 4
	NOCTableFull           = 5
	NOCInvalidAdminSubject = 6
	NOCFabricConflict      = 9
	NOCLabelConflict       = 10
	NOCInvalidFabricIndex  = 11
)

// Attestation holds the device attestation credentials.
type Attestation struct {
	DACKey                   *p256.PrivateKey
	DACCert, PAICert         []byte // DER
	CertificationDeclaration []byte
}

// OperationalCredentials is the Node Operational Credentials cluster. It
// adds fabrics under the fail-safe; GeneralCommissioning's
// CommissioningComplete commits them and fail-safe expiry reverts them.
type OperationalCredentials struct {
	im.ClusterBase
	Attestation *Attestation
	Fabrics     *fabric.Table
	FailSafe    *FailSafe
	ACL         *AccessControl
	Rand        io.Reader
	// OnFabricRemoved is called after a fabric is removed (to close its
	// sessions and forget its subscriptions).
	OnFabricRemoved func(now time.Time, index uint8)
	// OnFabricAdded is called after AddNOC adds a (pending) fabric.
	OnFabricAdded func(now time.Time, f *fabric.Fabric)

	// State of the commissioning in progress, reset when the fail-safe
	// ends.
	pendingKey  *p256.PrivateKey
	pendingRoot []byte
	addedNOC    bool
}

// NewOperationalCredentials returns the cluster and hooks its rollback to
// the fail-safe.
func NewOperationalCredentials(att *Attestation, ft *fabric.Table, fs *FailSafe, acl *AccessControl, rand io.Reader) *OperationalCredentials {
	o := &OperationalCredentials{Attestation: att, Fabrics: ft, FailSafe: fs, ACL: acl, Rand: rand}
	fs.OnExpire = append(fs.OnExpire, o.revert)
	return o
}

func (o *OperationalCredentials) revert(now time.Time) {
	for _, idx := range o.Fabrics.RevertPending() {
		o.ACL.RemoveFabric(idx)
		if o.OnFabricRemoved != nil {
			o.OnFabricRemoved(now, idx)
		}
	}
	o.Reset()
}

// Reset clears the commissioning state (after commit or rollback).
func (o *OperationalCredentials) Reset() {
	o.pendingKey, o.pendingRoot, o.addedNOC = nil, nil, false
}

func (*OperationalCredentials) ID() uint32       { return IDOperationalCredentials }
func (*OperationalCredentials) Revision() uint16 { return 1 }

const (
	ocNOCs                    = 0
	ocFabrics                 = 1
	ocSupportedFabrics        = 2
	ocCommissionedFabrics     = 3
	ocTrustedRootCertificates = 4
	ocCurrentFabricIndex      = 5

	ocAttestationRequest       = 0x00
	ocAttestationResponse      = 0x01
	ocCertificateChainRequest  = 0x02
	ocCertificateChainResponse = 0x03
	ocCSRRequest               = 0x04
	ocCSRResponse              = 0x05
	ocAddNOC                   = 0x06
	ocNOCResponse              = 0x08
	ocUpdateFabricLabel        = 0x09
	ocRemoveFabric             = 0x0A
	ocAddTrustedRootCert       = 0x0B
)

var (
	ocAttrs     = []uint32{0, 1, 2, 3, 4, 5}
	ocAccepted  = []uint32{ocAttestationRequest, ocCertificateChainRequest, ocCSRRequest, ocAddNOC, ocUpdateFabricLabel, ocRemoveFabric, ocAddTrustedRootCert}
	ocGenerated = []uint32{ocAttestationResponse, ocCertificateChainResponse, ocCSRResponse, ocNOCResponse}
)

func (*OperationalCredentials) Attributes() []uint32        { return ocAttrs }
func (*OperationalCredentials) AcceptedCommands() []uint32  { return ocAccepted }
func (*OperationalCredentials) GeneratedCommands() []uint32 { return ocGenerated }

func (*OperationalCredentials) ReadPrivilege(attr uint32) im.Privilege {
	if attr == ocNOCs {
		return im.Administer
	}
	return im.View
}
func (*OperationalCredentials) WritePrivilege(uint32) im.Privilege  { return im.Administer }
func (*OperationalCredentials) InvokePrivilege(uint32) im.Privilege { return im.Administer }

func (o *OperationalCredentials) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	acc := accessingFabric(ctx)
	switch attr {
	case ocNOCs:
		w.StartArray(tag)
		for _, f := range o.Fabrics.Fabrics() {
			if ctx.FabricFiltered && f.Index != acc {
				continue
			}
			w.StartStruct(tlv.Anonymous)
			if f.Index == acc {
				w.PutBytes(tlv.ContextTag(1), f.NOC)
				if f.ICAC == nil {
					w.PutNull(tlv.ContextTag(2))
				} else {
					w.PutBytes(tlv.ContextTag(2), f.ICAC)
				}
			}
			w.PutUint(tlv.ContextTag(0xFE), uint64(f.Index))
			w.EndContainer()
		}
		w.EndContainer()
	case ocFabrics:
		w.StartArray(tag)
		for _, f := range o.Fabrics.Fabrics() {
			if ctx.FabricFiltered && f.Index != acc {
				continue
			}
			w.StartStruct(tlv.Anonymous)
			w.PutBytes(tlv.ContextTag(1), f.RootPublicKey)
			w.PutUint(tlv.ContextTag(2), uint64(f.VendorID))
			w.PutUint(tlv.ContextTag(3), f.FabricID)
			w.PutUint(tlv.ContextTag(4), f.NodeID)
			w.PutString(tlv.ContextTag(5), f.Label)
			w.PutUint(tlv.ContextTag(0xFE), uint64(f.Index))
			w.EndContainer()
		}
		w.EndContainer()
	case ocSupportedFabrics:
		w.PutUint(tag, fabric.MaxFabrics)
	case ocCommissionedFabrics:
		w.PutUint(tag, uint64(o.Fabrics.Committed()))
	case ocTrustedRootCertificates:
		w.StartArray(tag)
		for _, f := range o.Fabrics.Fabrics() {
			w.PutBytes(tlv.Anonymous, f.RCAC)
		}
		if o.pendingRoot != nil && !o.addedNOC {
			w.PutBytes(tlv.Anonymous, o.pendingRoot)
		}
		w.EndContainer()
	case ocCurrentFabricIndex:
		w.PutUint(tag, uint64(acc))
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// fields decodes command fields into byte strings and integers by tag.
type fields struct {
	bytes [5][]byte
	uints [5]uint64
	have  uint8
}

func decodeFields(r *tlv.Reader) (*fields, im.Status) {
	f := &fields{}
	err := im.ForEachField(r, func(r *tlv.Reader, tag uint8) (err error) {
		if tag >= 5 {
			return nil
		}
		switch r.Type() {
		case tlv.TypeBytes, tlv.TypeUTF8:
			f.bytes[tag], err = r.Bytes()
			if r.Type() == tlv.TypeUTF8 {
				f.bytes[tag], err = r.UTF8()
			}
		case tlv.TypeUint:
			f.uints[tag], err = r.Uint()
		case tlv.TypeBool:
			var b bool
			b, err = r.Bool()
			if b {
				f.uints[tag] = 1
			}
		default:
			return im.InvalidCommand
		}
		f.have |= 1 << tag
		return err
	})
	if err != nil {
		return nil, im.InvalidCommand
	}
	return f, im.Success
}

func (f *fields) has(tags ...uint8) bool {
	for _, t := range tags {
		if f.have&(1<<t) == 0 {
			return false
		}
	}
	return true
}

func nocResponse(resp *im.Response, code uint8, index uint8) im.Status {
	w := resp.Fields(ocNOCResponse)
	w.PutUint(tlv.ContextTag(0), uint64(code))
	if index != 0 {
		w.PutUint(tlv.ContextTag(1), uint64(index))
	}
	return im.Success
}

func (o *OperationalCredentials) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
	f, st := decodeFields(r)
	if st != im.Success {
		return st
	}
	switch cmd {
	case ocAttestationRequest:
		nonce := f.bytes[0]
		if len(nonce) != 32 {
			return im.InvalidCommand
		}
		elems := credentials.AttestationElements(o.Attestation.CertificationDeclaration, nonce, 0, nil)
		sig, err := credentials.SignWithChallenge(o.Rand, o.Attestation.DACKey, elems, ctx.Session.AttestationChallenge[:])
		if err != nil {
			return im.Failure
		}
		w := resp.Fields(ocAttestationResponse)
		w.PutBytes(tlv.ContextTag(0), elems)
		w.PutBytes(tlv.ContextTag(1), sig)
		return im.Success

	case ocCertificateChainRequest:
		var cert []byte
		switch f.uints[0] {
		case 1:
			cert = o.Attestation.DACCert
		case 2:
			cert = o.Attestation.PAICert
		default:
			return im.InvalidCommand
		}
		resp.Fields(ocCertificateChainResponse).PutBytes(tlv.ContextTag(0), cert)
		return im.Success

	case ocCSRRequest:
		nonce := f.bytes[0]
		if len(nonce) != 32 {
			return im.InvalidCommand
		}
		if !o.FailSafe.Armed(ctx.Now) {
			return im.FailsafeRequired
		}
		if f.uints[1] != 0 { // IsForUpdateNOC: UpdateNOC is not supported yet
			return im.InvalidCommand
		}
		if o.addedNOC {
			return im.ConstraintError
		}
		key, err := p256.GenerateKey(o.Rand)
		if err != nil {
			return im.Failure
		}
		csr, err := credentials.NewCSR(o.Rand, key)
		if err != nil {
			return im.Failure
		}
		elems := credentials.NOCSRElements(csr, nonce)
		sig, err := credentials.SignWithChallenge(o.Rand, o.Attestation.DACKey, elems, ctx.Session.AttestationChallenge[:])
		if err != nil {
			return im.Failure
		}
		o.pendingKey = key
		w := resp.Fields(ocCSRResponse)
		w.PutBytes(tlv.ContextTag(0), elems)
		w.PutBytes(tlv.ContextTag(1), sig)
		return im.Success

	case ocAddTrustedRootCert:
		if !o.FailSafe.Armed(ctx.Now) {
			return im.FailsafeRequired
		}
		if o.pendingRoot != nil || o.addedNOC {
			return im.ConstraintError
		}
		c, err := credentials.DecodeCert(f.bytes[0])
		if err != nil || !c.IsCA || c.VerifySignature(c.PublicKey) != nil {
			return im.InvalidCommand
		}
		if _, ok := c.Subject.Get(credentials.DNMatterRCACID); !ok {
			return im.InvalidCommand
		}
		o.pendingRoot = append([]byte{}, f.bytes[0]...)
		return im.Success

	case ocAddNOC:
		if !f.has(0, 2, 3, 4) {
			return im.InvalidCommand
		}
		if !o.FailSafe.Armed(ctx.Now) {
			return im.FailsafeRequired
		}
		if o.addedNOC {
			return im.ConstraintError
		}
		if o.pendingKey == nil {
			return nocResponse(resp, NOCMissingCsr, 0)
		}
		if o.pendingRoot == nil || len(f.bytes[2]) != 16 {
			return nocResponse(resp, NOCInvalidNOC, 0)
		}
		admin := f.uints[3]
		if !credentials.IsOperationalNodeID(admin) && admin>>32 != 0xFFFFFFFD {
			return nocResponse(resp, NOCInvalidAdminSubject, 0)
		}
		noc := append([]byte{}, f.bytes[0]...)
		var icac []byte
		if f.has(1) && f.bytes[1] != nil {
			icac = append([]byte{}, f.bytes[1]...)
		}
		id, err := credentials.ValidateNOCChain(noc, icac, o.pendingRoot)
		if err != nil {
			return nocResponse(resp, NOCInvalidNOC, 0)
		}
		if string(id.PublicKey) != string(o.pendingKey.PublicKey().Bytes()) {
			return nocResponse(resp, NOCInvalidPublicKey, 0)
		}
		fb, err := o.Fabrics.Add(o.pendingRoot, icac, noc, o.pendingKey, f.bytes[2], uint16(f.uints[4]))
		switch err {
		case nil:
		case fabric.ErrTableFull:
			return nocResponse(resp, NOCTableFull, 0)
		case fabric.ErrConflict:
			return nocResponse(resp, NOCFabricConflict, 0)
		default:
			return nocResponse(resp, NOCInvalidNOC, 0)
		}
		o.addedNOC = true
		o.FailSafe.SetFabricIndex(fb.Index)
		o.ACL.Entries = append(o.ACL.Entries, ACLEntry{
			FabricIndex: fb.Index, Privilege: im.Administer, AuthMode: exchange.AuthCASE, Subjects: []uint64{admin},
		})
		// The PASE session now accesses the new fabric.
		if ctx.Session.AuthMode == exchange.AuthPASE {
			ctx.Session.FabricIndex = fb.Index
		}
		ctx.Node.Changed(ctx.Endpoint, IDOperationalCredentials, ocNOCs)
		ctx.Node.Changed(ctx.Endpoint, IDOperationalCredentials, ocFabrics)
		if o.OnFabricAdded != nil {
			o.OnFabricAdded(ctx.Now, fb)
		}
		return nocResponse(resp, NOCOK, fb.Index)

	case ocUpdateFabricLabel:
		label := string(f.bytes[0])
		if !f.has(0) || len(label) > 32 {
			return im.ConstraintError
		}
		fb := o.Fabrics.Get(accessingFabric(ctx))
		if fb == nil {
			return im.UnsupportedAccess
		}
		for _, other := range o.Fabrics.Fabrics() {
			if other != fb && label != "" && other.Label == label {
				return nocResponse(resp, NOCLabelConflict, 0)
			}
		}
		fb.Label = label
		ctx.Node.Changed(ctx.Endpoint, IDOperationalCredentials, ocFabrics)
		return nocResponse(resp, NOCOK, fb.Index)

	case ocRemoveFabric:
		idx := uint8(f.uints[0])
		if !f.has(0) || o.Fabrics.Remove(idx) != nil {
			return nocResponse(resp, NOCInvalidFabricIndex, 0)
		}
		o.ACL.RemoveFabric(idx)
		ctx.Node.Changed(ctx.Endpoint, IDOperationalCredentials, ocFabrics)
		resp.Fields(ocNOCResponse).PutUint(tlv.ContextTag(0), NOCOK)
		if o.OnFabricRemoved != nil {
			o.OnFabricRemoved(ctx.Now, idx)
		}
		return im.Success
	}
	return im.UnsupportedCommand
}
