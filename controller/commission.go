package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/credentials/attestation"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/onboarding"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/securechannel/pase"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Clusters, attributes and commands used to commission and administer
// nodes.
const (
	clBasicInformation     = 0x0028
	clGeneralCommissioning = 0x0030
	clAdminCommissioning   = 0x003C
	clOperationalCreds     = 0x003E

	attrVendorID        = 0x02 // Basic Information
	attrProductName     = 0x03
	attrProductID       = 0x04
	attrRegulatory      = 0x02 // General Commissioning RegulatoryConfig
	attrLocationCap     = 0x03 // General Commissioning LocationCapability
	attrCurrentFabricIx = 0x05 // Operational Credentials CurrentFabricIndex

	cmdArmFailSafe           = 0x00 // General Commissioning
	cmdSetRegulatoryConfig   = 0x02
	cmdCommissioningComplete = 0x04
	cmdAttestationRequest    = 0x00 // Operational Credentials
	cmdCertificateChain      = 0x02
	cmdCSRRequest            = 0x04
	cmdAddNOC                = 0x06
	cmdRemoveFabric          = 0x0A
	cmdAddTrustedRoot        = 0x0B
	cmdOpenWindow            = 0x00 // Administrator Commissioning
	cmdRevokeCommissioning   = 0x02

	certTypeDAC, certTypePAI = 1, 2
	locationIndoorOutdoor    = 2

	failSafeSeconds    = 120
	stepTimeout        = 30 * time.Second
	paseAttemptTimeout = 15 * time.Second
	commissionableWait = 10 * time.Second
)

// CommissionOptions adjust commissioning.
type CommissionOptions struct {
	// NodeID is the node ID to give the device (0: the next free one).
	NodeID uint64
	// Addr, if valid, is where the device is; otherwise it is found with
	// mDNS by the payload's discriminator.
	Addr netip.AddrPort
	// Label names the node in the controller's records (default: the
	// device's product name).
	Label string
	// SkipAttestation commissions a device whose attestation fails, after
	// logging why. Only for devices trusted by other means.
	SkipAttestation bool
}

// Commission commissions the device with onboarding payload p onto the
// controller's fabric. The device must be on the IP network already.
func (c *Controller) Commission(ctx context.Context, p *onboarding.Payload, opts CommissionOptions) (*Node, error) {
	id := opts.NodeID
	c.mu.Lock()
	if id == 0 {
		id = c.st.nextNodeID()
		c.st.NextNodeID++ // reserved; saved once the node is commissioned
	} else if c.st.node(id) != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("controller: node %d exists", id)
	}
	c.mu.Unlock()

	addrs := []netip.AddrPort{opts.Addr}
	if !opts.Addr.IsValid() {
		if c.disc == nil {
			return nil, errors.New("controller: no address given and discovery disabled")
		}
		dctx, cancel := context.WithTimeout(ctx, commissionableWait)
		found, err := c.disc.commissionable(dctx, p)
		cancel()
		if len(found) == 0 {
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				err = errors.New("none answered")
			}
			disc := fmt.Sprint("discriminator ", p.Discriminator)
			if p.ShortOnly {
				disc = fmt.Sprint("short discriminator ", p.ShortDiscriminator())
			}
			return nil, fmt.Errorf("controller: looking for a device in commissioning mode with %s: %w", disc, err)
		}
		addrs = addrs[:0]
		for _, f := range found {
			c.logf("found %s: discriminator %d, vendor %#04x, product %#04x, at %v",
				f.Name, f.Discriminator, f.VendorID, f.ProductID, f.Addrs)
			addrs = append(addrs, instanceAddrs(f.Instance)...)
		}
	}

	var ps *exchange.Session
	var err error
	for _, a := range addrs {
		c.logf("PASE with %v", a)
		actx, cancel := context.WithTimeout(ctx, paseAttemptTimeout)
		ps, err = c.pase(actx, a, p.Passcode)
		cancel()
		if err == nil || ctx.Err() != nil {
			break
		}
		c.logf("PASE with %v: %v", a, err)
	}
	if err != nil {
		return nil, fmt.Errorf("controller: PASE: %w", err)
	}
	defer c.do(func(now time.Time) { securechannel.CloseSession(now, c.m, ps) })

	n, err := c.commissionOver(ctx, ps, id, opts)
	if err != nil {
		// Let the device roll back now rather than when the fail-safe
		// expires.
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c.invokeOn(sctx, ps, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), 0)
			w.PutUint(tlv.ContextTag(1), 0)
		})
		cancel()
		return nil, err
	}
	return n, nil
}

// pase establishes a PASE session.
func (c *Controller) pase(ctx context.Context, addr netip.AddrPort, passcode uint32) (*exchange.Session, error) {
	type result struct {
		s   *exchange.Session
		err error
	}
	res := make(chan result, 1)
	err := c.do(func(now time.Time) {
		err := pase.Pair(now, c.m, addr, pase.InitiatorConfig{Passcode: passcode, Rand: rand.Reader,
			Done: func(now time.Time, s *exchange.Session, err error) { res <- result{s, err} }})
		if err != nil {
			res <- result{nil, err}
		}
	})
	if err != nil {
		return nil, err
	}
	select {
	case r := <-res:
		return r.s, r.err
	case <-ctx.Done():
		// A session established after all is closed when it arrives.
		go func() {
			select {
			case r := <-res:
				if r.s != nil {
					c.do(func(now time.Time) { c.m.CloseSession(now, r.s) })
				}
			case <-c.done:
			}
		}()
		return nil, ctx.Err()
	}
}

func gcCmd(cmd uint32) im.CommandPath {
	return im.CommandPath{Endpoint: 0, Cluster: clGeneralCommissioning, Command: cmd}
}

func ocCmd(cmd uint32) im.CommandPath {
	return im.CommandPath{Endpoint: 0, Cluster: clOperationalCreds, Command: cmd}
}

// commissionOver runs the commissioning steps over a PASE session, then
// completes commissioning over CASE.
func (c *Controller) commissionOver(ctx context.Context, ps *exchange.Session, id uint64, opts CommissionOptions) (*Node, error) {
	step := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, stepTimeout) }

	// What the commissioner needs to know first.
	sctx, cancel := step()
	rep, err := c.readOn(sctx, ps, im.Request{Attributes: []im.AttributePath{
		{Cluster: clBasicInformation, Attribute: attrVendorID},
		{Cluster: clBasicInformation, Attribute: attrProductID},
		{Cluster: clBasicInformation, Attribute: attrProductName},
		{Cluster: clGeneralCommissioning, Attribute: attrRegulatory},
		{Cluster: clGeneralCommissioning, Attribute: attrLocationCap},
	}})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: reading device information: %w", err)
	}
	vid := uint16(rep.uint(clBasicInformation, attrVendorID, 0))
	pid := uint16(rep.uint(clBasicInformation, attrProductID, 0))
	name := rep.string(clBasicInformation, attrProductName)
	c.logf("device: %q, vendor %#04x, product %#04x", name, vid, pid)

	sctx, cancel = step()
	res, err := c.invokeOn(sctx, ps, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), failSafeSeconds)
		w.PutUint(tlv.ContextTag(1), 1) // breadcrumb
	})
	cancel()
	if err = commissioningError("ArmFailSafe", res, err); err != nil {
		return nil, err
	}

	// Keep the device's regulatory location where it may choose.
	location := rep.uint(clGeneralCommissioning, attrLocationCap, locationIndoorOutdoor)
	if location == locationIndoorOutdoor {
		location = rep.uint(clGeneralCommissioning, attrRegulatory, locationIndoorOutdoor)
	}
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, ps, gcCmd(cmdSetRegulatoryConfig), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), location)
		w.PutString(tlv.ContextTag(1), "XX")
		w.PutUint(tlv.ContextTag(2), 2)
	})
	cancel()
	if err = commissioningError("SetRegulatoryConfig", res, err); err != nil {
		return nil, err
	}

	// Device attestation.
	certs := map[uint64][]byte{}
	for _, typ := range []uint64{certTypeDAC, certTypePAI} {
		sctx, cancel = step()
		res, err := c.invokeOn(sctx, ps, ocCmd(cmdCertificateChain), 0, func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), typ)
		})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("controller: CertificateChainRequest: %w", err)
		}
		if certs[typ], err = bytesField(res.Fields, 0); err != nil {
			return nil, fmt.Errorf("controller: CertificateChainResponse: %w", err)
		}
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, ps, ocCmd(cmdAttestationRequest), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), nonce)
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: AttestationRequest: %w", err)
	}
	elements, err1 := bytesField(res.Fields, 0)
	signature, err2 := bytesField(res.Fields, 1)
	if err1 != nil || err2 != nil {
		return nil, errors.New("controller: malformed AttestationResponse")
	}
	v := attestation.Verifier{PAAs: c.opts.PAAs, AllowTestCD: c.opts.AllowTestCD}
	att, err := v.Verify(&attestation.Info{
		DAC: certs[certTypeDAC], PAI: certs[certTypePAI],
		Elements: elements, Signature: signature, Nonce: nonce,
		Challenge: ps.AttestationChallenge[:], VendorID: vid, ProductID: pid,
	})
	switch {
	case err == nil:
		dev := ""
		if att.DevelopmentCredentials {
			dev = " (development credentials)"
		}
		c.logf("attestation verified: DAC %q, certificate %s%s", att.DAC.Subject.CommonName, att.CD.CertificateID, dev)
	case opts.SkipAttestation:
		c.logf("attestation FAILED, continuing as asked: %v", err)
	default:
		return nil, err
	}

	// The device's operational key, and its NOC.
	csrNonce := make([]byte, 32)
	rand.Read(csrNonce)
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, ps, ocCmd(cmdCSRRequest), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), csrNonce)
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: CSRRequest: %w", err)
	}
	nocsr, err1 := bytesField(res.Fields, 0)
	signature, err2 = bytesField(res.Fields, 1)
	if err1 != nil || err2 != nil {
		return nil, errors.New("controller: malformed CSRResponse")
	}
	pub, err := attestation.VerifyNOCSR(certs[certTypeDAC], nocsr, signature, ps.AttestationChallenge[:], csrNonce)
	if err != nil {
		return nil, err
	}
	noc, err := credentials.IssueNOC(c.root, c.rootKey, pub, c.fab.FabricID, id)
	if err != nil {
		return nil, err
	}

	sctx, cancel = step()
	_, err = c.invokeOn(sctx, ps, ocCmd(cmdAddTrustedRoot), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), c.fab.RCAC)
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: AddTrustedRootCertificate: %w", err)
	}
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, ps, ocCmd(cmdAddNOC), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), noc.Encode())
		w.PutBytes(tlv.ContextTag(2), c.fab.IPK[:])
		w.PutUint(tlv.ContextTag(3), catSubject(c.st.AdminCAT)) // CaseAdminSubject
		w.PutUint(tlv.ContextTag(4), uint64(c.fab.VendorID))
	})
	cancel()
	if err == nil {
		err = nocError(res.Fields)
	}
	if err != nil {
		return nil, fmt.Errorf("controller: AddNOC: %w", err)
	}
	c.logf("device joined fabric %016X as node %d", c.fab.FabricID, id)

	// CommissioningComplete over CASE on the new fabric. The node is
	// found with mDNS, or where PASE found it.
	c.mu.Lock()
	c.st.Nodes = append(c.st.Nodes, &Node{ID: id, Label: label(opts.Label, name),
		VendorID: vid, ProductID: pid, Addr: ps.Peer.String(), Added: time.Now().UTC().Truncate(time.Second)})
	c.mu.Unlock()
	err = c.withSession(ctx, id, func(s *exchange.Session) error {
		sctx, cancel := step()
		defer cancel()
		res, err := c.invokeOn(sctx, s, gcCmd(cmdCommissioningComplete), 0, nil)
		return commissioningError("CommissioningComplete", res, err)
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.removeNodeLocked(id)
		c.st.save(c.opts.Dir)
		return nil, err
	}
	if err := c.st.save(c.opts.Dir); err != nil {
		return nil, err
	}
	c.logf("node %d commissioned", id)
	out := *c.st.node(id)
	return &out, nil
}

func label(given, product string) string {
	if given != "" {
		return given
	}
	return product
}

// removeNodeLocked drops a node from the records (c.mu held).
func (c *Controller) removeNodeLocked(id uint64) bool {
	for i, n := range c.st.Nodes {
		if n.ID == id {
			c.st.Nodes = append(c.st.Nodes[:i], c.st.Nodes[i+1:]...)
			return true
		}
	}
	return false
}

// uint returns an unsigned attribute value from a report, or def.
func (rep *Report) uint(cluster, attr uint32, def uint64) uint64 {
	for _, a := range rep.Attributes {
		if a.Status == im.Success && a.Path.Cluster == cluster && a.Path.Attribute == attr {
			r := tlv.NewReader(a.Data)
			if r.Next() == nil {
				if v, err := r.Uint(); err == nil {
					return v
				}
			}
		}
	}
	return def
}

// string returns a string attribute value from a report.
func (rep *Report) string(cluster, attr uint32) string {
	for _, a := range rep.Attributes {
		if a.Status == im.Success && a.Path.Cluster == cluster && a.Path.Attribute == attr {
			r := tlv.NewReader(a.Data)
			if r.Next() == nil {
				if v, err := r.String(); err == nil {
					return v
				}
			}
		}
	}
	return ""
}

var commissioningErrors = [...]string{"OK", "ValueOutsideRange", "InvalidAuthentication", "NoFailSafe", "BusyWithOtherAdmin"}

// commissioningError turns a General Commissioning response (ErrorCode
// in field 0, DebugText in field 1) into an error.
func commissioningError(cmd string, res im.InvokeResult, err error) error {
	if err != nil {
		return fmt.Errorf("controller: %s: %w", cmd, err)
	}
	code, err := uintField(res.Fields, 0)
	if err != nil {
		return fmt.Errorf("controller: %s: malformed response", cmd)
	}
	if code == 0 {
		return nil
	}
	name := fmt.Sprint(code)
	if code < uint64(len(commissioningErrors)) {
		name = commissioningErrors[code]
	}
	text, _ := stringField(res.Fields, 1)
	return fmt.Errorf("controller: %s: %s %s", cmd, name, text)
}

var nocStatuses = map[uint64]string{
	1: "InvalidPublicKey", 2: "InvalidNodeOpId", 3: "InvalidNOC", 4: "MissingCsr",
	5: "TableFull", 6: "InvalidAdminSubject", 9: "FabricConflict", 10: "LabelConflict",
	11: "InvalidFabricIndex",
}

// nocError checks an NOCResponse (StatusCode in field 0, DebugText in 2).
func nocError(fields []byte) error {
	code, err := uintField(fields, 0)
	if err != nil {
		return errors.New("malformed NOCResponse")
	}
	if code == 0 {
		return nil
	}
	name, ok := nocStatuses[code]
	if !ok {
		name = fmt.Sprint(code)
	}
	text, _ := stringField(fields, 2)
	return fmt.Errorf("status %s %s", name, text)
}

// field positions a reader on a context-tagged field of a command's
// response fields.
func field(fields []byte, tag uint8) (*tlv.Reader, error) {
	r := tlv.NewReader(fields)
	if err := r.Next(); err != nil || r.Type() != tlv.TypeStruct {
		return nil, errors.New("no response fields")
	}
	if err := r.EnterContainer(); err != nil {
		return nil, err
	}
	for r.Next() == nil {
		if r.Tag().IsContext(tag) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("field %d missing", tag)
}

func bytesField(fields []byte, tag uint8) ([]byte, error) {
	r, err := field(fields, tag)
	if err != nil {
		return nil, err
	}
	return r.Bytes()
}

func uintField(fields []byte, tag uint8) (uint64, error) {
	r, err := field(fields, tag)
	if err != nil {
		return 0, err
	}
	return r.Uint()
}

func stringField(fields []byte, tag uint8) (string, error) {
	r, err := field(fields, tag)
	if err != nil {
		return "", err
	}
	return r.String()
}
