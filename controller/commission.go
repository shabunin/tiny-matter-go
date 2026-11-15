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
	"github.com/shabunin/tiny-matter-go/thread"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Clusters, attributes and commands used to commission and administer
// nodes.
const (
	clBasicInformation     = 0x0028
	clGeneralCommissioning = 0x0030
	clNetworkCommissioning = 0x0031
	clAdminCommissioning   = 0x003C
	clOperationalCreds     = 0x003E

	attrVendorID        = 0x02 // Basic Information
	attrProductName     = 0x03
	attrProductID       = 0x04
	attrRegulatory      = 0x02 // General Commissioning RegulatoryConfig
	attrLocationCap     = 0x03 // General Commissioning LocationCapability
	attrCurrentFabricIx = 0x05 // Operational Credentials CurrentFabricIndex
	attrConcurrent      = 0x04 // General Commissioning SupportsConcurrentConnection
	attrScanMaxTime     = 0x02 // Network Commissioning ScanMaxTimeSeconds
	attrConnectMaxTime  = 0x03 // Network Commissioning ConnectMaxTimeSeconds
	attrFeatureMap      = 0xFFFC

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
	cmdScanNetworks          = 0x00 // Network Commissioning
	cmdAddOrUpdateWiFi       = 0x02
	cmdAddOrUpdateThread     = 0x03
	cmdConnectNetwork        = 0x06

	featureWiFi   = 0x01 // Network Commissioning WI
	featureThread = 0x02 // Network Commissioning TH

	certTypeDAC, certTypePAI = 1, 2
	locationIndoorOutdoor    = 2

	failSafeSeconds    = 120
	stepTimeout        = 30 * time.Second
	paseAttemptTimeout = 15 * time.Second
	commissionableWait = 10 * time.Second
	operationalWait    = 90 * time.Second // for a device joining a network
)

// CommissionOptions adjust commissioning.
type CommissionOptions struct {
	// NodeID is the node ID to give the device (0: the next free one).
	NodeID uint64
	// Addr, if valid, is where the device is on the IP network: where it
	// is commissioned or, with BLE, reached once it has joined its
	// network. Otherwise it is looked for (see BLE).
	Addr netip.AddrPort
	// Label names the node in the controller's records (default: the
	// device's product name).
	Label string
	// SkipAttestation commissions a device whose attestation fails, after
	// logging why. Only for devices trusted by other means.
	SkipAttestation bool
	// BLE commissions over Bluetooth LE: the device is found by the
	// payload's discriminator in BLE advertisements and reached over BTP
	// until it is on the IP network, where it is then found with mDNS as
	// an operational node.
	//
	// Without BLE or Addr, the device is looked for with mDNS and, unless
	// its QR code says it does not advertise over BLE, over BLE at once. A
	// device on the network is commissioned there, keeping its network; a
	// device found only over BLE is commissioned over BLE if WiFi or
	// Thread gives it a network.
	BLE bool
	// WiFi, if set, is the Wi-Fi network a device commissioned over BLE
	// is told to join (Network Commissioning) before it is reached over
	// CASE. Over the IP network, the device keeps its network.
	WiFi *WiFiNetwork
	// Thread, if set, is the operational dataset of the Thread network to
	// give a device commissioned over BLE instead, in its TLV form (as
	// `ot-ctl dataset active -x` prints it).
	Thread []byte
}

// WiFiNetwork is a Wi-Fi network for a device to join.
type WiFiNetwork struct {
	SSID     []byte
	Password []byte // empty for an open network
}

// Commission commissions the device with onboarding payload p onto the
// controller's fabric, over the IP network or Bluetooth LE (see
// CommissionOptions.BLE).
func (c *Controller) Commission(ctx context.Context, p *onboarding.Payload, opts CommissionOptions) (*Node, error) {
	if opts.WiFi != nil && opts.Thread != nil {
		return nil, errors.New("controller: give a device Wi-Fi or Thread, not both")
	}
	if opts.Thread != nil {
		if _, err := thread.ParseDataset(opts.Thread); err != nil {
			return nil, fmt.Errorf("controller: Thread dataset: %w", err)
		}
	}
	// Over BLE, the device is reached over CASE once it is on the IP
	// network: at Addr, or wherever mDNS finds it.
	findable := opts.Addr.IsValid() || c.disc != nil
	if opts.BLE && !findable {
		return nil, errUnfindable
	}
	id, err := c.reserveNodeID(opts.NodeID)
	if err != nil {
		return nil, err
	}
	defer c.releaseNodeID(id)

	hasNetwork := opts.WiFi != nil || opts.Thread != nil
	ps, link, err := c.reach(ctx, p, opts, func() error {
		if !hasNetwork {
			return errNeedsNetwork
		}
		if !findable {
			return errUnfindable
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if link != nil {
		defer link.close()
	} else if hasNetwork {
		c.logf("commissioning over the IP network: the device keeps its network")
		opts.WiFi, opts.Thread = nil, nil
	}
	return c.commissionWith(ctx, ps, link, id, opts)
}

// commissionWith commissions over a PASE session, which ends with it.
func (c *Controller) commissionWith(ctx context.Context, ps *exchange.Session, link *bleLink, id uint64, opts CommissionOptions) (*Node, error) {
	defer c.do(func(now time.Time) { securechannel.CloseSession(now, c.m, ps) })
	n, err := c.commissionOver(ctx, ps, link, id, opts)
	if err != nil {
		// Let the device roll back now rather than when the fail-safe
		// expires, unless it has left BLE (to join its network).
		if link == nil || !link.gone() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.invokeOn(sctx, ps, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
				w.PutUint(tlv.ContextTag(0), 0)
				w.PutUint(tlv.ContextTag(1), 0)
			})
			cancel()
		}
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

// commissionOver runs the commissioning steps over a PASE session (over a
// BLE link, or the IP network if link is nil), gives the device its
// network if asked, then completes commissioning over CASE.
func (c *Controller) commissionOver(ctx context.Context, ps *exchange.Session, link *bleLink, id uint64, opts CommissionOptions) (*Node, error) {
	step := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, stepTimeout) }

	// What the commissioner needs to know first.
	paths := []im.AttributePath{
		{Cluster: clBasicInformation, Attribute: attrVendorID},
		{Cluster: clBasicInformation, Attribute: attrProductID},
		{Cluster: clBasicInformation, Attribute: attrProductName},
		{Cluster: clGeneralCommissioning, Attribute: attrRegulatory},
		{Cluster: clGeneralCommissioning, Attribute: attrLocationCap},
	}
	if opts.WiFi != nil || opts.Thread != nil {
		paths = append(paths,
			im.AttributePath{Cluster: clGeneralCommissioning, Attribute: attrConcurrent},
			im.AttributePath{AnyEndpoint: true, Cluster: clNetworkCommissioning, Attribute: attrFeatureMap},
			im.AttributePath{AnyEndpoint: true, Cluster: clNetworkCommissioning, Attribute: attrConnectMaxTime})
	}
	sctx, cancel := step()
	rep, err := c.readOn(sctx, ps, im.Request{Attributes: paths})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: reading device information: %w", err)
	}
	vid := uint16(rep.uint(clBasicInformation, attrVendorID, 0))
	pid := uint16(rep.uint(clBasicInformation, attrProductID, 0))
	name := rep.string(clBasicInformation, attrProductName)
	c.logf("device: %q, vendor %#04x, product %#04x", name, vid, pid)
	if f := opts.networkFeature(); f != 0 {
		if _, _, ok := networkEndpoint(rep, f); !ok {
			return nil, noInterface(f)
		}
	}

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

	if opts.networkFeature() != 0 {
		if err := c.joinNetwork(ctx, ps, rep, opts); err != nil {
			return nil, err
		}
	}
	// CommissioningComplete over CASE on the new fabric. The node is
	// found with mDNS, or where PASE found it.
	addr := ps.Peer.String()
	if link != nil {
		link.close() // the device is on its network now
		addr = ""
		if opts.Addr.IsValid() {
			addr = opts.Addr.String()
		} else {
			a, err := c.waitOperational(ctx, id)
			if err != nil {
				return nil, err
			}
			addr = a.String()
		}
	}
	c.mu.Lock()
	c.st.Nodes = append(c.st.Nodes, &Node{ID: id, Label: label(opts.Label, name),
		VendorID: vid, ProductID: pid, Addr: addr, Added: time.Now().UTC().Truncate(time.Second)})
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

// networkFeature is the Network Commissioning feature the network to give
// the device needs, or 0.
func (o *CommissionOptions) networkFeature() uint64 {
	switch {
	case o.WiFi != nil:
		return featureWiFi
	case o.Thread != nil:
		return featureThread
	}
	return 0
}

func noInterface(feature uint64) error {
	if feature == featureThread {
		return errors.New("controller: the device has no Thread interface (Network Commissioning with the Thread feature)")
	}
	return errors.New("controller: the device has no Wi-Fi interface (Network Commissioning with the Wi-Fi feature)")
}

var networkingStatuses = [...]string{"Success", "OutOfRange", "BoundsExceeded", "NetworkIDNotFound",
	"DuplicateNetworkID", "NetworkNotFound", "RegulatoryError", "AuthFailure", "UnsupportedSecurity",
	"OtherConnectionFailure", "IPV6Failed", "IPBindFailed", "UnknownError"}

// networkError turns a Network Commissioning response (NetworkingStatus in
// field 0, DebugText in field 1) into an error.
func networkError(cmd string, res im.InvokeResult, err error) error {
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
	if code < uint64(len(networkingStatuses)) {
		name = networkingStatuses[code]
	}
	text, _ := stringField(res.Fields, 1)
	return fmt.Errorf("controller: %s: %s %s", cmd, name, text)
}

// networkEndpoint finds, in a report, the device's Network Commissioning
// cluster with a feature (Wi-Fi or Thread), and its
// ConnectMaxTimeSeconds.
func networkEndpoint(rep *Report, feature uint64) (ep uint16, connectMax uint64, ok bool) {
	for _, a := range rep.Attributes {
		if a.Status != im.Success || a.Path.Cluster != clNetworkCommissioning || a.Path.Attribute != attrFeatureMap {
			continue
		}
		r := tlv.NewReader(a.Data)
		if r.Next() != nil {
			continue
		}
		if fm, err := r.Uint(); err == nil && fm&feature != 0 {
			ep, ok = a.Path.Endpoint, true
			break
		}
	}
	connectMax = 30
	for _, a := range rep.Attributes {
		if ok && a.Status == im.Success && a.Path.Endpoint == ep && a.Path.Cluster == clNetworkCommissioning &&
			a.Path.Attribute == attrConnectMaxTime {
			r := tlv.NewReader(a.Data)
			if r.Next() == nil {
				if v, err := r.Uint(); err == nil && v > 0 {
					connectMax = v
				}
			}
		}
	}
	return ep, connectMax, ok
}

// joinNetwork gives the device its network, Wi-Fi or Thread, and has it
// connect.
func (c *Controller) joinNetwork(ctx context.Context, ps *exchange.Session, rep *Report, opts CommissionOptions) error {
	feature := opts.networkFeature()
	ep, connectMax, ok := networkEndpoint(rep, feature)
	if !ok {
		return noInterface(feature)
	}
	concurrent := rep.uint(clGeneralCommissioning, attrConcurrent, 1) != 0
	nc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: ep, Cluster: clNetworkCommissioning, Command: cmd}
	}
	var (
		networkID []byte
		name      string
		res       im.InvokeResult
		err       error
	)
	sctx, cancel := context.WithTimeout(ctx, stepTimeout)
	if feature == featureThread {
		ds, _ := thread.ParseDataset(opts.Thread) // checked by Commission
		networkID = ds.ExtendedPANID[:]
		name = fmt.Sprintf("Thread network %q (extended PAN ID %X)", ds.NetworkName, networkID)
		res, err = c.invokeOn(sctx, ps, nc(cmdAddOrUpdateThread), 0, func(w *tlv.Writer) {
			w.PutBytes(tlv.ContextTag(0), opts.Thread)
			w.PutUint(tlv.ContextTag(1), 2) // breadcrumb
		})
		err = networkError("AddOrUpdateThreadNetwork", res, err)
	} else {
		networkID = opts.WiFi.SSID
		name = fmt.Sprintf("Wi-Fi network %q", networkID)
		res, err = c.invokeOn(sctx, ps, nc(cmdAddOrUpdateWiFi), 0, func(w *tlv.Writer) {
			w.PutBytes(tlv.ContextTag(0), opts.WiFi.SSID)
			w.PutBytes(tlv.ContextTag(1), opts.WiFi.Password)
			w.PutUint(tlv.ContextTag(2), 2) // breadcrumb
		})
		err = networkError("AddOrUpdateWiFiNetwork", res, err)
	}
	cancel()
	if err != nil {
		return err
	}
	// Time to join, then to be found and complete over CASE.
	sctx, cancel = context.WithTimeout(ctx, stepTimeout)
	res, err = c.invokeOn(sctx, ps, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), max(failSafeSeconds, connectMax+uint64(operationalWait/time.Second)))
		w.PutUint(tlv.ContextTag(1), 3)
	})
	cancel()
	if err := commissioningError("ArmFailSafe", res, err); err != nil {
		return err
	}
	c.logf("asking the device to join %s", name)
	wait := time.Duration(connectMax)*time.Second + 15*time.Second
	if !concurrent {
		wait = 15 * time.Second // it may leave BLE before it answers
	}
	sctx, cancel = context.WithTimeout(ctx, wait)
	res, err = c.invokeOn(sctx, ps, nc(cmdConnectNetwork), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), networkID)
		w.PutUint(tlv.ContextTag(1), 4)
	})
	cancel()
	if err != nil && !concurrent && ctx.Err() == nil {
		c.logf("no ConnectNetwork response (%v): the device has left BLE to join the network", err)
		return nil
	}
	return networkError("ConnectNetwork", res, err)
}

// waitOperational finds a node with mDNS, waiting for it to join its
// network.
func (c *Controller) waitOperational(ctx context.Context, id uint64) (netip.AddrPort, error) {
	if c.disc == nil {
		return netip.AddrPort{}, errors.New("controller: discovery is off: give the device's address")
	}
	c.logf("waiting for node %d on the IP network", id)
	wctx, cancel := context.WithTimeout(ctx, operationalWait)
	defer cancel()
	for {
		in, err := c.disc.operational(wctx, c.fab.CompressedFabricID, id)
		if err == nil {
			if addrs := instanceAddrs(in); len(addrs) > 0 {
				c.logf("node %d is at %s", id, addrs[0])
				return addrs[0], nil
			}
		}
		if wctx.Err() != nil {
			return netip.AddrPort{}, fmt.Errorf("controller: node %d did not appear on the network within %v", id, operationalWait)
		}
		select { // a failed query: try again shortly
		case <-time.After(time.Second):
		case <-wctx.Done():
		}
	}
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
