package device_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/securechannel/pase"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const passcode = 20202021

var salt = []byte("SPAKE2P Key Salt")

type harness struct {
	t     *testing.T
	w     *simnet.World
	dev   *device.Device
	devN  *simnet.Node
	ctl   *simnet.Node
	light *clusters.OnOff
	// emptyICAC sends AddNOC with an empty ICAC field, as matter.js does.
	emptyICAC bool
	// afterArm, if set, runs on the PASE session after ArmFailSafe.
	afterArm func(s *exchange.Session)
	// The fabric's root, set by commission.
	root    *credentials.Cert
	rootKey *p256.PrivateKey
}

func newHarness(t *testing.T) *harness { return newHarnessStore(t, nil) }

func newHarnessStore(t *testing.T, store storage.Store) *harness {
	return newHarnessWith(t, store, false)
}

func newHarnessWith(t *testing.T, store storage.Store, wifi bool) *harness {
	return newHarnessConfig(t, store, wifi, nil)
}

// newHarnessConfig creates the device after edit adjusts its config.
func newHarnessConfig(t *testing.T, store storage.Store, wifi bool, edit func(cfg *device.Config)) *harness {
	h := &harness{t: t, w: simnet.New(t)}
	h.ctl = h.w.Node(5550)
	h.devN = h.w.ExternalNode(5540)
	v, _ := spake2p.NewVerifier(passcode, salt, 1000)
	dacKey, _ := p256.NewPrivateKey(devcreds.DACPrivateKey)
	cfg := device.Config{
		Transport: h.devN.Transport(), Rand: rand.Reader,
		Verifier: v, Salt: salt, Iterations: 1000, Discriminator: 3840,
		Attestation: &clusters.Attestation{DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration},
		Basic: &clusters.BasicInformation{VendorName: "T", VendorID: 0xFFF1, ProductName: "P", ProductID: 0x8000},
		Store: store, WiFi: wifi,
	}
	if edit != nil {
		edit(&cfg)
	}
	var err error
	h.dev, err = device.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.devN.Attach(h.dev.HandlePacket, h.dev.Poll)
	h.light = &clusters.OnOff{}
	ep := h.dev.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	h.dev.Node.AddCluster(ep, clusters.Descriptor{}, h.light)
	if !h.dev.Commissioned() {
		h.dev.OpenCommissioningWindow()
	}
	return h
}

// invoke sends one command on s and returns the response fields (raw TLV)
// or status.
func (h *harness) invoke(s *exchange.Session, p im.CommandPath, fields func(w *tlv.Writer)) im.InvokeResult {
	h.t.Helper()
	var got []byte
	ex, err := h.ctl.M.NewExchange(s, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
		got = bytes.Clone(msg.Payload)
		ex.Close(now)
	}))
	if err != nil {
		h.t.Fatal(err)
	}
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpInvokeRequest, im.EncodeInvokeRequest(p, false, fields))
	h.w.Advance(time.Second)
	res, err := im.DecodeInvokeResponse(got)
	if err != nil || len(res) != 1 {
		h.t.Fatalf("invoke %+v: %v %v", p, res, err)
	}
	return res[0]
}

type delegate func(now time.Time, ex *exchange.Exchange, msg exchange.Message)

func (d delegate) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	d(now, ex, msg)
}
func (delegate) OnError(time.Time, *exchange.Exchange, error) {}

// field returns the byte-string or integer field tag of a response.
func field(t *testing.T, raw []byte, tag uint8) *tlv.Reader {
	r := tlv.NewReader(raw)
	r.Next()
	r.EnterContainer()
	for r.Next() == nil {
		if r.Tag().IsContext(tag) {
			return r
		}
	}
	t.Fatalf("field %d missing in %x", tag, raw)
	return nil
}

func TestCommissioning(t *testing.T) { newHarness(t).commission() }

// commission runs a full commissioning and returns the controller's fabric
// and its CASE session.
func (h *harness) commission() (*fabric.Fabric, *exchange.Session) {
	return h.commissionWith(passcode, 1)
}

// commissionWith commissions with code, expecting wantFabrics afterwards.
func (h *harness) commissionWith(code uint32, wantFabrics int) (*fabric.Fabric, *exchange.Session) {
	t := h.t

	// PASE.
	var paseS *exchange.Session
	err := pase.Pair(h.w.Now, h.ctl.M, h.devN.Addr, pase.InitiatorConfig{Passcode: code, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) {
			if err != nil {
				t.Fatal(err)
			}
			paseS = s
		}})
	if err != nil {
		t.Fatal(err)
	}
	h.w.Advance(time.Second)
	if paseS == nil {
		t.Fatal("PASE did not complete")
	}

	gc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: cmd}
	}
	oc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: cmd}
	}

	res := h.invoke(paseS, gc(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 60); w.PutUint(tlv.ContextTag(1), 1) })
	if code, _ := field(t, res.Fields, 0).Uint(); code != 0 {
		t.Fatalf("ArmFailSafe: %d", code)
	}
	if h.afterArm != nil {
		h.afterArm(paseS)
	}

	// Attestation: the signature covers elements || challenge.
	nonce := make([]byte, 32)
	rand.Read(nonce)
	res = h.invoke(paseS, oc(0), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) })
	elems, _ := field(t, res.Fields, 0).Bytes()
	sig, _ := field(t, res.Fields, 1).Bytes()
	dacPub, _ := p256.NewPublicKey(devcreds.DACPublicKey)
	if !dacPub.VerifyMessage(append(bytes.Clone(elems), paseS.AttestationChallenge[:]...), sig) {
		t.Fatal("attestation signature invalid")
	}

	// CSR.
	res = h.invoke(paseS, oc(4), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) })
	nocsr, _ := field(t, res.Fields, 0).Bytes()
	csrDER, _ := field(t, nocsr, 1).Bytes()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR: %v", err)
	}
	ecdhPub, _ := csr.PublicKey.(*ecdsa.PublicKey).ECDH()
	nodePub := ecdhPub.Bytes()

	// Controller fabric: root, the device's NOC, and the controller's own.
	rootKey, _ := p256.GenerateKey(rand.Reader)
	root, _ := credentials.IssueRoot(rootKey, 1)
	h.root, h.rootKey = root, rootKey
	devNOC, _ := credentials.IssueNOC(root, rootKey, nodePub, 0xFAB, 0x1)
	ctlKey, _ := p256.GenerateKey(rand.Reader)
	ctlNOC, _ := credentials.IssueNOC(root, rootKey, ctlKey.PublicKey().Bytes(), 0xFAB, 0x1B669)
	ipk := []byte("temporary ipk 01")

	res = h.invoke(paseS, oc(0x0B), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), root.Encode()) })
	if res.Status != im.Success {
		t.Fatalf("AddTrustedRootCertificate: %#x", res.Status)
	}
	res = h.invoke(paseS, oc(6), func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), devNOC.Encode())
		if h.emptyICAC {
			w.PutBytes(tlv.ContextTag(1), []byte{})
		}
		w.PutBytes(tlv.ContextTag(2), ipk)
		w.PutUint(tlv.ContextTag(3), 0x1B669)
		w.PutUint(tlv.ContextTag(4), 0xFFF1)
	})
	if code, _ := field(t, res.Fields, 0).Uint(); code != 0 {
		t.Fatalf("AddNOC status %d", code)
	}

	// CASE with the new fabric.
	ctlTable := &fabric.Table{}
	ctlF, err := ctlTable.Add(root.Encode(), nil, ctlNOC.Encode(), ctlKey, ipk, 0xFFF1)
	if err != nil {
		t.Fatal(err)
	}
	var caseS *exchange.Session
	err = casesession.Connect(h.w.Now, h.ctl.M, h.devN.Addr, casesession.InitiatorConfig{
		Fabric: ctlF, PeerNodeID: 1, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) {
			if err != nil {
				t.Fatal(err)
			}
			caseS = s
		}})
	if err != nil {
		t.Fatal(err)
	}
	h.w.Advance(time.Second)
	if caseS == nil {
		t.Fatal("CASE did not complete")
	}

	// CommissioningComplete over PASE is refused, over CASE accepted.
	res = h.invoke(paseS, gc(4), nil)
	if code, _ := field(t, res.Fields, 0).Uint(); code != uint64(clusters.InvalidAuthentication) {
		t.Fatalf("CommissioningComplete over PASE: %d", code)
	}
	res = h.invoke(caseS, gc(4), nil)
	if code, _ := field(t, res.Fields, 0).Uint(); code != 0 {
		t.Fatalf("CommissioningComplete: %d", code)
	}
	h.w.Advance(time.Second)
	if h.dev.PASE.WindowOpen() {
		t.Fatal("commissioning window still open")
	}
	for _, s := range h.dev.M.Sessions() {
		if s.AuthMode == exchange.AuthPASE {
			t.Fatal("device kept its PASE session")
		}
	}
	if h.dev.Fabrics.Committed() != wantFabrics {
		t.Fatal("fabric not committed")
	}

	// Operate the light over CASE; the fail-safe no longer rolls back.
	was := h.light.On
	res = h.invoke(caseS, im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 2}, nil)
	if res.Status != im.Success || h.light.On == was {
		t.Fatalf("toggle: %+v", res)
	}
	h.w.Advance(2 * time.Minute)
	if h.dev.Fabrics.Committed() != wantFabrics {
		t.Fatal("fabric lost after the fail-safe period")
	}
	return ctlF, caseS
}

// connect opens a CASE session to the device with the controller fabric.
func (h *harness) connect(ctlF *fabric.Fabric) *exchange.Session {
	var caseS *exchange.Session
	err := casesession.Connect(h.w.Now, h.ctl.M, h.devN.Addr, casesession.InitiatorConfig{
		Fabric: ctlF, PeerNodeID: 1, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) {
			if err != nil {
				h.t.Fatal(err)
			}
			caseS = s
		}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.w.Advance(time.Second)
	if caseS == nil {
		h.t.Fatal("CASE did not complete")
	}
	return caseS
}

func TestRestartKeepsFabric(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	ctlF, caseS := h.commission()
	// Label the fabric, then "reboot" into a new device on the same store.
	h.invoke(caseS, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: 9},
		func(w *tlv.Writer) { w.PutString(tlv.ContextTag(0), "home") })
	h.w.Advance(time.Second)

	h2 := newHarnessStore(t, store)
	if !h2.dev.Commissioned() || h2.dev.PASE.WindowOpen() {
		t.Fatal("restarted device is not commissioned")
	}
	f := h2.dev.Fabrics.Fabrics()[0]
	if f.Label != "home" || f.NodeID != 1 || len(h2.dev.ACL.Entries) != 1 {
		t.Fatalf("restored fabric %+v, %d ACL entries", f, len(h2.dev.ACL.Entries))
	}
	s := h2.connect(ctlF)
	res := h2.invoke(s, im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 1}, nil)
	if res.Status != im.Success || !h2.light.On {
		t.Fatalf("on after restart: %+v", res)
	}

	// Removing the last fabric is saved and reopens commissioning.
	res = h2.invoke(s, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: 0x0A},
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), uint64(f.Index)) })
	h2.w.Advance(time.Second)
	if h2.dev.Commissioned() || !h2.dev.PASE.WindowOpen() {
		t.Fatal("window not reopened after removing the last fabric")
	}
	h3 := newHarnessStore(t, store)
	if h3.dev.Commissioned() {
		t.Fatal("removed fabric came back after restart")
	}
}

func TestCorruptStateIgnored(t *testing.T) {
	store := &storage.Memory{}
	store.Save([]byte{0x15, 0x24, 0x01, 0x07, 0x18}) // version 7
	h := newHarnessStore(t, store)
	if h.dev.Commissioned() || !h.dev.PASE.WindowOpen() {
		t.Fatal("bad state not ignored")
	}
}

func TestFailSafeRollback(t *testing.T) {
	h := newHarness(t)
	var paseS *exchange.Session
	pase.Pair(h.w.Now, h.ctl.M, h.devN.Addr, pase.InitiatorConfig{Passcode: passcode, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) { paseS = s }})
	h.w.Advance(time.Second)
	gc := im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: 0}
	h.invoke(paseS, gc, func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 5); w.PutUint(tlv.ContextTag(1), 1) })
	oc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: cmd}
	}
	nonce := make([]byte, 32)
	res := h.invoke(paseS, oc(4), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) })
	nocsr, _ := field(t, res.Fields, 0).Bytes()
	csrDER, _ := field(t, nocsr, 1).Bytes()
	csr, _ := x509.ParseCertificateRequest(csrDER)
	ecdhPub, _ := csr.PublicKey.(*ecdsa.PublicKey).ECDH()
	rootKey, _ := p256.GenerateKey(rand.Reader)
	root, _ := credentials.IssueRoot(rootKey, 1)
	devNOC, _ := credentials.IssueNOC(root, rootKey, ecdhPub.Bytes(), 0xFAB, 0x1)
	h.invoke(paseS, oc(0x0B), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), root.Encode()) })
	h.invoke(paseS, oc(6), func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), devNOC.Encode())
		w.PutBytes(tlv.ContextTag(2), make([]byte, 16))
		w.PutUint(tlv.ContextTag(3), 0x1B669)
		w.PutUint(tlv.ContextTag(4), 0xFFF1)
	})
	if len(h.dev.Fabrics.Fabrics()) != 1 || len(h.dev.ACL.Entries) != 1 {
		t.Fatal("pending fabric not added")
	}
	h.w.Advance(10 * time.Second)
	if len(h.dev.Fabrics.Fabrics()) != 0 || len(h.dev.ACL.Entries) != 0 {
		t.Fatal("fail-safe expiry did not roll back")
	}
}

// subscriber acknowledges reports and counts them.
type subscriber struct{ reports, subResp int }

func (c *subscriber) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	switch msg.Opcode {
	case im.OpReportData:
		c.reports++
		ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(im.Success))
	case im.OpSubscribeResp:
		c.subResp++
		ex.Close(now)
	}
}
func (c *subscriber) OnError(time.Time, *exchange.Exchange, error) {}

func TestSubscriptionOverCASE(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()
	c := &subscriber{}
	h.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c })
	ex, _ := h.ctl.M.NewExchange(caseS, c)
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpSubscribeRequest, im.EncodeSubscribeRequest(
		[]im.AttributePath{{Endpoint: 1, Cluster: clusters.IDOnOff, Attribute: 0}}, 0, 60, false, true))
	h.w.Advance(time.Second)
	if c.subResp != 1 || c.reports != 1 || h.dev.Server.Subscriptions() != 1 {
		t.Fatalf("subscribe: %+v", c)
	}
	h.invoke(caseS, im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 2}, nil)
	h.w.Advance(time.Second)
	if c.reports != 2 {
		t.Fatalf("toggle not reported: %+v", c)
	}
}

// A CloseSession from the controller closes the session on the device and
// ends its subscriptions.
func TestCloseSessionFromPeer(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()
	c := &subscriber{}
	h.ctl.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return c })
	ex, _ := h.ctl.M.NewExchange(caseS, c)
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpSubscribeRequest, im.EncodeSubscribeRequest(
		[]im.AttributePath{{Endpoint: 1, Cluster: clusters.IDOnOff, Attribute: 0}}, 0, 60, false, true))
	h.w.Advance(time.Second)
	if h.dev.Server.Subscriptions() != 1 {
		t.Fatal("not subscribed")
	}
	before := liveSecure(h.dev.M)
	if err := securechannel.CloseSession(h.w.Now, h.ctl.M, caseS); err != nil {
		t.Fatal(err)
	}
	h.w.Advance(time.Second)
	h.dev.Poll(h.w.Now) // device loops poll after each packet; simnet polls before
	if got := liveSecure(h.dev.M); got != before-1 {
		t.Errorf("device secure sessions: %d, want %d", got, before-1)
	}
	if h.dev.Server.Subscriptions() != 0 {
		t.Errorf("subscription survived its session")
	}
}

func liveSecure(m *exchange.Manager) (n int) {
	for _, s := range m.Sessions() {
		if s.IsSecure() && !s.Closed() {
			n++
		}
	}
	return n
}

func (h *harness) pairPASE(code uint32) (*exchange.Session, error) {
	var (
		done bool
		s    *exchange.Session
		perr error
	)
	err := pase.Pair(h.w.Now, h.ctl.M, h.devN.Addr, pase.InitiatorConfig{
		Passcode: code, Rand: rand.Reader,
		Done: func(now time.Time, got *exchange.Session, e error) {
			done, s, perr = true, got, e
		},
	})
	if err != nil {
		return nil, err
	}
	h.w.Advance(2 * time.Second)
	if !done {
		h.t.Fatal("PASE did not finish")
	}
	return s, perr
}

func (h *harness) addPendingFabric(paseS *exchange.Session, fabricID, nodeID uint64) {
	h.t.Helper()
	gc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: cmd}
	}
	oc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: cmd}
	}
	res := h.invoke(paseS, gc(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 60); w.PutUint(tlv.ContextTag(1), 1) })
	if code, _ := field(h.t, res.Fields, 0).Uint(); code != 0 {
		h.t.Fatalf("ArmFailSafe: %d", code)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	res = h.invoke(paseS, oc(4), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) })
	nocsr, _ := field(h.t, res.Fields, 0).Bytes()
	csrDER, _ := field(h.t, nocsr, 1).Bytes()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		h.t.Fatalf("CSR: %v", err)
	}
	ecdhPub, _ := csr.PublicKey.(*ecdsa.PublicKey).ECDH()
	rootKey, _ := p256.GenerateKey(rand.Reader)
	root, _ := credentials.IssueRoot(rootKey, 1)
	devNOC, _ := credentials.IssueNOC(root, rootKey, ecdhPub.Bytes(), fabricID, nodeID)
	ipk := []byte("temporary ipk 01")
	if res := h.invoke(paseS, oc(0x0B), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), root.Encode()) }); res.Status != im.Success {
		h.t.Fatalf("AddTrustedRootCertificate: %#x", res.Status)
	}
	res = h.invoke(paseS, oc(6), func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), devNOC.Encode())
		w.PutBytes(tlv.ContextTag(2), ipk)
		w.PutUint(tlv.ContextTag(3), 0x1B669)
		w.PutUint(tlv.ContextTag(4), 0xFFF1)
	})
	if code, _ := field(h.t, res.Fields, 0).Uint(); code != 0 {
		h.t.Fatalf("AddNOC: %d", code)
	}
}

func TestACLEmptyListIsWildcard(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()

	var got []byte
	ex, err := h.ctl.M.NewExchange(caseS, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
		got = bytes.Clone(msg.Payload)
		ex.Close(now)
	}))
	if err != nil {
		t.Fatal(err)
	}
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpWriteRequest, im.EncodeWriteRequest(
		im.AttributePath{Endpoint: 0, Cluster: clusters.IDAccessControl, Attribute: 0}, false,
		func(w *tlv.Writer, tag tlv.Tag) {
			w.StartArray(tag)
			// Entry 0: keep CASE admin access to AccessControl on EP0 only.
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), uint64(im.Administer))
			w.PutUint(tlv.ContextTag(2), uint64(exchange.AuthCASE))
			w.StartArray(tlv.ContextTag(3))
			w.PutUint(tlv.Anonymous, 0x1B669)
			w.EndContainer()
			w.StartArray(tlv.ContextTag(4))
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(0), clusters.IDAccessControl)
			w.PutUint(tlv.ContextTag(1), 0)
			w.EndContainer()
			w.EndContainer()
			w.EndContainer()
			// Entry 1: an empty Subjects array matches any subject, like null.
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), uint64(im.View))
			w.PutUint(tlv.ContextTag(2), uint64(exchange.AuthCASE))
			w.StartArray(tlv.ContextTag(3))
			w.EndContainer()
			w.PutNull(tlv.ContextTag(4))
			w.EndContainer()
			// Entry 2: an empty Targets array matches every target, like null.
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), uint64(im.View))
			w.PutUint(tlv.ContextTag(2), uint64(exchange.AuthCASE))
			w.StartArray(tlv.ContextTag(3))
			w.PutUint(tlv.Anonymous, 0x1B669)
			w.EndContainer()
			w.StartArray(tlv.ContextTag(4))
			w.EndContainer()
			w.EndContainer()
			w.EndContainer()
		}))
	h.w.Advance(time.Second)
	res, err := im.DecodeWriteResponse(got)
	if err != nil || len(res) != 1 || res[0].Status != im.Success {
		t.Fatalf("ACL write: %+v %v", res, err)
	}

	rds := h.readQ(caseS, im.Request{Attributes: []im.AttributePath{{Endpoint: 1, Cluster: clusters.IDOnOff, Attribute: 0}}})
	if len(rds) != 1 || len(rds[0].Reports) != 1 || rds[0].Reports[0].Status != im.Success {
		t.Fatalf("OnOff read with empty ACL lists: %+v", rds)
	}
}

func TestCrossFabricFailSafeRejected(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()
	res := h.invokeTimed(caseS, ac(1), basicWindow(180))
	if res.Status != im.Success {
		t.Fatalf("OpenBasicCommissioningWindow: %+v", res)
	}

	paseS, err := h.pairPASE(passcode)
	if err != nil {
		t.Fatal(err)
	}
	gc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: cmd}
	}
	oc := func(cmd uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: cmd}
	}

	// PASE arms fail-safe; CASE must not be allowed to use it.
	if res := h.invoke(paseS, gc(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 60); w.PutUint(tlv.ContextTag(1), 1) }); res.Status != im.Success {
		t.Fatalf("ArmFailSafe over PASE: %#x", res.Status)
	}
	nonce := make([]byte, 32)
	if res := h.invoke(caseS, oc(4), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) }); res.Status != im.FailsafeRequired {
		t.Fatalf("CSRRequest over CASE during PASE fail-safe: got %#x, want %#x", res.Status, im.FailsafeRequired)
	}

	// Disarm (which ends the PASE session), then CASE arms fail-safe; a new
	// PASE session must not be allowed to use it.
	h.invoke(paseS, gc(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 0); w.PutUint(tlv.ContextTag(1), 1) })
	if paseS, err = h.pairPASE(passcode); err != nil {
		t.Fatal(err)
	}
	if res := h.invoke(caseS, gc(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 60); w.PutUint(tlv.ContextTag(1), 1) }); res.Status != im.Success {
		t.Fatalf("ArmFailSafe over CASE: %#x", res.Status)
	}
	if res := h.invoke(paseS, oc(4), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) }); res.Status != im.FailsafeRequired {
		t.Fatalf("CSRRequest over PASE during CASE fail-safe: got %#x, want %#x", res.Status, im.FailsafeRequired)
	}
}

// livePASE counts the device's open PASE sessions.
func (h *harness) livePASE() int {
	n := 0
	for _, s := range h.dev.M.Sessions() {
		if s.AuthMode == exchange.AuthPASE && !s.Closed() {
			n++
		}
	}
	return n
}

func TestFailSafeExpiryClosesPASE(t *testing.T) {
	armFailSafe := func(seconds uint64) func(w *tlv.Writer) {
		return func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), seconds); w.PutUint(tlv.ContextTag(1), 1) }
	}
	arm := im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: 0}

	t.Run("after AddNOC", func(t *testing.T) {
		h := newHarness(t)
		paseS, err := h.pairPASE(passcode)
		if err != nil {
			t.Fatal(err)
		}
		h.addPendingFabric(paseS, 0xFAB, 1)
		h.w.Advance(61 * time.Second)
		if len(h.dev.Fabrics.Fabrics()) != 0 || len(h.dev.ACL.Entries) != 0 {
			t.Fatalf("pending fabric/ACL survived rollback: fabrics=%d acl=%d", len(h.dev.Fabrics.Fabrics()), len(h.dev.ACL.Entries))
		}
		if n := h.livePASE(); n != 0 {
			t.Fatalf("%d PASE sessions survived the fail-safe expiry", n)
		}
		// The window is still open: a commissioner starts over with PASE.
		paseS, err = h.pairPASE(passcode)
		if err != nil {
			t.Fatalf("PASE after rollback: %v", err)
		}
		if code, _ := field(t, h.invoke(paseS, arm, armFailSafe(60)).Fields, 0).Uint(); code != 0 {
			t.Fatalf("ArmFailSafe after rollback: %d", code)
		}
	})

	t.Run("before AddNOC", func(t *testing.T) {
		h := newHarness(t)
		paseS, err := h.pairPASE(passcode)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := field(t, h.invoke(paseS, arm, armFailSafe(60)).Fields, 0).Uint(); code != 0 {
			t.Fatalf("ArmFailSafe: %d", code)
		}
		h.w.Advance(61 * time.Second)
		if n := h.livePASE(); n != 0 {
			t.Fatalf("%d PASE sessions survived the fail-safe expiry", n)
		}
		if b := h.dev.General.Breadcrumb; b != 0 {
			t.Fatalf("Breadcrumb %d after the fail-safe expired, want 0", b)
		}
	})

	t.Run("ArmFailSafe(0)", func(t *testing.T) {
		h := newHarness(t)
		paseS, err := h.pairPASE(passcode)
		if err != nil {
			t.Fatal(err)
		}
		h.invoke(paseS, arm, armFailSafe(60))
		// The response still arrives; the session goes after it.
		if code, _ := field(t, h.invoke(paseS, arm, armFailSafe(0)).Fields, 0).Uint(); code != 0 {
			t.Fatalf("ArmFailSafe(0): %d", code)
		}
		h.w.Advance(time.Second)
		if n := h.livePASE(); n != 0 {
			t.Fatalf("%d PASE sessions survived ArmFailSafe(0)", n)
		}
		if b := h.dev.General.Breadcrumb; b != 0 {
			t.Fatalf("Breadcrumb %d after ArmFailSafe(0), want 0", b)
		}
	})
}

func TestPASEFailedAttemptsClosesDeviceWindow(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < pase.MaxFailedAttempts; i++ {
		if _, err := h.pairPASE(12345679); err == nil {
			t.Fatalf("attempt %d succeeded unexpectedly", i)
		}
	}
	if h.dev.PASE.WindowOpen() {
		t.Fatal("PASE window still open after MaxFailedAttempts")
	}
	if h.dev.Admin.WindowStatus != clusters.WindowNotOpen {
		t.Fatalf("Admin.WindowStatus = %d, want WindowNotOpen", h.dev.Admin.WindowStatus)
	}
}

func TestWriteACLReplaceAndAppendOverCASE(t *testing.T) {
	writeACL := func(t *testing.T, h *harness, caseS *exchange.Session, chunked bool) {
		t.Helper()
		entry := func(w *tlv.Writer, tag tlv.Tag, priv uint64, subj uint64) {
			w.StartStruct(tag)
			w.PutUint(tlv.ContextTag(1), priv)
			w.PutUint(tlv.ContextTag(2), uint64(exchange.AuthCASE))
			w.StartArray(tlv.ContextTag(3))
			w.PutUint(tlv.Anonymous, subj)
			w.EndContainer()
			w.PutNull(tlv.ContextTag(4))
			w.EndContainer()
		}
		putPath := func(w *tlv.Writer, appendItem bool) {
			w.StartList(tlv.ContextTag(1))
			w.PutUint(tlv.ContextTag(2), 0)
			w.PutUint(tlv.ContextTag(3), clusters.IDAccessControl)
			w.PutUint(tlv.ContextTag(4), 0)
			if appendItem {
				w.PutNull(tlv.ContextTag(5))
			}
			w.EndContainer()
		}
		encodeBatch := func(more, replace bool, appends []struct{ priv, subj uint64 }) []byte {
			w := tlv.NewWriter(nil)
			w.StartStruct(tlv.Anonymous)
			w.PutBool(tlv.ContextTag(0), false)
			w.PutBool(tlv.ContextTag(1), false)
			w.StartArray(tlv.ContextTag(2))
			if replace {
				w.StartStruct(tlv.Anonymous)
				putPath(w, false)
				w.StartArray(tlv.ContextTag(2))
				w.EndContainer()
				w.EndContainer()
			}
			for _, a := range appends {
				w.StartStruct(tlv.Anonymous)
				putPath(w, true)
				entry(w, tlv.ContextTag(2), a.priv, a.subj)
				w.EndContainer()
			}
			w.EndContainer()
			w.PutBool(tlv.ContextTag(3), more)
			w.EndContainer()
			return w.Bytes()
		}

		var resps [][]byte
		ex, err := h.ctl.M.NewExchange(caseS, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
			resps = append(resps, bytes.Clone(msg.Payload))
			if !chunked || len(resps) == 2 {
				ex.Close(now)
			}
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !chunked {
			ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpWriteRequest,
				encodeBatch(false, true, []struct{ priv, subj uint64 }{
					{uint64(im.Administer), 0x1B669},
					{uint64(im.View), 0x2B669},
				}))
			h.w.Advance(time.Second)
		} else {
			ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpWriteRequest,
				encodeBatch(true, true, nil))
			h.w.Advance(time.Second)
			ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpWriteRequest,
				encodeBatch(false, false, []struct{ priv, subj uint64 }{
					{uint64(im.Administer), 0x1B669},
					{uint64(im.View), 0x2B669},
				}))
			h.w.Advance(time.Second)
		}
		if len(resps) == 0 {
			t.Fatal("no WriteResponse received")
		}
		for i, raw := range resps {
			statuses, err := im.DecodeWriteResponse(raw)
			if err != nil {
				t.Fatalf("resp %d decode: %v", i, err)
			}
			for j, st := range statuses {
				if st.Status != im.Success {
					t.Fatalf("resp %d item %d: status=%#x, want Success", i, j, st.Status)
				}
			}
		}
		if len(h.dev.ACL.Entries) != 2 {
			t.Fatalf("ACL entries = %d, want 2", len(h.dev.ACL.Entries))
		}
	}

	t.Run("single-request", func(t *testing.T) {
		h := newHarness(t)
		_, caseS := h.commission()
		writeACL(t, h, caseS, false)
	})
	t.Run("chunked-request", func(t *testing.T) {
		h := newHarness(t)
		_, caseS := h.commission()
		writeACL(t, h, caseS, true)
	})
}
