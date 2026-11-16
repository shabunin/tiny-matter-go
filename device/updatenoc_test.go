package device_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func ocPath(cmd uint32) im.CommandPath {
	return im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: cmd}
}

func gcPath(cmd uint32) im.CommandPath {
	return im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: cmd}
}

// tryConnect opens a CASE session to the device as node, or returns the
// error.
func (h *harness) tryConnect(ctlF *fabric.Fabric, node uint64) (*exchange.Session, error) {
	var caseS *exchange.Session
	var cerr error
	err := casesession.Connect(h.w.Now, h.ctl.M, h.devN.Addr, casesession.InitiatorConfig{
		Fabric: ctlF, PeerNodeID: node, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) { caseS, cerr = s, err },
	})
	if err != nil {
		return nil, err
	}
	h.w.Advance(5 * time.Second)
	return caseS, cerr
}

// updateNOC arms the fail-safe on s and gives the device a new NOC as
// node, returning the NOCResponse status.
func (h *harness) updateNOC(s *exchange.Session, node uint64) uint64 {
	t := h.t
	t.Helper()
	res := h.invoke(s, gcPath(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 60); w.PutUint(tlv.ContextTag(1), 2) })
	if code, _ := field(t, res.Fields, 0).Uint(); code != 0 {
		t.Fatalf("ArmFailSafe: %d", code)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	res = h.invoke(s, ocPath(4), func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), nonce)
		w.PutBool(tlv.ContextTag(1), true)
	})
	if res.Status != im.Success {
		t.Fatalf("CSRRequest for UpdateNOC: %#x", res.Status)
	}
	nocsr, _ := field(t, res.Fields, 0).Bytes()
	csrDER, _ := field(t, nocsr, 1).Bytes()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := csr.PublicKey.(*ecdsa.PublicKey).ECDH()

	// AddNOC does not take a CSR made for UpdateNOC.
	res = h.invoke(s, ocPath(6), func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), []byte{1})
		w.PutBytes(tlv.ContextTag(2), make([]byte, 16))
		w.PutUint(tlv.ContextTag(3), 0x1B669)
		w.PutUint(tlv.ContextTag(4), 0xFFF1)
	})
	if res.Status != im.ConstraintError {
		t.Fatalf("AddNOC after an UpdateNOC CSR: %#x", res.Status)
	}

	noc, err := credentials.IssueNOC(h.root, h.rootKey, pub.Bytes(), 0xFAB, node)
	if err != nil {
		t.Fatal(err)
	}
	res = h.invoke(s, ocPath(7), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), noc.Encode()) })
	if res.Status != im.Success {
		t.Fatalf("UpdateNOC: %#x", res.Status)
	}
	code, _ := field(t, res.Fields, 0).Uint()
	return code
}

func (h *harness) secureSessions() int {
	n := 0
	for _, s := range h.dev.M.Sessions() {
		if s.IsSecure() && !s.Closed() {
			n++
		}
	}
	return n
}

func TestUpdateNOC(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	ctlF, s := h.commission()
	h.connect(ctlF)
	if n := h.secureSessions(); n != 2 {
		t.Fatalf("%d sessions before UpdateNOC", n)
	}

	if code := h.updateNOC(s, 0x2); code != clusters.NOCOK {
		t.Fatalf("UpdateNOC status %d", code)
	}
	// Only one NOC command per fail-safe.
	res := h.invoke(s, ocPath(7), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), []byte{1}) })
	if res.Status != im.ConstraintError {
		t.Fatalf("second UpdateNOC: %#x", res.Status)
	}
	h.w.Advance(time.Second)
	if f := h.dev.Fabrics.Get(1); f.NodeID != 2 || !f.Updating() {
		t.Fatalf("fabric node %#x after UpdateNOC", f.NodeID)
	}
	if n := h.secureSessions(); n != 1 {
		t.Fatalf("%d sessions on the fabric after UpdateNOC, want the one carrying it", n)
	}

	// A restart now keeps the committed identity.
	if h2 := newHarnessStore(t, store); h2.dev.Fabrics.Get(1).NodeID != 1 {
		t.Fatal("uncommitted NOC was saved")
	}

	// The device answers as node 2 only, and commits over that session.
	if _, err := h.tryConnect(ctlF, 1); err == nil {
		t.Fatal("CASE as the old node ID succeeded")
	}
	s2, err := h.tryConnect(ctlF, 2)
	if err != nil {
		t.Fatalf("CASE as the new node ID: %v", err)
	}
	res = h.invoke(s2, gcPath(4), nil)
	if code, _ := field(t, res.Fields, 0).Uint(); code != 0 {
		t.Fatalf("CommissioningComplete: %d", code)
	}
	h.w.Advance(2 * time.Minute)
	if f := h.dev.Fabrics.Get(1); f.NodeID != 2 || f.Updating() {
		t.Fatal("update not committed")
	}
	if h3 := newHarnessStore(t, store); h3.dev.Fabrics.Get(1).NodeID != 2 {
		t.Fatal("committed NOC not saved")
	}
}

func TestUpdateNOCRollback(t *testing.T) {
	h := newHarness(t)
	ctlF, s := h.commission()
	if code := h.updateNOC(s, 0x3); code != clusters.NOCOK {
		t.Fatalf("UpdateNOC status %d", code)
	}
	h.w.Advance(90 * time.Second) // the fail-safe expires
	if f := h.dev.Fabrics.Get(1); f.NodeID != 1 || f.Updating() {
		t.Fatalf("fabric node %#x after rollback", f.NodeID)
	}
	if n := h.secureSessions(); n != 0 {
		t.Fatalf("%d sessions on the fabric survived the rollback", n)
	}
	if _, err := h.tryConnect(ctlF, 1); err != nil {
		t.Fatalf("CASE as the old node ID after rollback: %v", err)
	}
}

func TestUpdateNOCOverPASE(t *testing.T) {
	h := newHarness(t)
	h.afterArm = func(s *exchange.Session) {
		nonce := make([]byte, 32)
		res := h.invoke(s, ocPath(4), func(w *tlv.Writer) {
			w.PutBytes(tlv.ContextTag(0), nonce)
			w.PutBool(tlv.ContextTag(1), true)
		})
		if res.Status != im.InvalidCommand {
			t.Fatalf("CSRRequest for UpdateNOC over PASE: %#x", res.Status)
		}
	}
	h.commission()
}
