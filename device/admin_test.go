package device_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// invokeTimed sends a TimedRequest and then the command on one exchange.
func (h *harness) invokeTimed(s *exchange.Session, p im.CommandPath, fields func(w *tlv.Writer)) im.InvokeResult {
	h.t.Helper()
	var got []byte
	step := 0
	ex, err := h.ctl.M.NewExchange(s, delegate(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
		if step == 0 {
			step = 1
			if st, err := im.DecodeStatusResponse(msg.Payload); err != nil || st != im.Success {
				h.t.Fatalf("TimedRequest: %v %v", st, err)
			}
			ex.Send(now, message.ProtocolInteractionModel, im.OpInvokeRequest, im.EncodeInvokeRequest(p, true, fields))
			return
		}
		got = bytes.Clone(msg.Payload)
		ex.Close(now)
	}))
	if err != nil {
		h.t.Fatal(err)
	}
	ex.Send(h.w.Now, message.ProtocolInteractionModel, im.OpTimedRequest, im.EncodeTimedRequest(1000))
	h.w.Advance(time.Second)
	res, err := im.DecodeInvokeResponse(got)
	if err != nil || len(res) != 1 {
		h.t.Fatalf("invoke %+v: %v %v", p, res, err)
	}
	return res[0]
}

func ac(cmd uint32) im.CommandPath {
	return im.CommandPath{Endpoint: 0, Cluster: clusters.IDAdminCommissioning, Command: cmd}
}

func basicWindow(timeout uint64) func(w *tlv.Writer) {
	return func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), timeout) }
}

func enhancedWindow(code uint32, salt []byte, iterations uint32, disc uint16) func(w *tlv.Writer) {
	v, err := spake2p.NewVerifier(code, salt, int(iterations))
	if err != nil { // invalid on purpose: send it with any valid verifier
		v, _ = spake2p.NewVerifier(code, []byte("a valid salt 16B"), 1000)
	}
	return func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), 180)
		w.PutBytes(tlv.ContextTag(1), v.Bytes())
		w.PutUint(tlv.ContextTag(2), uint64(disc))
		w.PutUint(tlv.ContextTag(3), uint64(iterations))
		w.PutBytes(tlv.ContextTag(4), salt)
	}
}

func wantClusterStatus(t *testing.T, what string, res im.InvokeResult, code clusters.AdminStatus) {
	t.Helper()
	if res.Status != im.Failure || !res.HasClusterStatus || res.ClusterStatus != uint8(code) {
		t.Fatalf("%s: %+v, want cluster status %d", what, res, code)
	}
}

func TestMultiAdmin(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()
	a := h.dev.Admin
	if a.WindowStatus != clusters.WindowNotOpen || h.dev.PASE.WindowOpen() {
		t.Fatal("window open after commissioning")
	}

	// The commands need a timed interaction and valid parameters.
	if res := h.invoke(caseS, ac(1), basicWindow(180)); res.Status != im.NeedsTimedInteraction {
		t.Fatalf("untimed: %+v", res)
	}
	if res := h.invokeTimed(caseS, ac(1), basicWindow(60)); res.Status != im.InvalidCommand {
		t.Fatalf("short timeout: %+v", res)
	}
	wantClusterStatus(t, "short salt", h.invokeTimed(caseS, ac(0), enhancedWindow(1234, []byte("short"), 1000, 7)), clusters.AdminPAKEParameterError)
	wantClusterStatus(t, "revoke while closed", h.invokeTimed(caseS, ac(2), nil), clusters.AdminWindowNotOpen)

	// Enhanced window: a second controller joins with its own passcode.
	const code2 = 12345678
	if res := h.invokeTimed(caseS, ac(0), enhancedWindow(code2, []byte("multi-admin salt"), 1000, 0x123)); res.Status != im.Success {
		t.Fatalf("OpenCommissioningWindow: %+v", res)
	}
	if a.WindowStatus != clusters.WindowEnhancedOpen || a.AdminFabricIndex != 1 || a.AdminVendorID != 0xFFF1 {
		t.Fatalf("attributes: %+v", a)
	}
	wantClusterStatus(t, "second open", h.invokeTimed(caseS, ac(1), basicWindow(180)), clusters.AdminBusy)
	h.emptyICAC = true
	_, case2 := h.commissionWith(code2, 2)
	if a.WindowStatus != clusters.WindowNotOpen || a.AdminFabricIndex != 0 {
		t.Fatalf("window not closed by commissioning: %+v", a)
	}
	// Both administrators operate the light.
	for _, s := range []*exchange.Session{caseS, case2} {
		if res := h.invoke(s, im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 2}, nil); res.Status != im.Success {
			t.Fatalf("toggle: %+v", res)
		}
	}

	// Basic window: revoked, then left to time out.
	if res := h.invokeTimed(case2, ac(1), basicWindow(180)); res.Status != im.Success {
		t.Fatalf("OpenBasicCommissioningWindow: %+v", res)
	}
	if a.WindowStatus != clusters.WindowBasicOpen || a.AdminFabricIndex != 2 || !h.dev.PASE.WindowOpen() {
		t.Fatalf("basic window: %+v", a)
	}
	if res := h.invokeTimed(caseS, ac(2), nil); res.Status != im.Success {
		t.Fatalf("RevokeCommissioning: %+v", res)
	}
	if h.dev.PASE.WindowOpen() || a.WindowStatus != clusters.WindowNotOpen {
		t.Fatal("revoke left the window open")
	}
	if res := h.invokeTimed(caseS, ac(1), basicWindow(180)); res.Status != im.Success {
		t.Fatalf("reopen: %+v", res)
	}
	h.w.Advance(178 * time.Second) // invokeTimed advanced 1 s
	if !h.dev.PASE.WindowOpen() {
		t.Fatal("window closed early")
	}
	h.w.Advance(2 * time.Second)
	if h.dev.PASE.WindowOpen() || a.WindowStatus != clusters.WindowNotOpen {
		t.Fatal("window did not time out")
	}

	// Removing the fabric that opened the window nulls AdminFabricIndex but
	// keeps AdminVendorId (TestCommissioningWindow); closing nulls both.
	if res := h.invokeTimed(case2, ac(1), basicWindow(180)); res.Status != im.Success {
		t.Fatalf("OpenBasicCommissioningWindow: %+v", res)
	}
	h.invoke(caseS, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: 0x0A},
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 2) })
	h.w.Advance(time.Second)
	if !h.attr(caseS, 0, clusters.IDAdminCommissioning, 1).IsNull() {
		t.Fatal("AdminFabricIndex not null after its fabric was removed")
	}
	if v, err := h.attr(caseS, 0, clusters.IDAdminCommissioning, 2).Uint(); err != nil || v != 0xFFF1 {
		t.Fatalf("AdminVendorId after its fabric was removed: %d, %v", v, err)
	}
	if res := h.invokeTimed(caseS, ac(2), nil); res.Status != im.Success {
		t.Fatalf("RevokeCommissioning: %+v", res)
	}
	if !h.attr(caseS, 0, clusters.IDAdminCommissioning, 2).IsNull() {
		t.Fatal("AdminVendorId not null with the window closed")
	}
}

func TestRevokeCommissioningAfterAddNOC(t *testing.T) {
	h := newHarness(t)
	_, admin1 := h.commission()

	res := h.invokeTimed(admin1, ac(1), basicWindow(180))
	if res.Status != im.Success {
		t.Fatalf("OpenBasicCommissioningWindow: %+v", res)
	}

	paseS, err := h.pairPASE(passcode)
	if err != nil {
		t.Fatal(err)
	}
	h.addPendingFabric(paseS, 0xFAB2, 2)
	if len(h.dev.Fabrics.Fabrics()) != 2 || h.dev.Fabrics.Committed() != 1 {
		t.Fatalf("before revoke: fabrics=%d committed=%d", len(h.dev.Fabrics.Fabrics()), h.dev.Fabrics.Committed())
	}

	res = h.invokeTimed(admin1, ac(2), nil)
	if res.Status != im.Success {
		t.Fatalf("RevokeCommissioning: %+v", res)
	}
	h.w.Advance(time.Second)

	if len(h.dev.Fabrics.Fabrics()) != 1 || len(h.dev.ACL.Entries) != 1 {
		t.Fatalf("after revoke: fabrics=%d acl=%d", len(h.dev.Fabrics.Fabrics()), len(h.dev.ACL.Entries))
	}
	if h.dev.FailSafe.Armed(h.w.Now) {
		t.Fatal("fail-safe still armed after RevokeCommissioning")
	}
	if h.dev.PASE.WindowOpen() {
		t.Fatal("commissioning window still open after RevokeCommissioning")
	}
	for _, s := range h.dev.M.Sessions() {
		if s.AuthMode == exchange.AuthPASE && !s.Closed() {
			t.Fatal("PASE session survived RevokeCommissioning")
		}
	}
}
