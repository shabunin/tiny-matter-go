package casesession

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

// Vector from connectedhomeip TestCASESession.cpp (DestinationIdTest),
// itself from the specification.
func TestDestinationID(t *testing.T) {
	ipk, _ := hex.DecodeString("9bc61cd9c62a2df6d64dfcaa9dc472d4")
	random, _ := hex.DecodeString("7e171231568dfa17206b3accf8faec2f4d21b580113196f47c7c4deb810a73dc")
	root, _ := hex.DecodeString("044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa")
	got := DestinationID(ipk, random, root, 0x2906C908D115D362, 0xCD5544AA7B13EF14)
	if hex.EncodeToString(got[:]) != "dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53" {
		t.Fatalf("got %x", got)
	}
}

type testFabric struct {
	rootKey *p256.PrivateKey
	root    *credentials.Cert
	ipk     []byte
}

func newTestFabric(t *testing.T) *testFabric {
	k, _ := p256.GenerateKey(rand.Reader)
	rc, err := credentials.IssueRoot(k, 1)
	if err != nil {
		t.Fatal(err)
	}
	return &testFabric{rootKey: k, root: rc, ipk: []byte("0123456789abcdef")}
}

// member adds a node of the fabric to a table.
func (tf *testFabric) member(t *testing.T, table *fabric.Table, fabricID, nodeID uint64) *fabric.Fabric {
	key, _ := p256.GenerateKey(rand.Reader)
	nc, err := credentials.IssueNOC(tf.root, tf.rootKey, key.PublicKey().Bytes(), fabricID, nodeID, 0x00010001)
	if err != nil {
		t.Fatal(err)
	}
	f, err := table.Add(tf.root.Encode(), nil, nc.Encode(), key, tf.ipk, 0xFFF1)
	if err != nil {
		t.Fatal(err)
	}
	table.Commit()
	return f
}

type peers struct {
	w              *simnet.World
	dev, ctl       *simnet.Node
	devFab, ctlFab *fabric.Table
	established    []*exchange.Session
	failures       []error
}

func setup(t *testing.T) *peers {
	p := &peers{w: simnet.New(t), devFab: &fabric.Table{}, ctlFab: &fabric.Table{}}
	p.dev, p.ctl = p.w.Node(5540), p.w.Node(5550)
	NewResponder(p.dev.M, securechannel.NewDispatcher(p.dev.M), ResponderConfig{
		Fabrics: p.devFab, Rand: rand.Reader,
		OnEstablished: func(now time.Time, s *exchange.Session, f *fabric.Fabric) {
			p.established = append(p.established, s)
		},
		OnFailed: func(now time.Time, err error) { p.failures = append(p.failures, err) },
	})
	return p
}

type result struct {
	done bool
	s    *exchange.Session
	err  error
}

func (p *peers) connect(t *testing.T, f *fabric.Fabric, peerNode uint64) *result {
	res := &result{}
	err := Connect(p.w.Now, p.ctl.M, p.dev.Addr, InitiatorConfig{
		Fabric: f, PeerNodeID: peerNode, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) { res.done, res.s, res.err = true, s, err },
	})
	if err != nil {
		t.Fatal(err)
	}
	p.w.Advance(time.Second)
	return res
}

func TestCASE(t *testing.T) {
	p := setup(t)
	tf := newTestFabric(t)
	devF := tf.member(t, p.devFab, 0xFAB1, 0x1111)
	ctlF := tf.member(t, p.ctlFab, 0xFAB1, 0x2222)

	res := p.connect(t, ctlF, 0x1111)
	if !res.done || res.err != nil {
		t.Fatalf("connect: done=%v err=%v failures=%v", res.done, res.err, p.failures)
	}
	if len(p.established) != 1 {
		t.Fatalf("device sessions: %d", len(p.established))
	}
	ds, cs := p.established[0], res.s
	if ds.PeerNodeID() != 0x2222 || cs.PeerNodeID() != 0x1111 || ds.FabricIndex != devF.Index ||
		ds.AuthMode != exchange.AuthCASE || len(ds.PeerCATs) != 1 || ds.PeerCATs[0] != 0x00010001 {
		t.Fatalf("device session: peer %x fabric %d auth %d cats %x", ds.PeerNodeID(), ds.FabricIndex, ds.AuthMode, ds.PeerCATs)
	}
	if ds.AttestationChallenge != cs.AttestationChallenge {
		t.Fatal("attestation challenges differ")
	}

	// The session keys agree: an unknown-protocol message is acked rather
	// than failing decryption, so delivery succeeds.
	var errs []error
	ex, _ := p.ctl.M.NewExchange(cs, errDelegate{&errs})
	ex.Send(p.w.Now, 0x7777, 1, []byte("hi"))
	p.w.Advance(10 * time.Second)
	if len(errs) != 0 {
		t.Fatalf("message over CASE session: %v", errs)
	}
}

type errDelegate struct{ errs *[]error }

func (errDelegate) OnMessage(time.Time, *exchange.Exchange, exchange.Message) {}
func (d errDelegate) OnError(now time.Time, ex *exchange.Exchange, err error) {
	*d.errs = append(*d.errs, err)
}

func TestCASEUnknownDestination(t *testing.T) {
	p := setup(t)
	tf := newTestFabric(t)
	tf.member(t, p.devFab, 0xFAB1, 0x1111)
	ctlF := tf.member(t, p.ctlFab, 0xFAB1, 0x2222)

	res := p.connect(t, ctlF, 0x9999) // wrong node
	var se *securechannel.StatusError
	if !res.done || !errors.As(res.err, &se) || se.Report.ProtocolCode != securechannel.CodeNoSharedTrustRoots {
		t.Fatalf("got %v", res.err)
	}
}

func TestCASEForeignRoot(t *testing.T) {
	p := setup(t)
	tf := newTestFabric(t)
	devF := tf.member(t, p.devFab, 0xFAB1, 0x1111)
	// An attacker knows the device's root public key, fabric ID and IPK
	// (enough to address it) but holds a NOC from its own root.
	evilKey, _ := p256.GenerateKey(rand.Reader)
	evilRoot, _ := credentials.IssueRoot(evilKey, 1)
	key, _ := p256.GenerateKey(rand.Reader)
	nc, _ := credentials.IssueNOC(evilRoot, evilKey, key.PublicKey().Bytes(), 0xFAB1, 0x2222)
	f, err := p.ctlFab.Add(evilRoot.Encode(), nil, nc.Encode(), key, tf.ipk, 0xFFF1)
	if err != nil {
		t.Fatal(err)
	}
	// Point the controller's destination computation at the device's root.
	f.RootPublicKey = tf.root.PublicKey
	f.RCAC = tf.root.Encode()
	f.OperationalIPK = devF.OperationalIPK
	res := p.connect(t, f, 0x1111)
	if !res.done || res.err == nil || len(p.established) != 0 {
		t.Fatalf("foreign NOC accepted: err=%v", res.err)
	}
	if len(p.failures) != 1 || !errors.Is(p.failures[0], ErrPeerCert) {
		t.Fatalf("device failures: %v", p.failures)
	}
}

func TestCASERejectsZeroSessionAndNilFabrics(t *testing.T) {
	if _, err := DecodeSigma1((&Sigma1{InitiatorSessionID: 0}).Encode()); err == nil {
		t.Fatal("accepted zero InitiatorSessionID in Sigma1")
	}
	if _, err := DecodeSigma1((&Sigma1{InitiatorSessionID: 1, ResumptionID: make([]byte, ResumptionIDSize)}).Encode()); err == nil {
		t.Fatal("accepted ResumptionID without ResumeMIC")
	}
	if _, err := DecodeSigma2((&Sigma2{ResponderSessionID: 0, Encrypted2: make([]byte, 32)}).Encode()); err == nil {
		t.Fatal("accepted zero ResponderSessionID in Sigma2")
	}
	w := simnet.New(t)
	dev := w.Node(5540)
	NewResponder(dev.M, securechannel.NewDispatcher(dev.M), ResponderConfig{Rand: rand.Reader})
	ctl := w.Node(5550)
	tf := newTestFabric(t)
	ctlFab := &fabric.Table{}
	ctlF := tf.member(t, ctlFab, 0xFAB1, 0x2222)
	var done bool
	var gotErr error
	if err := Connect(w.Now, ctl.M, dev.Addr, InitiatorConfig{
		Fabric: ctlF, PeerNodeID: 0x1111, Rand: rand.Reader,
		Done: func(_ time.Time, _ *exchange.Session, err error) { done, gotErr = true, err },
	}); err != nil {
		t.Fatal(err)
	}
	w.Advance(time.Second)
	if !done || gotErr == nil {
		t.Fatalf("nil Fabrics: done=%v err=%v", done, gotErr)
	}
}

func FuzzDecode(f *testing.F) {
	s1 := Sigma1{SessionParams: &securechannel.DefaultSessionParams, ResumptionID: make([]byte, 16), ResumeMIC: make([]byte, 16)}
	s2 := Sigma2{Encrypted2: make([]byte, 40), SessionParams: &securechannel.DefaultSessionParams}
	f.Add(s1.Encode())
	f.Add(s2.Encode())
	f.Add(EncodeSigma3(make([]byte, 40)))
	f.Add(tbeData(make([]byte, 30), nil, make([]byte, 64), make([]byte, 16)))
	f.Add((&Sigma2Resume{ResponderSessionID: 1, SessionParams: &securechannel.DefaultSessionParams}).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodeSigma2Resume(b)
		DecodeSigma1(b)
		DecodeSigma2(b)
		DecodeSigma3(b)
		decodeTBEData(b)
	})
}
