package casesession

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

type resumePeers struct {
	*peers
	devStore, ctlStore *ResumptionStore
}

func setupResume(t *testing.T) *resumePeers {
	p := &resumePeers{peers: &peers{w: simnet.New(t), devFab: &fabric.Table{}, ctlFab: &fabric.Table{}},
		devStore: &ResumptionStore{}, ctlStore: &ResumptionStore{}}
	p.dev, p.ctl = p.w.Node(5540), p.w.Node(5550)
	NewResponder(p.dev.M, securechannel.NewDispatcher(p.dev.M), ResponderConfig{
		Fabrics: p.devFab, Rand: rand.Reader, Resumptions: p.devStore,
		OnEstablished: func(now time.Time, s *exchange.Session, f *fabric.Fabric) {
			p.established = append(p.established, s)
		},
		OnFailed: func(now time.Time, err error) { p.failures = append(p.failures, err) },
	})
	return p
}

func (p *resumePeers) connect(t *testing.T, f *fabric.Fabric, peerNode uint64) *exchange.Session {
	t.Helper()
	var res result
	err := Connect(p.w.Now, p.ctl.M, p.dev.Addr, InitiatorConfig{
		Fabric: f, PeerNodeID: peerNode, Rand: rand.Reader, Resumptions: p.ctlStore,
		Done: func(now time.Time, s *exchange.Session, err error) { res.done, res.s, res.err = true, s, err },
	})
	if err != nil {
		t.Fatal(err)
	}
	p.w.Advance(time.Second)
	if !res.done || res.err != nil {
		t.Fatalf("connect: done=%v err=%v failures=%v", res.done, res.err, p.failures)
	}
	ds := p.established[len(p.established)-1]
	if ds.PeerNodeID() != f.NodeID || res.s.PeerNodeID() != peerNode || len(ds.PeerCATs) != 1 ||
		ds.AttestationChallenge != res.s.AttestationChallenge {
		t.Fatalf("sessions disagree: device peer %x cats %x", ds.PeerNodeID(), ds.PeerCATs)
	}
	var errs []error
	ex, _ := p.ctl.M.NewExchange(res.s, errDelegate{&errs})
	ex.Send(p.w.Now, 0x7777, 1, []byte("hi"))
	p.w.Advance(10 * time.Second)
	if len(errs) != 0 {
		t.Fatalf("message over the session: %v", errs)
	}
	return res.s
}

// sameRecord checks that both sides hold one record with the same ID and
// secret, and returns the ID.
func (p *resumePeers) sameRecord(t *testing.T) [ResumptionIDSize]byte {
	t.Helper()
	if p.devStore.Len() != 1 || p.ctlStore.Len() != 1 {
		t.Fatalf("records: device %d, controller %d", p.devStore.Len(), p.ctlStore.Len())
	}
	d, c := p.devStore.records[0], p.ctlStore.records[0]
	if d.ID != c.ID || !bytes.Equal(d.Secret, c.Secret) {
		t.Fatal("the two records differ")
	}
	return d.ID
}

func TestCASEResumption(t *testing.T) {
	p := setupResume(t)
	tf := newTestFabric(t)
	devF := tf.member(t, p.devFab, 0xFAB1, 0x1111)
	ctlF := tf.member(t, p.ctlFab, 0xFAB1, 0x2222)

	p.connect(t, ctlF, 0x1111)
	first := p.sameRecord(t)
	if d, c := p.devStore.records[0], p.ctlStore.records[0]; d.PeerNodeID != 0x2222 || d.LocalNodeID != 0x1111 ||
		c.PeerNodeID != 0x1111 || c.LocalNodeID != 0x2222 {
		t.Fatal("records name the wrong peers")
	}

	// The device restarts: its records come back from storage.
	w := tlv.NewWriter(nil)
	p.devStore.Encode(w, tlv.Anonymous, nil)
	restored := &ResumptionStore{}
	r := tlv.NewReader(w.Bytes())
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if err := restored.Decode(r); err != nil {
		t.Fatal(err)
	}
	*p.devStore = *restored

	// With a key that no longer matches its NOC, the device cannot run a
	// full handshake: it can only resume.
	realKey := devF.Key
	devF.Key, _ = p256.GenerateKey(rand.Reader)
	p.connect(t, ctlF, 0x1111)
	second := p.sameRecord(t)
	if second == first {
		t.Fatal("resumption ID not renewed")
	}
	p.connect(t, ctlF, 0x1111)
	if p.sameRecord(t) == second {
		t.Fatal("resumption ID not renewed")
	}
	devF.Key = realKey

	// The device forgot the record: a full handshake, and a new record.
	p.devStore.ForgetFabric(devF.Index)
	p.connect(t, ctlF, 0x1111)
	p.sameRecord(t)

	// A record whose secret the initiator does not hold fails the MIC:
	// again a full handshake.
	p.ctlStore.records[0].Secret = bytes.Repeat([]byte{1}, 32)
	p.connect(t, ctlF, 0x1111)
	p.sameRecord(t)
	if len(p.failures) != 0 {
		t.Fatalf("device failures: %v", p.failures)
	}
}

func TestResumptionStore(t *testing.T) {
	s := &ResumptionStore{Max: 2}
	changes := 0
	s.OnChange = func() { changes++ }
	for i := range 3 {
		r := &Resumption{Secret: make([]byte, 32), FabricIndex: 1, PeerNodeID: uint64(i), PeerCATs: []uint32{7}}
		r.ID[0] = byte(i)
		s.save(r)
	}
	if s.Len() != 2 || s.byPeer(1, 0, 0) != nil || s.byPeer(1, 0, 2) == nil || s.byPeer(1, 5, 2) != nil || changes != 3 {
		t.Fatalf("store: %d records, %d changes", s.Len(), changes)
	}
	s.ForgetFabric(1)
	if s.Len() != 0 {
		t.Fatal("ForgetFabric left records")
	}
}

func TestResumptionStoreEncode(t *testing.T) {
	s := &ResumptionStore{}
	for i := range 4 {
		r := &Resumption{Secret: bytes.Repeat([]byte{byte(i)}, 32), FabricIndex: uint8(1 + i%2),
			LocalNodeID: 0x100 + uint64(i), PeerNodeID: uint64(i)}
		if i == 3 {
			r.PeerCATs = []uint32{0x0001_0001, 0x0002_0001}
		}
		r.ID[0] = byte(i)
		s.save(r)
	}
	decode := func(b []byte, max int) *ResumptionStore {
		t.Helper()
		d := &ResumptionStore{Max: max}
		r := tlv.NewReader(b)
		if err := r.Next(); err != nil {
			t.Fatal(err)
		}
		if err := d.Decode(r); err != nil {
			t.Fatal(err)
		}
		return d
	}

	// Fabric 1 only: records 0 and 2, in order.
	w := tlv.NewWriter(nil)
	s.Encode(w, tlv.Anonymous, func(index uint8) bool { return index == 1 })
	d := decode(w.Bytes(), 0)
	if d.Len() != 2 || d.records[0].PeerNodeID != 0 || d.records[1].PeerNodeID != 2 {
		t.Fatalf("filtered: %d records", d.Len())
	}

	// Everything round-trips; Max keeps the most recently used.
	w = tlv.NewWriter(nil)
	s.Encode(w, tlv.Anonymous, nil)
	d = decode(w.Bytes(), 0)
	for i, r := range d.records {
		o := s.records[i]
		if r.ID != o.ID || !bytes.Equal(r.Secret, o.Secret) || r.FabricIndex != o.FabricIndex ||
			r.LocalNodeID != o.LocalNodeID || r.PeerNodeID != o.PeerNodeID || len(r.PeerCATs) != len(o.PeerCATs) {
			t.Fatalf("record %d: %+v, want %+v", i, r, o)
		}
	}
	if d.records[3].PeerCATs[1] != 0x0002_0001 {
		t.Fatal("CATs lost")
	}
	if d = decode(w.Bytes(), 3); d.Len() != 3 || d.records[0].PeerNodeID != 1 {
		t.Fatalf("Max: %d records", d.Len())
	}
	// A record without a secret is dropped.
	s.records[0].Secret = nil
	w = tlv.NewWriter(nil)
	s.Encode(w, tlv.Anonymous, nil)
	if d = decode(w.Bytes(), 0); d.Len() != 3 {
		t.Fatalf("malformed record kept: %d records", d.Len())
	}
}
