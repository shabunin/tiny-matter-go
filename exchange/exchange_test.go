package exchange

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/message"
)

// From connectedhomeip src/messaging/tests/TestReliableMessageProtocol.cpp
// (theBackoffComplianceTestVector), in milliseconds.
func TestBackoffSDKCompliance(t *testing.T) {
	for _, tc := range []struct{ n, base, min, max int64 }{
		{0, 300, 330, 413},
		{1, 300, 330, 413},
		{2, 300, 528, 661},
		{3, 300, 844, 1057},
		{4, 300, 1351, 1691},
		{5, 300, 2162, 2705},
		{6, 300, 2162, 2705},
		{0, 4000, 4400, 5503},
		{1, 4000, 4400, 5503},
		{2, 4000, 7040, 8805},
		{3, 4000, 11264, 14088},
		{4, 4000, 18022, 22541},
		{5, 4000, 28835, 36065},
		{6, 4000, 28835, 36065},
	} {
		base := time.Duration(tc.base) * time.Millisecond
		for _, j := range []uint8{0, 1, 128, 255} {
			got := Backoff(base, int(tc.n), j) / time.Millisecond
			if int64(got) < tc.min || int64(got) > tc.max {
				t.Errorf("Backoff(%v, %d, %d) = %dms, want [%d, %d]", base, tc.n, j, got, tc.min, tc.max)
			}
		}
	}
}

// --- simulated network ---

type packet struct {
	from, to Addr
	data     []byte
}

type net struct {
	queue []packet
	drop  func(p packet) bool
	sent  int
}

type port struct {
	n    *net
	addr Addr
}

func (p port) Send(to Addr, pkt []byte) error {
	p.n.sent++
	pk := packet{from: p.addr, to: to, data: bytes.Clone(pkt)}
	if p.n.drop != nil && p.n.drop(pk) {
		return nil
	}
	p.n.queue = append(p.n.queue, pk)
	return nil
}

type node struct {
	m    *Manager
	addr Addr
}

type world struct {
	t     *testing.T
	net   *net
	now   time.Time
	nodes []*node
}

func newWorld(t *testing.T) *world {
	return &world{t: t, net: &net{}, now: time.Unix(1000, 0)}
}

func (w *world) node(port_ uint16) *node {
	addr := netip.AddrPortFrom(netip.MustParseAddr("fe80::1"), port_)
	m, err := NewManager(Config{Transport: port{w.net, addr}, Rand: rand.Reader})
	if err != nil {
		w.t.Fatal(err)
	}
	n := &node{m: m, addr: addr}
	w.nodes = append(w.nodes, n)
	return n
}

// deliver delivers queued packets until the network is quiet.
func (w *world) deliver() {
	for len(w.net.queue) > 0 {
		p := w.net.queue[0]
		w.net.queue = w.net.queue[1:]
		for _, n := range w.nodes {
			if n.addr == p.to {
				n.m.HandlePacket(w.now, p.from, p.data)
			}
		}
	}
}

// advance moves time forward by d, running timers on all nodes as they come
// due and delivering resulting packets.
func (w *world) advance(d time.Duration) {
	end := w.now.Add(d)
	for {
		var next time.Time
		for _, n := range w.nodes {
			if t := n.m.Poll(w.now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
				next = t
			}
		}
		w.deliver()
		if next.IsZero() || next.After(end) {
			break
		}
		if next.After(w.now) {
			w.now = next
		}
	}
	w.now = end
}

// recorder is a Delegate that records events and optionally replies.
type recorder struct {
	msgs  []Message
	errs  []error
	reply []byte // if non-nil, respond to each message with opcode+1
	close bool   // close after replying
	onMsg func(now time.Time, ex *Exchange, msg Message)
}

func (r *recorder) OnMessage(now time.Time, ex *Exchange, msg Message) {
	msg.Payload = bytes.Clone(msg.Payload)
	r.msgs = append(r.msgs, msg)
	if r.onMsg != nil {
		r.onMsg(now, ex, msg)
	}
	if r.reply != nil {
		if err := ex.Send(now, msg.ProtocolID, msg.Opcode+1, r.reply); err != nil {
			panic(err)
		}
		if r.close {
			ex.Close(now)
		}
	}
}

func (r *recorder) OnError(now time.Time, ex *Exchange, err error) { r.errs = append(r.errs, err) }

func securePair(t *testing.T, w *world, a, b *node) (sa, sb *Session) {
	k1, k2 := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	ida, _ := a.m.AllocateSessionID()
	idb, _ := b.m.AllocateSessionID()
	var err error
	sa, err = a.m.NewSecureSession(w.now, SecureSessionParams{Peer: b.addr, LocalSessionID: ida, PeerSessionID: idb,
		LocalNodeID: 0x1111, PeerNodeID: 0x2222, EncryptKey: k1, DecryptKey: k2})
	if err != nil {
		t.Fatal(err)
	}
	sb, err = b.m.NewSecureSession(w.now, SecureSessionParams{Peer: a.addr, LocalSessionID: idb, PeerSessionID: ida,
		LocalNodeID: 0x2222, PeerNodeID: 0x1111, EncryptKey: k2, DecryptKey: k1})
	if err != nil {
		t.Fatal(err)
	}
	return sa, sb
}

func TestUnsecuredRequestResponse(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	srv := &recorder{reply: []byte("pong"), close: true}
	b.m.Register(message.ProtocolSecureChannel, func(ex *Exchange) Delegate { return srv })

	s, err := a.m.NewUnsecuredSession(w.now, b.addr, MRPConfig{})
	if err != nil {
		t.Fatal(err)
	}
	cli := &recorder{}
	ex, _ := a.m.NewExchange(s, cli)
	if err := ex.Send(w.now, message.ProtocolSecureChannel, 0x20, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	w.deliver()
	if len(srv.msgs) != 1 || string(srv.msgs[0].Payload) != "ping" || srv.msgs[0].Opcode != 0x20 {
		t.Fatalf("server got %+v", srv.msgs)
	}
	if len(cli.msgs) != 1 || string(cli.msgs[0].Payload) != "pong" || cli.msgs[0].Opcode != 0x21 {
		t.Fatalf("client got %+v", cli.msgs)
	}
	if ex.AwaitingAck() {
		t.Fatal("request not acknowledged by piggybacked ack")
	}
	sent := w.net.sent
	ex.Close(w.now) // flushes the ack for the response immediately
	w.deliver()
	if w.net.sent != sent+1 {
		t.Fatalf("close sent %d packets, want 1 standalone ack", w.net.sent-sent)
	}
	w.advance(time.Minute)
	if w.net.sent != sent+1 || len(a.m.exchanges)+len(b.m.exchanges) != 0 {
		t.Fatalf("traffic or exchanges left over: sent %d, exchanges %d/%d",
			w.net.sent-sent, len(a.m.exchanges), len(b.m.exchanges))
	}
}

func TestStandaloneAckAfterTimeout(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	srv := &recorder{} // never replies
	b.m.Register(message.ProtocolSecureChannel, func(ex *Exchange) Delegate { return srv })
	s, _ := a.m.NewUnsecuredSession(w.now, b.addr, MRPConfig{})
	ex, _ := a.m.NewExchange(s, &recorder{})
	ex.Send(w.now, message.ProtocolSecureChannel, 0x20, nil)
	w.deliver()
	w.advance(StandaloneAckTimeout - time.Millisecond)
	if !ex.AwaitingAck() {
		t.Fatal("acked before MRP_STANDALONE_ACK_TIMEOUT")
	}
	w.advance(time.Millisecond)
	if ex.AwaitingAck() {
		t.Fatal("no standalone ack after MRP_STANDALONE_ACK_TIMEOUT")
	}
}

func TestSecureSessionEncryptsAndRoutes(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, _ := securePair(t, w, a, b)
	srv := &recorder{reply: []byte("secret reply")}
	b.m.Register(message.ProtocolInteractionModel, func(ex *Exchange) Delegate { return srv })

	var wire [][]byte
	w.net.drop = func(p packet) bool { wire = append(wire, bytes.Clone(p.data)); return false }
	cli := &recorder{}
	ex, _ := a.m.NewExchange(sa, cli)
	ex.Send(w.now, message.ProtocolInteractionModel, 0x02, []byte("secret request"))
	w.deliver()
	if len(cli.msgs) != 1 || string(cli.msgs[0].Payload) != "secret reply" {
		t.Fatalf("client got %+v", cli.msgs)
	}
	for _, p := range wire {
		if bytes.Contains(p, []byte("secret")) {
			t.Fatalf("plaintext on the wire: % x", p)
		}
		var h message.Header
		if _, err := h.Decode(p); err != nil || !h.IsEncrypted() || h.HasSource || h.Dest != message.DestNone {
			t.Fatalf("bad secure header %+v (%v)", h, err)
		}
	}
	// A packet for an unknown session is dropped.
	bad := bytes.Clone(wire[0])
	bad[1] ^= 0xFF
	if err := b.m.HandlePacket(w.now, a.addr, bad); err != ErrUnknownSession {
		t.Fatalf("unknown session: %v", err)
	}
}

func TestRetransmissionAndDuplicate(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, _ := securePair(t, w, a, b)
	srv := &recorder{}
	b.m.Register(message.ProtocolInteractionModel, func(ex *Exchange) Delegate { return srv })

	var first []byte
	w.net.drop = func(p packet) bool {
		if first == nil {
			first = p.data
			return true // lose the first transmission
		}
		return false
	}
	ex, _ := a.m.NewExchange(sa, &recorder{})
	ex.Send(w.now, message.ProtocolInteractionModel, 0x02, []byte("req"))
	w.deliver()
	if len(srv.msgs) != 0 {
		t.Fatal("lost packet delivered")
	}
	// Idle peer: first retransmission within [330*500/300, ...] ms.
	w.advance(Backoff(DefaultMRPConfig.IdleInterval, 0, 255))
	if len(srv.msgs) != 1 {
		t.Fatalf("retransmission not delivered: %d", len(srv.msgs))
	}
	// Replay the original (identical) packet: acked, not redelivered.
	before := w.net.sent
	err := b.m.HandlePacket(w.now, a.addr, bytes.Clone(first))
	if err != message.ErrDuplicate || len(srv.msgs) != 1 {
		t.Fatalf("duplicate: err %v, delivered %d", err, len(srv.msgs))
	}
	if w.net.sent != before+1 {
		t.Fatal("duplicate needing an ack was not acked")
	}
	w.advance(time.Second)
	if ex.AwaitingAck() {
		t.Fatal("request never acknowledged")
	}
}

func TestDeliveryFailure(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, _ := securePair(t, w, a, b)
	var times []time.Time
	w.net.drop = func(p packet) bool { times = append(times, w.now); return true }
	cli := &recorder{}
	ex, _ := a.m.NewExchange(sa, cli)
	start := w.now
	ex.Send(w.now, message.ProtocolInteractionModel, 0x02, nil)
	w.advance(time.Minute)
	if len(times) != MaxTransmissions {
		t.Fatalf("%d transmissions, want %d", len(times), MaxTransmissions)
	}
	if len(cli.errs) != 1 || !errors.Is(cli.errs[0], ErrDeliveryFailed) {
		t.Fatalf("errors %v", cli.errs)
	}
	// Each gap lies within the SDK backoff bounds for an idle peer (500ms).
	prev := start
	for i, ts := range times[1:] {
		gap := ts.Sub(prev)
		lo, hi := Backoff(500*time.Millisecond, i, 0), Backoff(500*time.Millisecond, i, 255)
		if gap < lo || gap > hi {
			t.Errorf("gap %d = %v, want [%v, %v]", i, gap, lo, hi)
		}
		prev = ts
	}
	if len(a.m.exchanges) != 0 {
		t.Fatal("failed exchange not removed")
	}
	if err := ex.Send(w.now, 1, 1, nil); err != ErrExchangeClosed {
		t.Fatalf("send on failed exchange: %v", err)
	}
}

func TestActivePeerUsesActiveInterval(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, sb := securePair(t, w, a, b)
	b.m.Register(message.ProtocolInteractionModel, func(ex *Exchange) Delegate { return &recorder{} })
	_ = sb
	// Make the peer active by receiving something from it.
	sa.lastPeerActivity = w.now
	var times []time.Time
	w.net.drop = func(p packet) bool { times = append(times, w.now); return true }
	ex, _ := a.m.NewExchange(sa, &recorder{})
	ex.Send(w.now, message.ProtocolInteractionModel, 0x02, nil)
	w.advance(2 * time.Second)
	if len(times) < 2 || times[1].Sub(times[0]) > Backoff(300*time.Millisecond, 0, 255) {
		t.Fatalf("active peer retransmitted after %v", times[1].Sub(times[0]))
	}
}

func TestUnknownProtocolIsAckedAndDropped(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, _ := securePair(t, w, a, b)
	ex, _ := a.m.NewExchange(sa, &recorder{})
	ex.Send(w.now, 0x7777, 1, nil)
	w.deliver()
	if ex.AwaitingAck() {
		t.Fatal("message to unknown protocol not acknowledged")
	}
	if len(b.m.exchanges) != 0 {
		t.Fatal("exchange created for unknown protocol")
	}
}

func TestBusyAndPiggyback(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, _ := securePair(t, w, a, b)
	var srvEx *Exchange
	srv := &recorder{onMsg: func(now time.Time, ex *Exchange, msg Message) { srvEx = ex }}
	b.m.Register(message.ProtocolInteractionModel, func(ex *Exchange) Delegate { return srv })
	ex, _ := a.m.NewExchange(sa, &recorder{})
	w.net.drop = func(p packet) bool { return true } // hold everything
	ex.Send(w.now, message.ProtocolInteractionModel, 1, nil)
	if err := ex.Send(w.now, message.ProtocolInteractionModel, 2, nil); err != ErrBusy {
		t.Fatalf("second unacked send: %v", err)
	}
	w.net.drop = nil
	w.advance(time.Second) // retransmission reaches b
	if srvEx == nil {
		t.Fatal("not delivered")
	}
	// b replies before its standalone ack timer: the ack rides on the reply.
	var wire []byte
	w.net.drop = func(p packet) bool { wire = p.data; return false }
	srvEx.Send(w.now, message.ProtocolInteractionModel, 3, nil)
	w.net.drop = nil
	w.deliver()
	if ex.AwaitingAck() {
		t.Fatal("piggybacked ack not applied")
	}
	_ = wire
}

func TestSessionCloseFailsExchanges(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(1), w.node(2)
	sa, _ := securePair(t, w, a, b)
	cli := &recorder{}
	ex, _ := a.m.NewExchange(sa, cli)
	w.net.drop = func(p packet) bool { return true }
	ex.Send(w.now, 1, 1, nil)
	a.m.CloseSession(w.now, sa)
	if len(cli.errs) != 1 || cli.errs[0] != ErrSessionClosed {
		t.Fatalf("errors %v", cli.errs)
	}
	if _, err := a.m.NewExchange(sa, cli); err != ErrSessionClosed {
		t.Fatalf("new exchange on closed session: %v", err)
	}
	if w.advance(time.Minute); w.net.sent != 1 {
		t.Fatalf("closed session kept retransmitting (%d sends)", w.net.sent)
	}
}

func TestUnsecuredSessionEviction(t *testing.T) {
	w := newWorld(t)
	b := w.node(2)
	b.m.Register(message.ProtocolSecureChannel, func(ex *Exchange) Delegate { return &recorder{} })
	for i := range b.m.cfg.MaxUnsecuredSessions + 3 {
		a := w.node(uint16(10 + i))
		s, _ := a.m.NewUnsecuredSession(w.now, b.addr, MRPConfig{})
		ex, _ := a.m.NewExchange(s, &recorder{})
		ex.Send(w.now, message.ProtocolSecureChannel, 0x20, nil)
		w.deliver()
		w.now = w.now.Add(time.Second)
	}
	if n := b.m.count(false); n != b.m.cfg.MaxUnsecuredSessions {
		t.Fatalf("%d unsecured sessions, want %d", n, b.m.cfg.MaxUnsecuredSessions)
	}
}

// TestClockTimesRetransmission: a reply computed slowly after the request
// it answers must not be retransmitted at once.
func TestClockTimesRetransmission(t *testing.T) {
	w := newWorld(t)
	a := w.node(1)
	peer := netip.AddrPortFrom(netip.MustParseAddr("fe80::1"), 9)
	compute := 700 * time.Millisecond // PASE on a microcontroller
	a.m.cfg.Clock = func() time.Time { return w.now.Add(compute) }
	s, _ := a.m.NewUnsecuredSession(w.now, peer, MRPConfig{})
	ex, _ := a.m.NewExchange(s, &recorder{})
	ex.Send(w.now, message.ProtocolSecureChannel, 0x23, []byte("pake2"))
	sent := w.net.sent
	// Just after the real send, nothing may be retransmitted yet.
	a.m.Poll(w.now.Add(compute + 10*time.Millisecond))
	if w.net.sent != sent {
		t.Fatal("retransmitted immediately after a slow send")
	}
	a.m.cfg.Clock = nil
	ex2, _ := a.m.NewExchange(s, &recorder{})
	ex2.Send(w.now, message.ProtocolSecureChannel, 0x23, []byte("pake2"))
	a.m.Poll(w.now.Add(compute + 10*time.Millisecond))
	if w.net.sent == sent+1 {
		t.Fatal("without a clock the stale time should have caused a retransmission (test premise)")
	}
}

// reliablePort is a transport that delivers reliably, as BTP does.
type reliablePort struct{ port }

func (reliablePort) Reliable(to Addr) bool { return true }

func TestReliableTransportSkipsMRP(t *testing.T) {
	w := newWorld(t)
	var nodes [2]*node
	for i := range nodes {
		addr := netip.AddrPortFrom(netip.MustParseAddr("fe80::1"), uint16(i+1))
		m, err := NewManager(Config{Transport: reliablePort{port{w.net, addr}}, Rand: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = &node{m: m, addr: addr}
		w.nodes = append(w.nodes, nodes[i])
	}
	a, b := nodes[0], nodes[1]
	sa, _ := securePair(t, w, a, b)
	srv := &recorder{reply: []byte("pong"), close: true}
	b.m.Register(message.ProtocolInteractionModel, func(ex *Exchange) Delegate { return srv })

	cli := &recorder{}
	ex, _ := a.m.NewExchange(sa, cli)
	if err := ex.Send(w.now, message.ProtocolInteractionModel, 0x02, []byte("req")); err != nil {
		t.Fatal(err)
	}
	if ex.AwaitingAck() {
		t.Fatal("awaiting an MRP ack over a reliable transport")
	}
	w.deliver()
	if len(srv.msgs) != 1 || len(cli.msgs) != 1 {
		t.Fatalf("server got %d, client got %d", len(srv.msgs), len(cli.msgs))
	}
	ex.Close(w.now)
	w.advance(time.Minute)
	// Request and response only: a message asking for an MRP ack would
	// have drawn a standalone ack.
	if w.net.sent != 2 {
		t.Fatalf("%d packets sent, want 2", w.net.sent)
	}
	if len(a.m.exchanges)+len(b.m.exchanges) != 0 {
		t.Fatal("exchanges left over")
	}
}
