package btp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

// central models the client side of BTP, as connectedhomeip implements it.
type central struct {
	t        *testing.T
	frag     int
	window   uint8
	txSeq    uint8
	rxNext   uint8
	unacked  bool // received a segment we have not acknowledged
	rxNewest uint8
	rx       []byte
	rxLen    int
	msgs     [][]byte
}

func handshakeReq(mtu uint16, window uint8, versions ...uint8) []byte {
	b := []byte{0x65, 0x6C, 0, 0, 0, 0, 0, 0, window}
	for i, v := range versions {
		b[2+i/2] |= v << (4 * (i & 1))
	}
	binary.LittleEndian.PutUint16(b[6:], mtu)
	return b
}

// connect runs the handshake and returns the open server and its peer.
func connect(t *testing.T, mtu uint16) (*Conn, *central) {
	t.Helper()
	c := NewConn(247)
	if _, err := c.HandleWrite(t0, handshakeReq(mtu, 5, 4, 3)); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := c.Poll(t0); p != nil {
		t.Fatal("response before subscription")
	}
	c.Subscribed(t0)
	p, _, err := c.Poll(t0)
	if err != nil || len(p) != 6 || p[0] != 0x65 || p[1] != 0x6C || p[2] != 4 {
		t.Fatalf("response % x, %v", p, err)
	}
	cen := &central{t: t, frag: int(binary.LittleEndian.Uint16(p[3:])), window: p[5]}
	if cen.window != 5 || !c.Open() {
		t.Fatalf("window %d open %v", cen.window, c.Open())
	}
	// The response is segment 0, which the central acknowledges.
	cen.unacked, cen.rxNewest, cen.rxNext = true, 0, 1
	return c, cen
}

// segments fragments msg as the central would. Each segment is framed
// (ack and sequence number) only when sent, so acks can be interleaved.
func (cen *central) segments(msg []byte) []func() []byte {
	var out []func() []byte
	off := 0
	for first := true; first || off < len(msg); first = false {
		flags := uint8(flagContinue)
		hdr := 4 // flags, ack, seq; worst case as connectedhomeip assumes
		if first {
			flags, hdr = flagStart, 6
		}
		n := min(cen.frag-hdr, len(msg)-off)
		body := msg[off : off+n]
		off += n
		if off == len(msg) {
			flags |= flagEnd
		}
		total := len(msg)
		out = append(out, func() []byte {
			b := []byte{flags}
			if cen.unacked {
				b[0] |= flagAck
				b = append(b, cen.rxNewest)
				cen.unacked = false
			}
			b = append(b, cen.txSeq)
			cen.txSeq++
			if flags&flagStart != 0 {
				b = binary.LittleEndian.AppendUint16(b, uint16(total))
			}
			return append(b, body...)
		})
	}
	return out
}

func (cen *central) standaloneAck() []byte {
	b := []byte{flagAck, cen.rxNewest, cen.txSeq}
	cen.txSeq++
	cen.unacked = false
	return b
}

// receive handles a C2 packet from the server.
func (cen *central) receive(p []byte) {
	t := cen.t
	t.Helper()
	if len(p) > cen.frag {
		t.Fatalf("segment of %d bytes exceeds fragment size %d", len(p), cen.frag)
	}
	flags, i := p[0], 1
	if flags&flagAck != 0 {
		i++
	}
	if p[i] != cen.rxNext {
		t.Fatalf("seq %d, want %d", p[i], cen.rxNext)
	}
	cen.rxNewest, cen.unacked = p[i], true
	cen.rxNext++
	i++
	if flags&(flagStart|flagContinue|flagEnd) == 0 {
		return
	}
	if flags&flagStart != 0 {
		cen.rxLen = int(binary.LittleEndian.Uint16(p[i:]))
		cen.rx = cen.rx[:0]
		i += 2
	}
	cen.rx = append(cen.rx, p[i:]...)
	if flags&flagEnd != 0 {
		if len(cen.rx) != cen.rxLen {
			t.Fatalf("reassembled %d bytes, header said %d", len(cen.rx), cen.rxLen)
		}
		cen.msgs = append(cen.msgs, append([]byte(nil), cen.rx...))
	}
}

// drain delivers everything the server sends at now.
func drain(t *testing.T, c *Conn, cen *central, now time.Time) (n int, next time.Time) {
	t.Helper()
	for {
		p, nx, err := c.Poll(now)
		if err != nil {
			t.Fatal(err)
		}
		if p == nil {
			return n, nx
		}
		cen.receive(p)
		n++
	}
}

func msg(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

func TestHandshake(t *testing.T) {
	for _, tc := range []struct {
		mtu, att uint16
		frag     int
	}{
		{0, 0, 20},
		{0, 100, 97},
		{247, 0, 244},
		{517, 0, 244}, // capped by our maximum ATT MTU of 247
		{23, 517, 20},
		{5, 0, minFragment},
	} {
		c := NewConn(247)
		c.SetMTU(int(tc.att))
		if _, err := c.HandleWrite(t0, handshakeReq(tc.mtu, 10, 4)); err != nil {
			t.Fatal(err)
		}
		c.Subscribed(t0)
		p, _, _ := c.Poll(t0)
		if got := int(binary.LittleEndian.Uint16(p[3:])); got != tc.frag || p[5] != MaxWindow {
			t.Errorf("mtu %d/%d: fragment %d window %d, want %d %d", tc.mtu, tc.att, got, p[5], tc.frag, MaxWindow)
		}
	}
}

func TestHandshakeErrors(t *testing.T) {
	c := NewConn(0)
	if _, err := c.HandleWrite(t0, []byte{0x65, 0x6C, 4}); !errors.Is(err, ErrHandshake) {
		t.Fatal(err)
	}
	if _, err := c.HandleWrite(t0, handshakeReq(100, 0, 4)); !errors.Is(err, ErrHandshake) {
		t.Fatal("zero window accepted")
	}
	// No common version: the response says 0, then the connection closes.
	c.Reset(0)
	if _, err := c.HandleWrite(t0, handshakeReq(100, 4, 3, 2)); err != nil {
		t.Fatal(err)
	}
	c.Subscribed(t0)
	p, _, _ := c.Poll(t0)
	if p[2] != 0 {
		t.Fatalf("selected version %d", p[2])
	}
	if p, _, _ = c.Poll(t0); p != nil || !c.Closed() || c.Open() {
		t.Fatal("rejected connection not closed")
	}
	// Versions after a 0 terminator are ignored.
	c.Reset(0)
	c.HandleWrite(t0, handshakeReq(100, 4, 3, 0, 4))
	c.Subscribed(t0)
	if p, _, _ = c.Poll(t0); p[2] != 0 {
		t.Fatal("version after terminator selected")
	}
	// Data before the handshake completes.
	c.Reset(0)
	c.HandleWrite(t0, handshakeReq(100, 4, 4))
	if _, err := c.HandleWrite(t0, []byte{0x05, 0, 1, 0, 9}); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
}

func TestExchange(t *testing.T) {
	for _, mtu := range []uint16{23, 64, 247} {
		c, cen := connect(t, mtu)
		now := t0
		for round, size := range []int{1, 15, 16, 100, 600, MaxMessage} {
			want := msg(size, byte(round))
			var got []byte
			for _, s := range cen.segments(want) {
				m, err := c.HandleWrite(now, s())
				if err != nil {
					t.Fatalf("mtu %d size %d: %v", mtu, size, err)
				}
				if m != nil {
					got = append([]byte(nil), m...)
				}
				// Keep the window open as connectedhomeip does: ack at once
				// when the server's window runs low.
				if _, _ = drain(t, c, cen, now); cen.unacked {
					if _, err := c.HandleWrite(now, cen.standaloneAck()); err != nil {
						t.Fatalf("mtu %d size %d: ack: %v", mtu, size, err)
					}
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("mtu %d size %d: server got %d bytes", mtu, size, len(got))
			}
			reply := msg(size, byte(round+100))
			if err := c.Send(reply); err != nil {
				t.Fatal(err)
			}
			for c.qLen > 0 {
				if n, _ := drain(t, c, cen, now); n == 0 {
					// Window closed: the central acknowledges.
					if _, err := c.HandleWrite(now, cen.standaloneAck()); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(cen.msgs) != round+1 || !bytes.Equal(cen.msgs[round], reply) {
				t.Fatalf("mtu %d size %d: central did not get the reply", mtu, size)
			}
			now = now.Add(time.Second)
		}
	}
}

func TestWindow(t *testing.T) {
	c, cen := connect(t, 23)
	// The response used one slot of the central's window of 5. Without an
	// ack to piggyback the server keeps the last slot free, so 3 segments go.
	c.Send(msg(500, 1))
	// The first segment piggybacks nothing: nothing was received yet.
	n, _ := drain(t, c, cen, t0)
	if n != 3 {
		t.Fatalf("sent %d segments into a window of 4", n)
	}
	// The central acks the newest; the window reopens fully.
	if _, err := c.HandleWrite(t0, cen.standaloneAck()); err != nil {
		t.Fatal(err)
	}
	// The first segment carries the ack the server owes; after that the
	// last slot is kept free again.
	if n, _ = drain(t, c, cen, t0); n != 4 {
		t.Fatalf("sent %d segments after the window reopened", n)
	}
	if p := c.pkt[0]; p&flagAck != 0 {
		t.Fatal("ack sent twice")
	}
}

func TestAckTimers(t *testing.T) {
	c, cen := connect(t, 247)
	m, err := c.HandleWrite(t0, cen.segments([]byte("hello"))[0]())
	if err != nil || string(m) != "hello" {
		t.Fatal(m, err)
	}
	// The server holds the ack for piggybacking...
	n, next := drain(t, c, cen, t0)
	if n != 0 || !next.Equal(t0.Add(SendAckDelay)) {
		t.Fatalf("sent %d, next %v", n, next.Sub(t0))
	}
	// ...and sends it alone when the delay expires.
	if n, _ = drain(t, c, cen, next); n != 1 || len(cen.msgs) != 0 {
		t.Fatal("no standalone ack")
	}
	// The standalone ack needs an acknowledgement in turn; without one the
	// connection times out.
	_, next = drain(t, c, cen, next)
	if !next.Equal(t0.Add(SendAckDelay + AckTimeout)) {
		t.Fatalf("ack deadline %v", next.Sub(t0))
	}
	if _, _, err = c.Poll(next); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
}

func TestImmediateAck(t *testing.T) {
	c, cen := connect(t, 23)
	// The central streams a long message; once the server's window shrinks
	// to one, it acks at once rather than waiting for the timer.
	segs := cen.segments(msg(200, 3))
	for i := 0; i < 4; i++ {
		if _, err := c.HandleWrite(t0, segs[i]()); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := drain(t, c, cen, t0); n != 1 || cen.rxNewest != 1 {
		t.Fatal("no immediate ack")
	}
}

func TestBadSegments(t *testing.T) {
	for name, tc := range map[string]struct {
		seg  func(cen *central) []byte
		want error
	}{
		"seq":          {func(cen *central) []byte { return []byte{0x0D, 0, 7, 1, 0, 9} }, ErrSequence},
		"ack-future":   {func(cen *central) []byte { return []byte{0x0D, 3, 0, 1, 0, 9} }, ErrAck},
		"continue":     {func(cen *central) []byte { return []byte{0x0E, 0, 0, 9} }, ErrSegment},
		"too-long":     {func(cen *central) []byte { return []byte{0x0D, 0, 0, 0xFF, 0xFF, 9} }, ErrTooLong},
		"overflow":     {func(cen *central) []byte { return []byte{0x0D, 0, 0, 1, 0, 9, 9} }, ErrSegment},
		"short-end":    {func(cen *central) []byte { return []byte{0x0D, 0, 0, 3, 0, 9} }, ErrSegment},
		"management":   {func(cen *central) []byte { return []byte{0x25, 0, 0} }, ErrSegment},
		"truncated":    {func(cen *central) []byte { return []byte{0x08, 0} }, ErrSegment},
		"no-start-len": {func(cen *central) []byte { return []byte{0x01, 0} }, ErrSegment},
	} {
		c, cen := connect(t, 247)
		if _, err := c.HandleWrite(t0, tc.seg(cen)); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// An ack when nothing is outstanding is invalid.
	c, cen := connect(t, 247)
	c.HandleWrite(t0, cen.standaloneAck())
	if _, err := c.HandleWrite(t0, []byte{0x08, 0, cen.txSeq}); !errors.Is(err, ErrAck) {
		t.Fatal(err)
	}
}

func TestSequenceWrap(t *testing.T) {
	c, cen := connect(t, 247)
	for i := 0; i < 600; i++ {
		for _, s := range cen.segments([]byte{byte(i)}) {
			m, err := c.HandleWrite(t0, s())
			if err != nil || len(m) != 1 || m[0] != byte(i) {
				t.Fatalf("round %d: %v %v", i, m, err)
			}
		}
		c.Send([]byte{byte(i), 1})
		if n, _ := drain(t, c, cen, t0); n != 1 {
			t.Fatalf("round %d: sent %d", i, n)
		}
	}
	if len(cen.msgs) != 600 {
		t.Fatal(len(cen.msgs))
	}
}

func TestQueue(t *testing.T) {
	c := NewConn(0)
	if err := c.Send([]byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	c, _ = connect(t, 247)
	for i := 0; i < queueLen; i++ {
		if err := c.Send([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Send([]byte{9}); !errors.Is(err, ErrQueueFull) {
		t.Fatal(err)
	}
	if err := c.Send(make([]byte, MaxMessage+1)); err == nil {
		t.Fatal("oversized message queued")
	}
}

func TestAdvertisingData(t *testing.T) {
	d := ServiceData(3840, 0xFFF1, 0x8000, false)
	if want := [8]byte{0x00, 0x00, 0x0F, 0xF1, 0xFF, 0x00, 0x80, 0x00}; d != want {
		t.Fatalf("% x", d)
	}
	ad := AdvertisingData(0xF00|0x12, 0xFFF1, 0x8000)
	want := []byte{0x02, 0x01, 0x06, 0x0B, 0x16, 0xF6, 0xFF, 0x00, 0x12, 0x0F, 0xF1, 0xFF, 0x00, 0x80, 0x00}
	if !bytes.Equal(ad, want) {
		t.Fatalf("% x", ad)
	}
}

func FuzzHandleWrite(f *testing.F) {
	f.Add([]byte{0x0D, 0, 0, 1, 0, 9})
	f.Add([]byte{0x01, 0, 4, 0, 1, 2})
	f.Add([]byte{0x08, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		c := NewConn(247)
		c.HandleWrite(t0, handshakeReq(30, 4, 4))
		c.Subscribed(t0)
		c.Poll(t0)
		now := t0
		for len(b) > 0 {
			n := min(int(b[0]%32)+1, len(b))
			seg := b[:n]
			b = b[n:]
			if _, err := c.HandleWrite(now, seg); err != nil {
				return
			}
			c.Send(seg)
			for i := 0; i < 10; i++ {
				p, _, err := c.Poll(now)
				if err != nil || p == nil {
					break
				}
				if len(p) > c.frag {
					t.Fatalf("segment %d > %d", len(p), c.frag)
				}
			}
			now = now.Add(time.Second)
		}
	})
}
