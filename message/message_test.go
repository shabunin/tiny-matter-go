package message

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

// From connectedhomeip src/transport/raw/tests/TestMessageHeader.cpp
// (theSpecComplianceTestVector).
func TestSDKSpecCompliance(t *testing.T) {
	for _, tc := range []struct {
		enc       []byte
		h         Header
		encrypted bool
	}{
		{[]byte{0x00, 0x88, 0x77, 0x00, 0x44, 0x33, 0x22, 0x11},
			Header{SessionID: 0x7788, MessageCounter: 0x11223344}, true},
		{[]byte{0x02, 0xEE, 0xDD, 0xC1, 0x40, 0x30, 0x20, 0x10, 0x56, 0x34},
			Header{SessionID: 0xDDEE, SessionType: SessionGroup, Privacy: true, Control: true,
				MessageCounter: 0x10203040, Dest: DestGroup, DestGroupID: 0x3456}, true},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x40, 0x30, 0x20, 0x10},
			Header{MessageCounter: 0x10203040}, false},
	} {
		if got := tc.h.AppendTo(nil); !bytes.Equal(got, tc.enc) {
			t.Errorf("encode %+v = % x, want % x", tc.h, got, tc.enc)
		}
		var h Header
		n, err := h.Decode(tc.enc)
		if err != nil || n != len(tc.enc) || !reflect.DeepEqual(h, tc.h) {
			t.Errorf("decode % x = %+v, %d, %v", tc.enc, h, n, err)
		}
		if h.IsEncrypted() != tc.encrypted {
			t.Errorf("% x: IsEncrypted = %v", tc.enc, h.IsEncrypted())
		}
	}
}

// From TestMessageHeader.cpp (theTestVectorMsgExtensions): message and
// secured extensions in every source/destination combination.
func TestSDKExtensions(t *testing.T) {
	const hdr, src, dst, gid, mx, sx, pro = 8, 8, 8, 2, 6, 6, 6
	for _, tc := range []struct {
		msg                string
		payloadOff, appOff int
	}{
		{"\x00\x00\x00\x00\xCC\xCC\xCC\xCC\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr, pro},
		{"\x00\x00\x00\x20\xCC\xCC\xCC\xCC\x04\x00\xE4\xE3\xE2\xE1\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr + mx, pro},
		{"\x04\x00\x00\x20\xCC\xCC\xCC\xCC\x11\x11\x11\x11\x11\x11\x11\x11\x04\x00\xE4\xE3\xE2\xE1\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr + mx + src, pro},
		{"\x01\x00\x00\x20\xCC\xCC\xCC\xCC\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\x04\x00\xE4\xE3\xE2\xE1\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr + mx + dst, pro},
		{"\x05\x00\x00\x20\xCC\xCC\xCC\xCC\x11\x11\x11\x11\x11\x11\x11\x11\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\x04\x00\xE4\xE3\xE2\xE1\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr + mx + src + dst, pro},
		{"\x02\x00\x00\x21\xCC\xCC\xCC\xCC\xDD\xDD\x04\x00\xE4\xE3\xE2\xE1\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr + mx + gid, pro},
		{"\x06\x00\x00\x21\xCC\xCC\xCC\xCC\x11\x11\x11\x11\x11\x11\x11\x11\xDD\xDD\x04\x00\xE4\xE3\xE2\xE1\x01\xCC\xEE\xEE\x66\x66\xBB\xBB", hdr + mx + src + gid, pro},
		{"\x00\x00\x00\x00\xCC\xCC\xCC\xCC\x08\xCC\xEE\xEE\x66\x66\x04\x00\xE4\xE3\xE2\xE1\xBB\xBB", hdr, pro + sx},
		{"\x00\x00\x00\x20\xCC\xCC\xCC\xCC\x04\x00\xE4\xE3\xE2\xE1\x08\xCC\xEE\xEE\x66\x66\x04\x00\xE4\xE3\xE2\xE1\xBB\xBB", hdr + mx, pro + sx},
		{"\x05\x00\x00\x20\xCC\xCC\xCC\xCC\x11\x11\x11\x11\x11\x11\x11\x11\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\x04\x00\xE4\xE3\xE2\xE1\x09\xCC\xEE\xEE\x66\x66\x04\x00\xE4\xE3\xE2\xE1\xBB\xBB", hdr + mx + src + dst, pro + sx},
	} {
		msg := []byte(tc.msg)
		var h Header
		n, err := h.Decode(msg)
		if err != nil || n != tc.payloadOff {
			t.Errorf("% x: header size %d, %v; want %d", msg, n, err, tc.payloadOff)
			continue
		}
		var p ProtocolHeader
		m, err := p.Decode(msg[n:])
		if err != nil || m != tc.appOff {
			t.Errorf("% x: protocol header size %d, %v; want %d", msg, m, err, tc.appOff)
			continue
		}
		if p.ExchangeID != 0xEEEE || p.ProtocolID != 0x6666 || p.Opcode != 0xCC {
			t.Errorf("% x: protocol header %+v", msg, p)
		}
		if h.Extensions != nil && !bytes.Equal(h.Extensions, []byte{0xE4, 0xE3, 0xE2, 0xE1}) {
			t.Errorf("% x: MX = % x", msg, h.Extensions)
		}
		// Re-encoding reproduces the input exactly.
		re := p.AppendTo(h.AppendTo(nil))
		re = append(re, msg[n+m:]...)
		if !bytes.Equal(re, msg) {
			t.Errorf("re-encode:\n% x\n% x", re, msg)
		}
	}
}

func TestProtocolHeaderFields(t *testing.T) {
	p := ProtocolHeader{Initiator: true, NeedsAck: true, HasAck: true, Opcode: 0x20,
		ExchangeID: 0x1234, VendorID: 0xFFF1, ProtocolID: 0x0001, AckCounter: 0xA1B2C3D4}
	want := []byte{0x17, 0x20, 0x34, 0x12, 0xF1, 0xFF, 0x01, 0x00, 0xD4, 0xC3, 0xB2, 0xA1}
	got := p.AppendTo(nil)
	if !bytes.Equal(got, want) || p.Size() != len(want) {
		t.Fatalf("got % x (size %d), want % x", got, p.Size(), want)
	}
	var q ProtocolHeader
	if n, err := q.Decode(got); err != nil || n != len(want) || !reflect.DeepEqual(p, q) {
		t.Fatalf("decode = %+v, %d, %v", q, n, err)
	}
	for i := range want {
		if _, err := q.Decode(want[:i]); err == nil {
			t.Fatalf("truncated at %d accepted", i)
		}
	}
}

func TestHeaderErrors(t *testing.T) {
	for _, b := range [][]byte{
		{0x10, 0, 0, 0, 0, 0, 0, 0},             // version 1
		{0x03, 0, 0, 0, 0, 0, 0, 0},             // reserved DSIZ
		{0x02, 0, 0, 0x00, 0, 0, 0, 0, 1, 2},    // group ID on unicast session
		{0x00, 0, 0, 0x02, 0, 0, 0, 0},          // reserved session type
		{0x04, 0, 0, 0, 0, 0, 0, 0, 1},          // truncated source
		{0x00, 0, 0, 0x20, 0, 0, 0, 0, 5, 0, 1}, // truncated MX
	} {
		var h Header
		if _, err := h.Decode(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
}

func newCipher(t testing.TB, key byte) *Cipher {
	c, err := NewCipher(bytes.Repeat([]byte{key}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSealOpen(t *testing.T) {
	enc := newCipher(t, 1)
	h := Header{SessionID: 0x1234, MessageCounter: 99, HasSource: true, SourceNodeID: 0x0102030405060708}
	p := ProtocolHeader{Initiator: true, NeedsAck: true, Opcode: 0x02, ExchangeID: 7, ProtocolID: ProtocolInteractionModel}
	payload := append(p.AppendTo(nil), "app payload"...)

	buf := make([]byte, 0, MaxPacketSize)
	pkt, err := enc.AppendSealed(buf, &h, payload, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != h.Size()+len(payload)+MICSize {
		t.Fatalf("packet length %d", len(pkt))
	}
	if bytes.Contains(pkt, []byte("app payload")) {
		t.Fatal("payload not encrypted")
	}
	if n := testing.AllocsPerRun(10, func() { enc.AppendSealed(buf[:0], &h, payload, 42) }); n != 0 {
		t.Errorf("AppendSealed allocates %v times", n)
	}
	dec := newCipher(t, 1)
	scratch := make([]byte, len(pkt))
	if n := testing.AllocsPerRun(10, func() {
		copy(scratch, pkt)
		var rh Header
		l, _ := rh.Decode(scratch)
		if _, err := dec.OpenInPlace(scratch, &rh, l, 42); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Errorf("OpenInPlace allocates %v times", n)
	}

	open := func(pkt []byte, nodeID uint64) ([]byte, error) {
		pkt = bytes.Clone(pkt)
		var rh Header
		n, err := rh.Decode(pkt)
		if err != nil {
			return nil, err
		}
		return newCipher(t, 1).OpenInPlace(pkt, &rh, n, nodeID)
	}
	pt, err := open(pkt, 42)
	if err != nil || !bytes.Equal(pt, payload) {
		t.Fatalf("open = %q, %v", pt, err)
	}
	if _, err := open(pkt, 43); err != ErrAuth {
		t.Errorf("wrong nonce node ID: %v", err)
	}
	bad := bytes.Clone(pkt)
	bad[4] ^= 1 // message counter, part of AAD and nonce
	if _, err := open(bad, 42); err != ErrAuth {
		t.Errorf("tampered header: %v", err)
	}
	bad = bytes.Clone(pkt)
	bad[1] ^= 1 // session ID: AAD only
	if _, err := open(bad, 42); err != ErrAuth {
		t.Errorf("tampered session ID: %v", err)
	}
	if _, err := open(pkt[:h.Size()+MICSize-1], 42); err == nil {
		t.Error("short packet accepted")
	}
}

func TestCounter(t *testing.T) {
	for range 100 {
		c, err := NewCounter(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := c.Next()
		if v < 1 || v > 1<<28 {
			t.Fatalf("initial counter %d out of [1, 2^28]", v)
		}
		if w, _ := c.Next(); w != v+1 {
			t.Fatalf("not sequential: %d then %d", v, w)
		}
	}
	c := Counter{next: 0xFFFFFFFE}
	a, _ := c.Next()
	b, err := c.Next()
	if a != 0xFFFFFFFE || b != 0xFFFFFFFF || err != nil {
		t.Fatalf("got %x %x %v", a, b, err)
	}
	if _, err := c.Next(); err != ErrCounterExhausted {
		t.Fatalf("no exhaustion: %v", err)
	}
	w := Counter{next: 0xFFFFFFFF}
	if w.NextWrapping() != 0xFFFFFFFF || w.NextWrapping() != 0 {
		t.Fatal("NextWrapping does not wrap")
	}
}

func TestEncryptedUnicastWindow(t *testing.T) {
	var s ReceptionState
	if s.CheckEncryptedUnicast(1) == nil {
		t.Fatal("unsynchronized state accepted a counter")
	}
	s.SetCounter(0)
	accept := func(c uint32) bool {
		if s.CheckEncryptedUnicast(c) != nil {
			return false
		}
		s.CommitEncryptedUnicast(c)
		return true
	}
	if accept(0) {
		t.Fatal("counter equal to initial max accepted")
	}
	for _, c := range []uint32{100, 101, 105} {
		if !accept(c) {
			t.Fatalf("%d rejected", c)
		}
	}
	for _, c := range []uint32{100, 101, 105} {
		if accept(c) {
			t.Fatalf("replay %d accepted", c)
		}
	}
	if !accept(103) || accept(103) {
		t.Fatal("out-of-order in-window counter handled wrongly")
	}
	if !accept(105-CounterWindowSize) || accept(105-CounterWindowSize-1) {
		t.Fatal("window edge handled wrongly")
	}
	if !accept(1000) || accept(1000-CounterWindowSize-1) {
		t.Fatal("large jump handled wrongly")
	}
	// No rollover for unicast: a wrapped counter is old, not new.
	s.SetCounter(0xFFFFFFF0)
	if accept(5) {
		t.Fatal("wrapped unicast counter accepted")
	}
}

func TestUnencryptedAndGroup(t *testing.T) {
	var s ReceptionState
	if s.CheckUnencrypted(500) != nil {
		t.Fatal("first unencrypted counter rejected")
	}
	s.CommitUnencrypted(500)
	if s.CheckUnencrypted(500) != ErrDuplicate {
		t.Fatal("duplicate accepted")
	}
	// Far behind the window: accepted (peer may have rebooted) and resyncs.
	if s.CheckUnencrypted(10) != nil {
		t.Fatal("rebooted peer rejected")
	}
	s.CommitUnencrypted(10)
	if s.CheckUnencrypted(10) != ErrDuplicate || s.CheckUnencrypted(11) != nil {
		t.Fatal("not resynchronized after reboot")
	}

	var g ReceptionState
	g.CommitGroup(0xFFFFFFFE)
	for _, c := range []uint32{0xFFFFFFFF, 0, 3} { // rolls over
		if g.CheckGroup(c) != nil {
			t.Fatalf("group counter %x rejected", c)
		}
		g.CommitGroup(c)
	}
	if g.CheckGroup(0xFFFFFFFF) != ErrDuplicate || g.CheckGroup(1) != nil {
		t.Fatal("group window across rollover wrong")
	}
	if three := uint32(3); g.CheckGroup(three-1<<31) != ErrDuplicate {
		t.Fatal("group counter 2^31 behind accepted")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("\x05\x00\x00\x20\xCC\xCC\xCC\xCC\x11\x11\x11\x11\x11\x11\x11\x11\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\x04\x00\xE4\xE3\xE2\xE1\x09\xCC\xEE\xEE\x66\x66\x04\x00\xE4\xE3\xE2\xE1\xBB\xBB"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var h Header
		n, err := h.Decode(b)
		if err != nil {
			return
		}
		if n != h.Size() {
			t.Fatalf("Decode consumed %d, Size %d", n, h.Size())
		}
		var h2 Header
		if _, err := h2.Decode(h.AppendTo(nil)); err != nil || !reflect.DeepEqual(h, h2) {
			t.Fatalf("header round trip: %+v vs %+v (%v)", h, h2, err)
		}
		var p ProtocolHeader
		m, err := p.Decode(b[n:])
		if err != nil {
			return
		}
		// A V flag with vendor ID 0 is legal and means the common namespace,
		// which re-encodes without the field; otherwise sizes must agree.
		if m != p.Size() && !(b[n]&exVendor != 0 && p.VendorID == 0) {
			t.Fatalf("protocol Decode consumed %d, Size %d", m, p.Size())
		}
		var p2 ProtocolHeader
		if _, err := p2.Decode(p.AppendTo(nil)); err != nil || !reflect.DeepEqual(p, p2) {
			t.Fatalf("protocol round trip: %+v vs %+v (%v)", p, p2, err)
		}
	})
}
