package pase

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

const (
	testPasscode   = 20202021
	testIterations = 1000
)

var testSalt = []byte("SPAKE2P Key Salt")

func TestMessageRoundTrip(t *testing.T) {
	p := securechannel.DefaultSessionParams
	req := PBKDFParamRequest{InitiatorSessionID: 0x1234, HasPBKDFParameters: true, SessionParams: &p}
	rand.Read(req.InitiatorRandom[:])
	got, err := DecodePBKDFParamRequest(req.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.InitiatorRandom != req.InitiatorRandom || got.InitiatorSessionID != 0x1234 ||
		!got.HasPBKDFParameters || got.SessionParams == nil || *got.SessionParams != p {
		t.Fatalf("request mismatch: %+v", got)
	}

	resp := PBKDFParamResponse{ResponderSessionID: 7, Iterations: 1000, Salt: testSalt}
	rand.Read(resp.InitiatorRandom[:])
	rand.Read(resp.ResponderRandom[:])
	gr, err := DecodePBKDFParamResponse(resp.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if gr.InitiatorRandom != resp.InitiatorRandom || gr.ResponderRandom != resp.ResponderRandom ||
		gr.ResponderSessionID != 7 || gr.Iterations != 1000 || !bytes.Equal(gr.Salt, testSalt) || gr.SessionParams != nil {
		t.Fatalf("response mismatch: %+v", gr)
	}
	// Without PBKDF parameters.
	resp.Salt, resp.Iterations = nil, 0
	if gr, err = DecodePBKDFParamResponse(resp.Encode()); err != nil || gr.Salt != nil {
		t.Fatalf("got %+v, %v", gr, err)
	}

	pA := bytes.Repeat([]byte{4}, spake2p.PointSize)
	cB := bytes.Repeat([]byte{9}, spake2p.ConfirmSize)
	if v, err := DecodePake1(EncodePake1(pA)); err != nil || !bytes.Equal(v, pA) {
		t.Fatal("pake1", err)
	}
	if v, c, err := DecodePake2(EncodePake2(pA, cB)); err != nil || !bytes.Equal(v, pA) || !bytes.Equal(c, cB) {
		t.Fatal("pake2", err)
	}
	if v, err := DecodePake3(EncodePake3(cB)); err != nil || !bytes.Equal(v, cB) {
		t.Fatal("pake3", err)
	}
	// Wrong sizes and missing fields are rejected.
	if _, err := DecodePake1(EncodePake1(pA[:64])); err == nil {
		t.Fatal("short pA accepted")
	}
	if _, _, err := DecodePake2(EncodePake1(pA)); err == nil {
		t.Fatal("pake2 without cB accepted")
	}
	if _, err := DecodePBKDFParamRequest(EncodePake1(pA)); err == nil {
		t.Fatal("garbage request accepted")
	}
}

func FuzzDecode(f *testing.F) {
	req := PBKDFParamRequest{SessionParams: &securechannel.DefaultSessionParams}
	resp := PBKDFParamResponse{Iterations: 1000, Salt: testSalt, SessionParams: &securechannel.DefaultSessionParams}
	f.Add(req.Encode())
	f.Add(resp.Encode())
	f.Add(EncodePake2(make([]byte, 65), make([]byte, 32)))
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodePBKDFParamRequest(b)
		DecodePBKDFParamResponse(b)
		DecodePake1(b)
		DecodePake2(b)
		DecodePake3(b)
	})
}

type device struct {
	*simnet.Node
	r           *Responder
	established []*exchange.Session
	failures    []error
}

func newDevice(t *testing.T, w *simnet.World, port uint16) *device {
	v, err := spake2p.NewVerifier(testPasscode, testSalt, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	d := &device{Node: w.Node(port)}
	d.r, err = NewResponder(d.M, securechannel.NewDispatcher(d.M), ResponderConfig{
		Verifier: v, Salt: testSalt, Iterations: testIterations, Rand: rand.Reader,
		OnEstablished: func(now time.Time, s *exchange.Session) { d.established = append(d.established, s) },
		OnFailed:      func(now time.Time, err error) { d.failures = append(d.failures, err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	d.r.OpenWindow()
	return d
}

type result struct {
	done bool
	s    *exchange.Session
	err  error
}

func pair(t *testing.T, w *simnet.World, c *simnet.Node, dev exchange.Addr, passcode uint32) *result {
	res := &result{}
	err := Pair(w.Now, c.M, dev, InitiatorConfig{Passcode: passcode, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) {
			if res.done {
				t.Error("Done called twice")
			}
			res.done, res.s, res.err = true, s, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// echo replies to each Interaction Model message with the same payload.
type echo struct{ got [][]byte }

func (e *echo) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	e.got = append(e.got, bytes.Clone(msg.Payload))
	ex.Send(now, msg.ProtocolID, msg.Opcode+1, msg.Payload)
	ex.Close(now)
}
func (e *echo) OnError(time.Time, *exchange.Exchange, error) {}

func TestPairing(t *testing.T) {
	w := simnet.New(t)
	dev := newDevice(t, w, 5540)
	ctl := w.Node(5550)
	res := pair(t, w, ctl, dev.Addr, testPasscode)
	w.Advance(time.Second)

	if !res.done || res.err != nil {
		t.Fatalf("pairing: done=%v err=%v", res.done, res.err)
	}
	if len(dev.established) != 1 || len(dev.failures) != 0 {
		t.Fatalf("device: established=%d failures=%v", len(dev.established), dev.failures)
	}
	ds, cs := dev.established[0], res.s
	if !ds.IsSecure() || !cs.IsSecure() {
		t.Fatal("sessions not secure")
	}
	if ds.Attachment.(*Info).AttestationChallenge != cs.Attachment.(*Info).AttestationChallenge {
		t.Fatal("attestation challenges differ")
	}

	// The keys must agree: exchange an IM message over the new session.
	e := &echo{}
	dev.M.Register(message.ProtocolInteractionModel, func(*exchange.Exchange) exchange.Delegate { return e })
	var reply []byte
	ex, err := ctl.M.NewExchange(cs, delegateFunc(func(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
		reply = bytes.Clone(msg.Payload)
		ex.Close(now)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Send(w.Now, message.ProtocolInteractionModel, 2, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	w.Advance(time.Second)
	if string(reply) != "hello" || len(e.got) != 1 {
		t.Fatalf("echo over PASE session: reply=%q got=%q", reply, e.got)
	}
}

type delegateFunc func(now time.Time, ex *exchange.Exchange, msg exchange.Message)

func (f delegateFunc) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	f(now, ex, msg)
}
func (f delegateFunc) OnError(time.Time, *exchange.Exchange, error) {}

func TestWrongPasscode(t *testing.T) {
	w := simnet.New(t)
	dev := newDevice(t, w, 5540)
	ctl := w.Node(5550)
	res := pair(t, w, ctl, dev.Addr, 12345679)
	w.Advance(time.Second)

	// The commissioner detects the mismatch on cB and reports failure.
	if !res.done || !errors.Is(res.err, ErrConfirm) {
		t.Fatalf("commissioner: done=%v err=%v", res.done, res.err)
	}
	if len(dev.established) != 0 || len(dev.failures) != 1 {
		t.Fatalf("device: established=%d failures=%v", len(dev.established), dev.failures)
	}
	var se *securechannel.StatusError
	if !errors.As(dev.failures[0], &se) {
		t.Fatalf("device failure = %v, want peer status report", dev.failures[0])
	}
	// The device is free for the next attempt.
	res = pair(t, w, ctl, dev.Addr, testPasscode)
	w.Advance(time.Second)
	if res.err != nil || len(dev.established) != 1 {
		t.Fatalf("retry: err=%v established=%d", res.err, len(dev.established))
	}
}

// A commissioner that sends a wrong cA is caught by the device.
func TestDeviceRejectsBadPake3(t *testing.T) {
	w := simnet.New(t)
	dev := newDevice(t, w, 5540)
	ctl := w.Node(5550)
	w.Drop = func(p simnet.Packet) bool {
		// Flip the last byte of cA in flight (before end-of-container).
		if isOpcode(p, securechannel.OpPASEPake3) {
			p.Data[len(p.Data)-2] ^= 1
		}
		return false
	}
	res := pair(t, w, ctl, dev.Addr, testPasscode)
	w.Advance(time.Second)
	if !res.done || res.err == nil {
		t.Fatalf("commissioner: done=%v err=%v", res.done, res.err)
	}
	if len(dev.established) != 0 || len(dev.failures) != 1 || !errors.Is(dev.failures[0], ErrConfirm) {
		t.Fatalf("device: established=%d failures=%v", len(dev.established), dev.failures)
	}
	if dev.r.failed != 1 {
		t.Fatalf("failed attempts = %d", dev.r.failed)
	}
}

func TestWindowClosed(t *testing.T) {
	w := simnet.New(t)
	dev := newDevice(t, w, 5540)
	dev.r.CloseWindow()
	ctl := w.Node(5550)
	res := pair(t, w, ctl, dev.Addr, testPasscode)
	w.Advance(time.Second)
	if !res.done || res.err == nil || len(dev.established) != 0 {
		t.Fatalf("done=%v err=%v established=%d", res.done, res.err, len(dev.established))
	}
}

func TestBusy(t *testing.T) {
	w := simnet.New(t)
	dev := newDevice(t, w, 5540)
	c1, c2 := w.Node(5550), w.Node(5551)

	// c1 stalls after PBKDFParamResponse: drop its Pake1.
	stall := true
	w.Drop = func(p simnet.Packet) bool {
		return stall && p.From == c1.Addr && isOpcode(p, securechannel.OpPASEPake1)
	}
	r1 := pair(t, w, c1, dev.Addr, testPasscode)
	w.Deliver()
	r2 := pair(t, w, c2, dev.Addr, testPasscode)
	w.Deliver()
	var se *securechannel.StatusError
	if !r2.done || !errors.As(r2.err, &se) || se.Report.ProtocolCode != securechannel.CodeBusy {
		t.Fatalf("second commissioner: done=%v err=%v", r2.done, r2.err)
	}
	stall = false
	w.Advance(time.Minute)
	if r1.err != nil || len(dev.established) != 1 {
		t.Fatalf("first commissioner after retransmit: done=%v err=%v", r1.done, r1.err)
	}
}

func isOpcode(p simnet.Packet, op uint8) bool {
	var h message.Header
	n, err := h.Decode(p.Data)
	if err != nil || h.IsEncrypted() {
		return false
	}
	var ph message.ProtocolHeader
	_, err = ph.Decode(p.Data[n:])
	return err == nil && ph.ProtocolID == message.ProtocolSecureChannel && ph.Opcode == op
}
