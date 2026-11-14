package im_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// bigCluster has many large attributes to force chunked reports.
type bigCluster struct{ im.ClusterBase }

func (bigCluster) ID() uint32       { return 0xFFF1FC01 }
func (bigCluster) Revision() uint16 { return 1 }
func (bigCluster) Attributes() []uint32 {
	return []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
}
func (bigCluster) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if attr == 11 {
		w.PutString(tag, strings.Repeat("y", 1500)) // never fits
		return im.Success
	}
	w.PutString(tag, strings.Repeat("x", 200))
	return im.Success
}

type fixture struct {
	t        *testing.T
	w        *simnet.World
	dev, ctl *simnet.Node
	cs       *exchange.Session // controller's session to the device
	ds       *exchange.Session // device's session to the controller
	server   *im.Server
	node     *im.Node
	onoff    *clusters.OnOff
	basic    *clusters.BasicInformation
	failSafe *clusters.FailSafe
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, w: simnet.New(t)}
	f.dev, f.ctl = f.w.Node(5540), f.w.Node(5550)
	f.node = im.NewNode(1)
	f.failSafe = &clusters.FailSafe{}
	f.basic = &clusters.BasicInformation{VendorName: "Acme", VendorID: 0xFFF1, ProductName: "Lamp", ProductID: 0x8000}
	f.onoff = &clusters.OnOff{}
	root := f.node.AddEndpoint(0, clusters.DeviceTypeRootNode)
	f.node.AddCluster(root, clusters.Descriptor{}, f.basic, clusters.NewGeneralCommissioning(f.failSafe))
	ep1 := f.node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	f.node.AddCluster(ep1, clusters.Descriptor{}, f.onoff)
	ep2 := f.node.AddEndpoint(2)
	f.node.AddCluster(ep2, bigCluster{})
	f.server = im.NewServer(f.dev.M, f.node)
	f.dev.Attach(f.dev.M.HandlePacket, func(now time.Time) time.Time {
		a, b := f.dev.M.Poll(now), f.server.Poll(now)
		if a.IsZero() || (!b.IsZero() && b.Before(a)) {
			return b
		}
		return a
	})

	k1, k2 := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	ida, _ := f.ctl.M.AllocateSessionID()
	idb, _ := f.dev.M.AllocateSessionID()
	var err error
	f.cs, err = f.ctl.M.NewSecureSession(f.w.Now, exchange.SecureSessionParams{Peer: f.dev.Addr,
		LocalSessionID: ida, PeerSessionID: idb, EncryptKey: k1, DecryptKey: k2})
	if err != nil {
		t.Fatal(err)
	}
	if f.ds, err = f.dev.M.NewSecureSession(f.w.Now, exchange.SecureSessionParams{Peer: f.ctl.Addr,
		LocalSessionID: idb, PeerSessionID: ida, EncryptKey: k2, DecryptKey: k1,
		AuthMode: exchange.AuthCASE, FabricIndex: 1}); err != nil {
		t.Fatal(err)
	}
	return f
}

// client collects the responses on one exchange, acknowledging report
// chunks with StatusResponse.
type client struct {
	msgs []exchange.Message
}

func (c *client) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	msg.Payload = bytes.Clone(msg.Payload)
	c.msgs = append(c.msgs, msg)
	if msg.Opcode == im.OpReportData {
		if rd, err := im.DecodeReportData(msg.Payload); err == nil && rd.MoreChunks {
			ex.Send(now, message.ProtocolInteractionModel, im.OpStatusResponse, im.EncodeStatusResponse(im.Success))
			return
		}
	}
	if msg.Opcode != im.OpStatusResponse || len(c.msgs) > 1 {
		ex.Close(now)
	}
}
func (c *client) OnError(time.Time, *exchange.Exchange, error) {}

// request sends payloads on one exchange, one after the previous answer,
// and returns all messages received.
func (f *fixture) request(op uint8, payload []byte) []exchange.Message {
	c := &client{}
	ex, err := f.ctl.M.NewExchange(f.cs, c)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := ex.Send(f.w.Now, message.ProtocolInteractionModel, op, payload); err != nil {
		f.t.Fatal(err)
	}
	f.w.Advance(time.Second)
	return c.msgs
}

func (f *fixture) read(paths ...im.AttributePath) []im.AttributeReport {
	var out []im.AttributeReport
	msgs := f.request(im.OpReadRequest, im.EncodeReadRequest(paths, true))
	for i, m := range msgs {
		if m.Opcode != im.OpReportData {
			f.t.Fatalf("message %d: opcode %#x", i, m.Opcode)
		}
		rd, err := im.DecodeReportData(m.Payload)
		if err != nil {
			f.t.Fatal(err)
		}
		if last := i == len(msgs)-1; rd.MoreChunks == last || rd.SuppressResponse != last {
			f.t.Fatalf("chunk %d/%d: more=%v suppress=%v", i, len(msgs), rd.MoreChunks, rd.SuppressResponse)
		}
		out = append(out, rd.Reports...)
	}
	return out
}

func path(ep uint16, cl, attr uint32) im.AttributePath {
	return im.AttributePath{Endpoint: ep, Cluster: cl, Attribute: attr}
}

func value(t *testing.T, raw []byte) *tlv.Reader {
	r := tlv.NewReader(raw)
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReadConcrete(t *testing.T) {
	f := newFixture(t)
	reps := f.read(
		path(0, clusters.IDBasicInformation, 1),
		path(0, clusters.IDBasicInformation, 2),
		path(9, clusters.IDBasicInformation, 1),
		path(0, clusters.IDOnOff, 0),
		path(0, clusters.IDBasicInformation, 0x99),
		path(1, clusters.IDOnOff, im.AttrAttributeList),
	)
	if len(reps) != 6 {
		t.Fatalf("got %d reports", len(reps))
	}
	if s, _ := value(t, reps[0].Data).String(); s != "Acme" || reps[0].Path.Attribute != 1 {
		t.Fatalf("vendor name = %q", s)
	}
	if v, _ := value(t, reps[1].Data).Uint(); v != 0xFFF1 {
		t.Fatalf("vendor id = %#x", v)
	}
	for i, want := range []im.Status{im.UnsupportedEndpoint, im.UnsupportedCluster, im.UnsupportedAttribute} {
		if reps[2+i].Status != want || reps[2+i].Data != nil {
			t.Errorf("report %d: status %#x, want %#x", 2+i, reps[2+i].Status, want)
		}
	}
	var ids []uint64
	r := value(t, reps[5].Data)
	r.EnterContainer()
	for r.Next() == nil {
		v, _ := r.Uint()
		ids = append(ids, v)
	}
	if len(ids) != 6 || ids[0] != 0 || ids[5] != im.AttrClusterRevision {
		t.Fatalf("attribute list = %x", ids)
	}
}

func TestReadWildcardChunked(t *testing.T) {
	f := newFixture(t)
	var msgs int
	f.w.Drop = func(p simnet.Packet) bool {
		if p.From == f.dev.Addr && len(p.Data) > message.MaxPacketSize {
			t.Errorf("packet of %d bytes", len(p.Data))
		}
		msgs++
		return false
	}
	reps := f.read(im.AttributePath{AnyEndpoint: true, AnyCluster: true, AnyAttribute: true})
	// endpoint 0: descriptor 4+5, basic 15+5, gencomm 5+5; endpoint 1:
	// descriptor 4+5, onoff 1+5; endpoint 2: big 12+5.
	if want := 9 + 20 + 10 + 9 + 6 + 17; len(reps) != want {
		t.Fatalf("got %d reports, want %d", len(reps), want)
	}
	last := reps[len(reps)-6]
	if last.Path.Endpoint != 2 || last.Path.Attribute != 11 || last.Status != im.ResourceExhausted {
		t.Fatalf("oversized attribute: %+v", last)
	}
	if msgs < 6 {
		t.Fatalf("expected a chunked report, saw %d packets", msgs)
	}
	// Wildcard endpoint, concrete cluster: only endpoints that have it.
	reps = f.read(im.AttributePath{AnyEndpoint: true, Cluster: clusters.IDOnOff, Attribute: 0})
	if len(reps) != 1 || reps[0].Path.Endpoint != 1 {
		t.Fatalf("onoff wildcard: %+v", reps)
	}
	// Descriptor parts list of the root holds the other endpoints.
	reps = f.read(path(0, clusters.IDDescriptor, 3))
	r := value(t, reps[0].Data)
	r.EnterContainer()
	var parts []uint64
	for r.Next() == nil {
		v, _ := r.Uint()
		parts = append(parts, v)
	}
	if len(parts) != 2 || parts[0] != 1 || parts[1] != 2 {
		t.Fatalf("parts list = %v", parts)
	}
}

func (f *fixture) invoke(p im.CommandPath, timed bool, fields func(w *tlv.Writer)) im.InvokeResult {
	msgs := f.request(im.OpInvokeRequest, im.EncodeInvokeRequest(p, timed, fields))
	if len(msgs) != 1 || msgs[0].Opcode != im.OpInvokeResponse {
		f.t.Fatalf("invoke: %d messages %+v", len(msgs), msgs)
	}
	res, err := im.DecodeInvokeResponse(msgs[0].Payload)
	if err != nil || len(res) != 1 {
		f.t.Fatalf("invoke response: %v %v", res, err)
	}
	return res[0]
}

func TestInvoke(t *testing.T) {
	f := newFixture(t)
	v0, _ := f.node.DataVersion(1, clusters.IDOnOff)
	res := f.invoke(im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 2}, false, nil)
	if res.Status != im.Success || res.Fields != nil || !f.onoff.On {
		t.Fatalf("toggle: %+v on=%v", res, f.onoff.On)
	}
	if v1, _ := f.node.DataVersion(1, clusters.IDOnOff); v1 == v0 {
		t.Fatal("data version unchanged")
	}
	if res := f.invoke(im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 0x40}, false, nil); res.Status != im.UnsupportedCommand {
		t.Fatalf("unknown command: %+v", res)
	}
	if res := f.invoke(im.CommandPath{Endpoint: 5, Cluster: clusters.IDOnOff, Command: 0}, false, nil); res.Status != im.UnsupportedEndpoint {
		t.Fatalf("unknown endpoint: %+v", res)
	}

	// ArmFailSafe returns a response command.
	res = f.invoke(im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: 0}, false, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), 60)
		w.PutUint(tlv.ContextTag(1), 7)
	})
	if res.Path.Command != 1 || res.Fields == nil {
		t.Fatalf("ArmFailSafe: %+v", res)
	}
	r := value(t, res.Fields)
	r.EnterContainer()
	r.Next()
	if code, _ := r.Uint(); code != 0 || !f.failSafe.Armed(f.w.Now) {
		t.Fatalf("ArmFailSafe error code %d", code)
	}
	expired := false
	f.failSafe.OnExpire = append(f.failSafe.OnExpire, func(time.Time) { expired = true })
	f.failSafe.Poll(f.w.Now.Add(58 * time.Second))
	if expired {
		t.Fatal("expired early")
	}
	f.failSafe.Poll(f.w.Now.Add(61 * time.Second))
	if !expired {
		t.Fatal("did not expire")
	}
	// Missing fields are rejected.
	res = f.invoke(im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: 0}, false, nil)
	if res.Status != im.InvalidCommand {
		t.Fatalf("ArmFailSafe without fields: %+v", res)
	}
}

func TestTimed(t *testing.T) {
	f := newFixture(t)
	toggle := im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 2}

	// TimedRequest flag without a preceding TimedRequest.
	msgs := f.request(im.OpInvokeRequest, im.EncodeInvokeRequest(toggle, true, nil))
	if st, _ := im.DecodeStatusResponse(msgs[0].Payload); msgs[0].Opcode != im.OpStatusResponse || st != im.TimedRequestMismatch {
		t.Fatalf("got opcode %#x status %#x", msgs[0].Opcode, st)
	}

	// TimedRequest followed by a timed invoke on the same exchange.
	run := func(delay time.Duration) []exchange.Message {
		c := &client{}
		ex, _ := f.ctl.M.NewExchange(f.cs, c)
		ex.Send(f.w.Now, message.ProtocolInteractionModel, im.OpTimedRequest, im.EncodeTimedRequest(500))
		f.w.Advance(delay)
		ex.Send(f.w.Now, message.ProtocolInteractionModel, im.OpInvokeRequest, im.EncodeInvokeRequest(toggle, true, nil))
		f.w.Advance(time.Second)
		return c.msgs
	}
	msgs = run(100 * time.Millisecond)
	if len(msgs) != 2 || msgs[1].Opcode != im.OpInvokeResponse || !f.onoff.On {
		t.Fatalf("timed invoke: %+v on=%v", msgs, f.onoff.On)
	}
	msgs = run(time.Second)
	if st, _ := im.DecodeStatusResponse(msgs[len(msgs)-1].Payload); st != im.Timeout || !f.onoff.On {
		t.Fatalf("late timed invoke: status %#x", st)
	}
}

func TestWrite(t *testing.T) {
	f := newFixture(t)
	write := func(p im.AttributePath, val func(w *tlv.Writer, tag tlv.Tag)) im.Status {
		msgs := f.request(im.OpWriteRequest, im.EncodeWriteRequest(p, false, val))
		if len(msgs) != 1 || msgs[0].Opcode != im.OpWriteResponse {
			t.Fatalf("write: %+v", msgs)
		}
		reps, err := im.DecodeWriteResponse(msgs[0].Payload)
		if err != nil || len(reps) != 1 {
			t.Fatalf("write response: %+v %v", reps, err)
		}
		return reps[0].Status
	}
	str := func(s string) func(w *tlv.Writer, tag tlv.Tag) {
		return func(w *tlv.Writer, tag tlv.Tag) { w.PutString(tag, s) }
	}
	if st := write(path(0, clusters.IDBasicInformation, 5), str("kitchen")); st != im.Success || f.basic.NodeLabel != "kitchen" {
		t.Fatalf("write node label: %#x", st)
	}
	if st := write(path(0, clusters.IDBasicInformation, 5), str(strings.Repeat("z", 33))); st != im.ConstraintError {
		t.Fatalf("long node label: %#x", st)
	}
	if st := write(path(0, clusters.IDBasicInformation, 1), str("Evil")); st != im.UnsupportedWrite {
		t.Fatalf("read-only attribute: %#x", st)
	}
	if st := write(path(0, clusters.IDBasicInformation, im.AttrClusterRevision), func(w *tlv.Writer, tag tlv.Tag) { w.PutUint(tag, 9) }); st != im.UnsupportedWrite {
		t.Fatalf("global attribute: %#x", st)
	}
	reps := f.read(path(0, clusters.IDBasicInformation, 5))
	if s, _ := value(t, reps[0].Data).String(); s != "kitchen" {
		t.Fatalf("read back %q", s)
	}
}

func TestUnknownOpcode(t *testing.T) {
	f := newFixture(t)
	msgs := f.request(0x77, []byte{0x15, 0x18})
	if st, _ := im.DecodeStatusResponse(msgs[0].Payload); len(msgs) != 1 || st != im.InvalidAction {
		t.Fatalf("got %+v", msgs)
	}
}

func FuzzServer(f *testing.F) {
	f.Add(uint8(im.OpReadRequest), im.EncodeReadRequest([]im.AttributePath{{AnyEndpoint: true, AnyCluster: true, AnyAttribute: true}}, false))
	f.Add(uint8(im.OpInvokeRequest), im.EncodeInvokeRequest(im.CommandPath{Endpoint: 1, Cluster: 6, Command: 2}, false, nil))
	f.Add(uint8(im.OpWriteRequest), im.EncodeWriteRequest(path(0, 0x28, 5), false, func(w *tlv.Writer, tag tlv.Tag) { w.PutString(tag, "x") }))
	f.Add(uint8(im.OpTimedRequest), im.EncodeTimedRequest(100))
	f.Add(uint8(im.OpSubscribeRequest), im.EncodeSubscribeRequest([]im.AttributePath{{AnyEndpoint: true, AnyCluster: true, AnyAttribute: true}}, 0, 10, false, true))
	f.Fuzz(func(t *testing.T, op uint8, payload []byte) {
		fx := newFixture(&testing.T{})
		c := &client{}
		ex, err := fx.ctl.M.NewExchange(fx.cs, c)
		if err != nil {
			t.Fatal(err)
		}
		if ex.Send(fx.w.Now, message.ProtocolInteractionModel, op, payload) != nil {
			return
		}
		fx.w.Advance(time.Second)
		fx.onoff.Set(fx.node, 1, true) // exercise subscription reports
		fx.w.Advance(time.Minute)
	})
}
