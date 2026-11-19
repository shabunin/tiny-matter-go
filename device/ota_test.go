package device_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/bdx"
	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/ota"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const providerNode = 0x1B669 // the test controller

// memImages is an ImageStore in memory.
type memImages struct {
	header    *ota.Header
	data      []byte
	done      bool
	aborted   bool
	applied   bool
	beginErr  error
	writeErr  error
	finishErr error
	applyErr  error
}

func (m *memImages) Begin(h *ota.Header) error {
	if m.beginErr != nil {
		return m.beginErr
	}
	m.header, m.data, m.done, m.aborted = h, nil, false, false
	return nil
}
func (m *memImages) Write(p []byte) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.data = append(m.data, p...)
	return nil
}
func (m *memImages) Finish() error {
	if m.finishErr != nil {
		return m.finishErr
	}
	m.done = true
	return nil
}
func (m *memImages) Abort() { m.aborted = true }
func (m *memImages) Apply() error {
	if m.applyErr != nil {
		return m.applyErr
	}
	m.applied = true
	return nil
}

// provider serves one image from the test controller.
type provider struct {
	image       []byte
	version     uint32
	token       []byte
	busyLeft    int // QueryImage responses to answer Busy before UpdateAvailable
	awaitLeft   int // ApplyUpdate responses to answer AwaitNextAction before Proceed
	discontinue bool
	queries     int
	applies     int
	notified    []uint32
	served      []error
}

// attach makes the harness controller an OTA provider.
func (p *provider) attach(h *harness) {
	n := im.NewNode(1)
	ep := n.AddEndpoint(0)
	n.AddCluster(ep, &clusters.OTAProvider{
		QueryImage: func(ctx *im.Context, q *clusters.QueryImage) clusters.QueryImageResponse {
			p.queries++
			if p.busyLeft > 0 {
				p.busyLeft--
				return clusters.QueryImageResponse{Status: clusters.OTABusy, DelayedActionTime: 10}
			}
			if q.SoftwareVersion >= p.version {
				return clusters.QueryImageResponse{Status: clusters.OTANotAvailable}
			}
			return clusters.QueryImageResponse{Status: clusters.OTAUpdateAvailable,
				ImageURI: clusters.BDXURI(providerNode, "light.ota"), SoftwareVersion: p.version,
				SoftwareVersionString: "2.0", UpdateToken: p.token}
		},
		ApplyUpdate: func(ctx *im.Context, token []byte, version uint32) (uint8, uint32) {
			p.applies++
			if !bytes.Equal(token, p.token) || version != p.version {
				return clusters.OTAApplyDiscontinue, 0
			}
			if p.discontinue {
				return clusters.OTAApplyDiscontinue, 0
			}
			if p.awaitLeft > 0 {
				p.awaitLeft--
				return clusters.OTAApplyAwaitNextAction, 10
			}
			return clusters.OTAApplyProceed, 0
		},
		NotifyUpdateApplied: func(ctx *im.Context, token []byte, version uint32) {
			if bytes.Equal(token, p.token) {
				p.notified = append(p.notified, version)
			}
		},
	})
	im.NewServer(h.ctl.M, n)
	s := &bdx.Sender{
		Open: func(ex *exchange.Exchange, d []byte) (io.ReaderAt, int64, uint16) {
			if string(d) != "light.ota" {
				return nil, 0, bdx.StatusFileDesignatorUnknown
			}
			return bytes.NewReader(p.image), int64(len(p.image)), 0
		},
		Done: func(now time.Time, ex *exchange.Exchange, err error) { p.served = append(p.served, err) },
	}
	h.ctl.M.Register(message.ProtocolBDX, s.Accept)
}

func otaHarness(t *testing.T, store storage.Store, images *memImages, version uint32) *harness {
	return newHarnessConfig(t, store, false, func(cfg *device.Config) {
		cfg.Updates = images
		cfg.Basic.SoftwareVersion = version
		cfg.Basic.SoftwareVersionString = "v"
		cfg.Log = func(m string) { t.Log(m) }
	})
}

func announce(h *harness, s *exchange.Session) {
	h.t.Helper()
	res := h.invoke(s, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOTARequestor, Command: clusters.CmdAnnounceOTAProvider},
		func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), providerNode)
			w.PutUint(tlv.ContextTag(1), 0xFFF1)
			w.PutUint(tlv.ContextTag(2), clusters.OTAAnnounceUpdateAvailable)
			w.PutUint(tlv.ContextTag(4), 0)
		})
	if res.Status != im.Success {
		h.t.Fatalf("AnnounceOTAProvider: %#x", res.Status)
	}
}

func testImage(t *testing.T, product uint16, payload []byte) []byte {
	img, err := ota.Create(ota.Header{VendorID: 0xFFF1, ProductID: product, SoftwareVersion: 2, SoftwareVersionString: "2.0"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// ctlResponder lets the device open CASE sessions to the controller.
func ctlResponder(t *testing.T, h *harness, f *fabric.Fabric) {
	table := &fabric.Table{}
	if _, err := table.Restore(1, f.RCAC, f.ICAC, f.NOC, f.Key, f.IPK[:], f.VendorID, ""); err != nil {
		t.Fatal(err)
	}
	casesession.NewResponder(h.ctl.M, securechannel.NewDispatcher(h.ctl.M), casesession.ResponderConfig{Fabrics: table, Rand: rand.Reader})
}

func TestOTAUpdate(t *testing.T) {
	store := &storage.Memory{}
	images := &memImages{}
	h := otaHarness(t, store, images, 1)
	ctlF, s := h.commission()
	payload := make([]byte, 5000)
	rand.Read(payload)
	p := &provider{image: testImage(t, 0x8000, payload), version: 2, token: bytes.Repeat([]byte{7}, 32)}
	p.attach(h)

	announce(h, s)
	h.w.Advance(30 * time.Second)
	if p.queries != 1 || p.applies != 1 || len(p.served) != 1 || p.served[0] != nil {
		t.Fatalf("provider saw %d queries, %d applies, transfers %v", p.queries, p.applies, p.served)
	}
	if !images.done || !images.applied || !bytes.Equal(images.data, payload) {
		t.Fatalf("image store: done %v applied %v, %d bytes", images.done, images.applied, len(images.data))
	}
	if st := h.dev.OTA.State(); st != clusters.OTAStateApplying {
		t.Fatalf("state %d after apply, want Applying", st)
	}

	// "Restart" into version 2: VersionApplied, back to Idle, and the
	// provider is told, over a CASE session the device opens.
	h2 := otaHarness(t, store, &memImages{}, 2)
	p.attach(h2)
	ctlResponder(t, h2, ctlF)
	if st := h2.dev.OTA.State(); st != clusters.OTAStateApplying {
		t.Fatalf("restored state %d, want Applying", st)
	}
	h2.w.Advance(30 * time.Second)
	if st := h2.dev.OTA.State(); st != clusters.OTAStateIdle {
		t.Fatalf("state %d after restart, want Idle", st)
	}
	if len(p.notified) != 1 || p.notified[0] != 2 {
		t.Fatalf("provider notified with %v", p.notified)
	}
	if r := h2.dev.Diagnostics.BootReason; r != clusters.BootSoftwareUpdate {
		t.Fatalf("boot reason %d after the update, want SoftwareUpdateCompleted", r)
	}

	// The update is finished: another restart notifies nobody.
	h3 := otaHarness(t, store, &memImages{}, 2)
	p.attach(h3)
	ctlResponder(t, h3, ctlF)
	h3.w.Advance(30 * time.Second)
	if len(p.notified) != 1 || h3.dev.OTA.State() != clusters.OTAStateIdle {
		t.Fatalf("notified again: %v", p.notified)
	}
}

func TestOTARollback(t *testing.T) {
	store := &storage.Memory{}
	images := &memImages{}
	h := otaHarness(t, store, images, 1)
	ctlF, s := h.commission()
	p := &provider{image: testImage(t, 0x8000, []byte("new firmware")), version: 2, token: bytes.Repeat([]byte{7}, 32)}
	p.attach(h)
	announce(h, s)
	h.w.Advance(30 * time.Second)
	if !images.applied {
		t.Fatal("not applied")
	}
	// The new image failed and the old one runs again.
	h2 := otaHarness(t, store, &memImages{}, 1)
	p.attach(h2)
	ctlResponder(t, h2, ctlF)
	h2.w.Advance(30 * time.Second)
	if h2.dev.OTA.State() != clusters.OTAStateIdle || len(p.notified) != 0 {
		t.Fatalf("after rollback: state %d, notified %v", h2.dev.OTA.State(), p.notified)
	}
}

func TestOTAWrongImage(t *testing.T) {
	images := &memImages{}
	h := otaHarness(t, nil, images, 1)
	_, s := h.commission()
	p := &provider{image: testImage(t, 0x8001, []byte("someone else's firmware")), version: 2, token: bytes.Repeat([]byte{7}, 32)}
	p.attach(h)
	announce(h, s)
	h.w.Advance(30 * time.Second)
	var e *bdx.Error
	if len(p.served) != 1 || !errors.As(p.served[0], &e) || e.Code != bdx.StatusBadMessageContents {
		t.Fatalf("transfer ended with %v, want BadMessageContents", p.served)
	}
	if images.header != nil || images.applied || p.applies != 0 || h.dev.OTA.State() != clusters.OTAStateIdle {
		t.Fatalf("wrong image accepted: %+v, state %d", images, h.dev.OTA.State())
	}
}

// TestOTAResolveProvider: after a restart the device has no session to its
// default provider and no address for it; it finds it with DNS-SD.
func TestOTAResolveProvider(t *testing.T) {
	store := &storage.Memory{}
	h := otaHarness(t, store, &memImages{}, 1)
	ctlF, s := h.commission()
	p := &provider{image: testImage(t, 0x8000, []byte("x")), version: 1, token: bytes.Repeat([]byte{7}, 32)}
	p.attach(h)
	path := im.AttributePath{Endpoint: 0, Cluster: clusters.IDOTARequestor, Attribute: 0}
	if st := h.write(s, path, func(w *tlv.Writer, tag tlv.Tag) {
		w.StartArray(tag)
		w.StartStruct(tlv.Anonymous)
		w.PutUint(tlv.ContextTag(1), providerNode)
		w.PutUint(tlv.ContextTag(2), 0)
		w.EndContainer()
		w.EndContainer()
	}); st != im.Success {
		t.Fatalf("write default provider: %#x", st)
	}
	h.w.Advance(5 * time.Second) // saved

	var h2 *harness
	lookups := 0
	h2 = newHarnessConfig(t, store, false, func(cfg *device.Config) {
		cfg.Updates = &memImages{}
		cfg.Basic.SoftwareVersion = 1
		cfg.Log = func(m string) { t.Log(m) }
		cfg.Resolve = func(now time.Time, cfid [8]byte, node uint64) (exchange.Addr, bool) {
			lookups++
			if cfid != ctlF.CompressedFabricID || node != providerNode {
				t.Errorf("resolving %x node %#x", cfid, node)
			}
			return h2.ctl.Addr, lookups > 2 // the answer takes a while
		}
	})
	p.attach(h2)
	ctlResponder(t, h2, ctlF)
	if !h2.dev.CheckForUpdate(h2.w.Now) {
		t.Fatal("no query started")
	}
	h2.w.Advance(10 * time.Second)
	if p.queries != 1 || lookups != 3 || h2.dev.OTA.State() != clusters.OTAStateIdle {
		t.Fatalf("%d queries after %d lookups, state %d", p.queries, lookups, h2.dev.OTA.State())
	}
}

func TestOTADefaultProviders(t *testing.T) {
	images := &memImages{}
	h := otaHarness(t, nil, images, 1)
	_, s := h.commission()
	p := &provider{image: testImage(t, 0x8000, []byte("x")), version: 1, token: bytes.Repeat([]byte{7}, 32)}
	p.attach(h)
	path := im.AttributePath{Endpoint: 0, Cluster: clusters.IDOTARequestor, Attribute: 0}
	loc := func(w *tlv.Writer, tag tlv.Tag) {
		w.StartStruct(tag)
		w.PutUint(tlv.ContextTag(1), providerNode)
		w.PutUint(tlv.ContextTag(2), 0)
		w.EndContainer()
	}
	two := func(w *tlv.Writer, tag tlv.Tag) {
		w.StartArray(tag)
		loc(w, tlv.Anonymous)
		loc(w, tlv.Anonymous)
		w.EndContainer()
	}
	if st := h.write(s, path, two); st != im.ConstraintError {
		t.Fatalf("two providers for a fabric: %#x", st)
	}
	one := func(w *tlv.Writer, tag tlv.Tag) {
		w.StartArray(tag)
		loc(w, tlv.Anonymous)
		w.EndContainer()
	}
	if st := h.write(s, path, one); st != im.Success || len(h.dev.OTA.Providers) != 1 {
		t.Fatalf("write default provider: %#x", st)
	}
	// Version 1 is current: the provider has nothing newer.
	if !h.dev.CheckForUpdate(h.w.Now) {
		t.Fatal("no query started")
	}
	h.w.Advance(10 * time.Second)
	if p.queries != 1 || h.dev.OTA.State() != clusters.OTAStateIdle || images.header != nil {
		t.Fatalf("%d queries, state %d", p.queries, h.dev.OTA.State())
	}
}

func TestOTACorruptDigest(t *testing.T) {
	images := &memImages{}
	h := otaHarness(t, nil, images, 1)
	_, s := h.commission()
	payload := make([]byte, 3000)
	rand.Read(payload)
	img := testImage(t, 0x8000, payload)
	// Flip a byte inside the payload after the header so SHA-256 verification fails.
	img[len(img)-10] ^= 0x55
	p := &provider{image: img, version: 2, token: bytes.Repeat([]byte{9}, 32)}
	p.attach(h)

	announce(h, s)
	h.w.Advance(30 * time.Second)
	if !images.aborted || images.applied || images.done {
		t.Fatalf("corrupt digest store state: %+v", images)
	}
	if p.applies != 0 || h.dev.OTA.State() != clusters.OTAStateIdle {
		t.Fatalf("applies=%d state=%d, want 0 and Idle", p.applies, h.dev.OTA.State())
	}
}

func TestOTAPacketLoss(t *testing.T) {
	images := &memImages{}
	h := otaHarness(t, nil, images, 1)
	_, s := h.commission()
	payload := make([]byte, 8192)
	rand.Read(payload)
	p := &provider{image: testImage(t, 0x8000, payload), version: 2, token: bytes.Repeat([]byte{3}, 32)}
	p.attach(h)

	// Drop 1 out of every 5 packets during the BDX download; MRP must recover.
	seen := 0
	h.w.Drop = func(pk simnet.Packet) bool {
		seen++
		return seen%5 == 0
	}
	announce(h, s)
	h.w.Advance(90 * time.Second)
	h.w.Drop = nil
	if !images.done || !images.applied || !bytes.Equal(images.data, payload) {
		t.Fatalf("packet-loss OTA failed: done=%v applied=%v got=%d bytes", images.done, images.applied, len(images.data))
	}
}

func TestOTAApplyDiscontinue(t *testing.T) {
	store := &storage.Memory{}
	images := &memImages{}
	h := otaHarness(t, store, images, 1)
	_, s := h.commission()
	p := &provider{image: testImage(t, 0x8000, []byte("candidate")), version: 2, token: bytes.Repeat([]byte{4}, 32), discontinue: true}
	p.attach(h)

	announce(h, s)
	h.w.Advance(30 * time.Second)
	if !images.done || !images.aborted || images.applied {
		t.Fatalf("discontinue store state: done=%v aborted=%v applied=%v", images.done, images.aborted, images.applied)
	}
	if h.dev.OTA.State() != clusters.OTAStateIdle {
		t.Fatalf("state=%d, want Idle", h.dev.OTA.State())
	}
}

func TestOTAApplyAwaitNextAction(t *testing.T) {
	images := &memImages{}
	h := otaHarness(t, nil, images, 1)
	_, s := h.commission()
	p := &provider{image: testImage(t, 0x8000, []byte("delayed apply")), version: 2, token: bytes.Repeat([]byte{5}, 32), awaitLeft: 1}
	p.attach(h)

	announce(h, s)
	h.w.Advance(30 * time.Second)
	if images.applied || h.dev.OTA.State() != clusters.OTAStateDelayedOnApply {
		t.Fatalf("expected DelayedOnApply, got state=%d applied=%v", h.dev.OTA.State(), images.applied)
	}
	// Advance past otaBusyRetry (2 minutes).
	h.w.Advance(3 * time.Minute)
	if !images.applied || p.applies != 2 {
		t.Fatalf("after delay: applied=%v applies=%d, want true and 2", images.applied, p.applies)
	}
}

func TestOTAProviderBusyRetries(t *testing.T) {
	images := &memImages{}
	h := otaHarness(t, nil, images, 1)
	_, s := h.commission()
	p := &provider{image: testImage(t, 0x8000, []byte("after busy")), version: 2, token: bytes.Repeat([]byte{6}, 32), busyLeft: 2}
	p.attach(h)

	announce(h, s)
	h.w.Advance(30 * time.Second)
	if h.dev.OTA.State() != clusters.OTAStateDelayedOnQuery || p.queries != 1 {
		t.Fatalf("after first Busy: state=%d queries=%d", h.dev.OTA.State(), p.queries)
	}
	h.w.Advance(6 * time.Minute)
	if p.queries != 3 || !images.applied {
		t.Fatalf("after retries: queries=%d applied=%v, want 3 and true", p.queries, images.applied)
	}
}

func TestOTAImageStoreErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*memImages)
	}{
		{"begin", func(m *memImages) { m.beginErr = errors.New("flash busy") }},
		{"write", func(m *memImages) { m.writeErr = errors.New("flash write failed") }},
		{"finish", func(m *memImages) { m.finishErr = errors.New("flash crc mismatch") }},
		{"apply", func(m *memImages) { m.applyErr = errors.New("restart failed") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			images := &memImages{}
			tc.setup(images)
			h := otaHarness(t, nil, images, 1)
			_, s := h.commission()
			p := &provider{image: testImage(t, 0x8000, bytes.Repeat([]byte{0xAB}, 2500)), version: 2, token: bytes.Repeat([]byte{8}, 32)}
			p.attach(h)

			announce(h, s)
			h.w.Advance(30 * time.Second)
			if h.dev.OTA.State() != clusters.OTAStateIdle {
				t.Fatalf("state=%d after %s error, want Idle", h.dev.OTA.State(), tc.name)
			}
			if images.applied {
				t.Fatalf("image applied despite %s error", tc.name)
			}
			if tc.name != "begin" && !images.aborted {
				t.Fatalf("store.Abort not called after %s error", tc.name)
			}
		})
	}
}
