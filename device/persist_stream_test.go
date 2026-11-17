package device_test

import (
	"bytes"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// bigState is an application cluster with a large persistent state, as a
// full scene table makes.
type bigState struct {
	im.ClusterBase
	data, restored []byte
}

func (*bigState) ID() uint32           { return 0xFFF1FC10 }
func (*bigState) Revision() uint16     { return 1 }
func (*bigState) Attributes() []uint32 { return nil }
func (*bigState) ReadAttribute(*im.Context, uint32, *tlv.Writer, tlv.Tag) im.Status {
	return im.UnsupportedAttribute
}
func (*bigState) WriteAttribute(*im.Context, uint32, bool, *tlv.Reader) im.Status {
	return im.UnsupportedWrite
}
func (b *bigState) EncodeState(w *tlv.Writer, tag tlv.Tag) { w.PutBytes(tag, b.data) }
func (b *bigState) DecodeState(r *tlv.Reader) error {
	v, err := r.Bytes()
	b.restored = bytes.Clone(v)
	return err
}

// preallocStore is a streaming Store whose buffer is allocated beforehand,
// so a save through it allocates nothing itself.
type preallocStore struct{ b []byte }

func (s *preallocStore) Load() ([]byte, error) { return s.b, nil }
func (s *preallocStore) Save(b []byte) error   { s.b = append(s.b[:0], b...); return nil }
func (s *preallocStore) SaveFunc(fill func(write func([]byte) error) error) error {
	s.b = s.b[:0]
	return fill(func(p []byte) error { s.b = append(s.b, p...); return nil })
}

// plainStore hides SaveFunc: the device must fall back to Save.
type plainStore struct{ storage.Store }

func TestStateSavedInPieces(t *testing.T) {
	data := make([]byte, 20000)
	rnd := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		data[i] = byte(rnd.Uint32())
	}
	addBig := func(h *harness, b *bigState) {
		ep := h.dev.Node.AddEndpoint(2, clusters.DeviceTypeOnOffLight)
		h.dev.Node.AddCluster(ep, clusters.Descriptor{}, b)
	}

	store := &preallocStore{b: make([]byte, 0, 64<<10)}
	h := newHarnessStore(t, store)
	h.commission()
	addBig(h, &bigState{data: data})
	h.dev.Node.Changed(2, 0xFFF1FC10, 0) // application state changed

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	h.dev.Flush()
	runtime.ReadMemStats(&m1)
	if len(store.b) < len(data) {
		t.Fatalf("saved %d bytes", len(store.b))
	}
	// The state went through the device's small buffer: the save allocated
	// a small fraction of it (hashing, closures), never the whole.
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 4096 {
		t.Fatalf("saving a %d-byte state allocated %d bytes", len(store.b), alloc)
	}

	// After a restart the state is back, byte for byte.
	h2 := newHarnessStore(t, store)
	b2 := &bigState{}
	addBig(h2, b2)
	if !bytes.Equal(b2.restored, data) {
		t.Fatalf("restored %d bytes, want %d", len(b2.restored), len(data))
	}
	if len(h2.dev.Fabrics.Fabrics()) != 1 {
		t.Fatalf("%d fabrics restored", len(h2.dev.Fabrics.Fabrics()))
	}

	// A Store without SaveFunc gets the same blob from Save.
	plain := &storage.Memory{}
	h3 := newHarnessStore(t, plainStore{plain})
	b3 := &bigState{}
	addBig(h3, b3)
	b3.data = data
	h3.dev.Node.Changed(2, 0xFFF1FC10, 0)
	h3.dev.Flush()
	saved, _ := plain.Load()
	h4 := newHarnessStore(t, plain)
	b4 := &bigState{}
	addBig(h4, b4)
	if len(saved) == 0 || !bytes.Equal(b4.restored, data) {
		t.Fatalf("Save fallback: %d bytes saved, %d restored", len(saved), len(b4.restored))
	}
}
