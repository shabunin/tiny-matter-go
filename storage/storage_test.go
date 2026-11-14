package storage

import (
	"bytes"
	"errors"
	"testing"
)

// fakeFlash models NOR flash: erase sets 0xFF, writes can only clear bits.
// failAfter, when positive, makes the n-th write fail halfway (power cut).
type fakeFlash struct {
	mem       []byte
	writes    int
	failAfter int
}

var errPower = errors.New("power cut")

func newFake(size int) *fakeFlash {
	f := &fakeFlash{mem: make([]byte, size)}
	for i := range f.mem {
		f.mem[i] = 0xFF
	}
	return f
}

func (f *fakeFlash) ReadAt(p []byte, off int64) (int, error) { return copy(p, f.mem[off:]), nil }
func (f *fakeFlash) EraseBlockSize() int64                   { return 4096 }

func (f *fakeFlash) EraseBlocks(start, n int64) error {
	for i := start * 4096; i < (start+n)*4096; i++ {
		f.mem[i] = 0xFF
	}
	return nil
}

func (f *fakeFlash) WriteAt(p []byte, off int64) (int, error) {
	f.writes++
	if f.failAfter > 0 && f.writes == f.failAfter {
		p = p[:len(p)/2]
		defer func() { f.failAfter = 0 }()
		for i, b := range p {
			f.mem[off+int64(i)] &= b
		}
		return len(p), errPower
	}
	for i, b := range p {
		f.mem[off+int64(i)] &= b
	}
	return len(p), nil
}

func TestFlashRoundTrip(t *testing.T) {
	dev := newFake(64 << 10)
	s := &Flash{Dev: dev, Offset: 16 << 10, SlotSize: 8 << 10}
	if b, _ := s.Load(); b != nil {
		t.Fatal("blank flash returned state")
	}
	for i := 0; i < 5; i++ {
		want := bytes.Repeat([]byte{byte(i)}, 100+i*1000)
		if err := s.Save(want); err != nil {
			t.Fatal(err)
		}
		// A fresh instance (reboot) sees the newest blob.
		got, _ := (&Flash{Dev: dev, Offset: 16 << 10, SlotSize: 8 << 10}).Load()
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d: got %d bytes", i, len(got))
		}
	}
	if err := s.Save(make([]byte, 8<<10)); err != ErrTooLarge {
		t.Fatalf("oversize: %v", err)
	}
	if err := s.Erase(); err != nil {
		t.Fatal(err)
	}
	if b, _ := (&Flash{Dev: dev, Offset: 16 << 10, SlotSize: 8 << 10}).Load(); b != nil {
		t.Fatal("state survived erase")
	}
}

func TestFlashPowerCut(t *testing.T) {
	for cut := 1; cut <= 2; cut++ { // data write, then header write
		dev := newFake(32 << 10)
		s := &Flash{Dev: dev, SlotSize: 8 << 10}
		old := []byte("old state")
		s.Save(old)
		dev.writes, dev.failAfter = 0, cut
		if err := s.Save(bytes.Repeat([]byte("new state "), 300)); err == nil {
			t.Fatal("expected failure")
		}
		got, _ := (&Flash{Dev: dev, SlotSize: 8 << 10}).Load()
		if !bytes.Equal(got, old) {
			t.Fatalf("cut %d: got %q, want the old state", cut, got)
		}
	}
}

func TestSequenceWrap(t *testing.T) {
	if !newer(0, 0xFFFFFFFF) || newer(0xFFFFFFFF, 0) {
		t.Fatal("wraparound")
	}
}
