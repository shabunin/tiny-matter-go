package storage

import (
	"bytes"
	"errors"
	"testing"
)

// fakeFlash models NOR flash: erase sets 0xFF, writes can only clear bits.
// failAfter, when positive, makes the n-th write fail halfway (power cut).
// Like the ESP32 flash routines it wants 4-byte aligned writes, and it
// reports a write to a byte not erased since its last write (bad).
type fakeFlash struct {
	mem       []byte
	clean     []bool // erased and not written since
	writes    int
	erases    int
	failAfter int
	bad       error
}

var errPower = errors.New("power cut")

func newFake(size int) *fakeFlash {
	f := &fakeFlash{mem: make([]byte, size), clean: make([]bool, size)}
	for i := range f.mem {
		f.mem[i], f.clean[i] = 0xFF, true
	}
	return f
}

func (f *fakeFlash) ReadAt(p []byte, off int64) (int, error) { return copy(p, f.mem[off:]), nil }
func (f *fakeFlash) EraseBlockSize() int64                   { return 4096 }

func (f *fakeFlash) EraseBlocks(start, n int64) error {
	for i := start * 4096; i < (start+n)*4096; i++ {
		f.mem[i], f.clean[i] = 0xFF, true
	}
	f.erases += int(n)
	return nil
}

func (f *fakeFlash) WriteAt(p []byte, off int64) (int, error) {
	if off%4 != 0 || len(p)%4 != 0 {
		f.bad = errors.New("unaligned write")
	}
	for i := range p {
		if !f.clean[off+int64(i)] {
			f.bad = errors.New("write to a byte not erased")
		}
		f.clean[off+int64(i)] = false
	}
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
		if dev.bad != nil {
			t.Fatal(dev.bad)
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
	newState := bytes.Repeat([]byte("new state "), 300)
	// Count the writes of a whole save, then cut the power at each one.
	probe := newFake(32 << 10)
	(&Flash{Dev: probe, SlotSize: 8 << 10}).Save(newState)
	if probe.writes < 3 || probe.bad != nil {
		t.Fatalf("%d writes, %v", probe.writes, probe.bad)
	}
	for cut := 1; cut <= probe.writes; cut++ {
		dev := newFake(32 << 10)
		s := &Flash{Dev: dev, SlotSize: 8 << 10}
		old := []byte("old state")
		s.Save(old)
		dev.writes, dev.failAfter = 0, cut
		if err := s.Save(newState); err == nil {
			t.Fatal("expected failure")
		}
		got, _ := (&Flash{Dev: dev, SlotSize: 8 << 10}).Load()
		if !bytes.Equal(got, old) {
			t.Fatalf("cut %d: got %q, want the old state", cut, got)
		}
		// The next save after the cut works.
		dev.bad = nil
		if err := s.Save(newState); err != nil || dev.bad != nil {
			t.Fatalf("cut %d: save after: %v, %v", cut, err, dev.bad)
		}
		if got, _ := (&Flash{Dev: dev, SlotSize: 8 << 10}).Load(); !bytes.Equal(got, newState) {
			t.Fatalf("cut %d: new state not saved after the cut", cut)
		}
	}
}

func TestFlashStreamed(t *testing.T) {
	const slot = 8 << 10
	dev := newFake(32 << 10)
	s := &Flash{Dev: dev, SlotSize: slot}
	reload := func() []byte {
		b, _ := (&Flash{Dev: dev, SlotSize: slot}).Load()
		return b
	}
	pieceSizes := []int{0, 1, 3, 4, 5, 255, 256, 257, 511, 1000, 2}
	for round, total := range []int{0, 1, 2, 3, 13, 255, 256, 257, 4096 - 16, 4096 - 15, 5000, slot - 16} {
		want := make([]byte, total)
		for i := range want {
			want[i] = byte(i*7 + round)
		}
		dev.erases, dev.bad = 0, nil
		err := s.SaveFunc(func(write func([]byte) error) error {
			for i, k := 0, 0; i < len(want); k++ {
				n := min(pieceSizes[k%len(pieceSizes)], len(want)-i)
				if err := write(want[i : i+n]); err != nil {
					return err
				}
				i += n
			}
			return nil
		})
		if err != nil || dev.bad != nil {
			t.Fatalf("%d bytes: %v, %v", total, err, dev.bad)
		}
		if got := reload(); !bytes.Equal(got, want) {
			t.Fatalf("%d bytes: loaded %d bytes", total, len(got))
		}
		// Only the blocks the data reaches are erased.
		if blocks := (16 + total + 4095) / 4096; dev.erases != max(blocks, 1) {
			t.Fatalf("%d bytes: %d blocks erased, want %d", total, dev.erases, blocks)
		}
		// Save of the same bytes, in one piece, writes the same slot content.
		if err := s.Save(want); err != nil || dev.bad != nil {
			t.Fatalf("Save %d bytes: %v, %v", total, err, dev.bad)
		}
		if got := reload(); !bytes.Equal(got, want) {
			t.Fatalf("Save %d bytes: loaded %d", total, len(got))
		}
	}

	// A failing fill, or a blob too large, leaves the current state.
	cur := reload()
	errFill := errors.New("fill failed")
	if err := s.SaveFunc(func(write func([]byte) error) error {
		write(make([]byte, 3000))
		return errFill
	}); err != errFill {
		t.Fatalf("fill error: %v", err)
	}
	if !bytes.Equal(reload(), cur) {
		t.Fatal("failed fill changed the state")
	}
	err := s.SaveFunc(func(write func([]byte) error) error {
		for i := 0; i < 100; i++ {
			if err := write(make([]byte, 100)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != ErrTooLarge || !bytes.Equal(reload(), cur) {
		t.Fatalf("oversize stream: %v", err)
	}
	// And the store still works afterwards.
	if err := s.Save([]byte("after")); err != nil || !bytes.Equal(reload(), []byte("after")) || dev.bad != nil {
		t.Fatalf("save after failures: %v, %v", err, dev.bad)
	}
}

func TestMemoryStreamed(t *testing.T) {
	m := &Memory{}
	m.Save([]byte("old"))
	if err := m.SaveFunc(func(write func([]byte) error) error {
		write([]byte("ne"))
		return write([]byte("w"))
	}); err != nil {
		t.Fatal(err)
	}
	if b, _ := m.Load(); string(b) != "new" {
		t.Fatalf("got %q", b)
	}
	if err := m.SaveFunc(func(write func([]byte) error) error {
		write([]byte("partial"))
		return errors.New("x")
	}); err == nil {
		t.Fatal("expected error")
	}
	if b, _ := m.Load(); string(b) != "new" {
		t.Fatalf("failed save changed it: %q", b)
	}
}

func TestSequenceWrap(t *testing.T) {
	if !newer(0, 0xFFFFFFFF) || newer(0xFFFFFFFF, 0) {
		t.Fatal("wraparound")
	}
}
