// Package storage keeps a node's persistent state: one blob that is read
// at startup and replaced as a whole when it changes.
//
// A node's state is small (a few KB for the fabric table and ACL) and
// changes rarely, so whole-blob writes keep this simple. Flash stores it
// in two alternating slots so a power cut during a write leaves the
// previous state intact.
package storage

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// Store holds one state blob.
type Store interface {
	// Load returns the last saved blob, or nil if there is none.
	Load() ([]byte, error)
	// Save replaces the blob. After a crash, Load returns either the old or
	// the new blob, never a mix.
	Save(b []byte) error
}

// Memory is a Store in RAM, for tests and hosts without persistence.
type Memory struct{ b []byte }

func (m *Memory) Load() ([]byte, error) { return m.b, nil }

func (m *Memory) Save(b []byte) error {
	m.b = append([]byte(nil), b...)
	return nil
}

// BlockDevice is the flash interface the Flash store needs. TinyGo's
// machine.Flash implements it.
type BlockDevice interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	EraseBlockSize() int64
	EraseBlocks(start, length int64) error
}

// ErrTooLarge is returned when a blob does not fit in a slot.
var ErrTooLarge = errors.New("storage: state too large for its slot")

const (
	headerSize = 16
	magic      = 0x544D4731 // "TMG1"
)

// Flash stores the blob in two slots of SlotSize bytes starting at Offset
// on Dev. SlotSize must be a multiple of the erase block size. Each slot
// starts with a header {magic, sequence, length, CRC-32}; Load picks the
// valid slot with the higher sequence and Save writes the other one.
type Flash struct {
	Dev      BlockDevice
	Offset   int64
	SlotSize int64

	seq  uint32
	slot int // slot holding the current state, -1 if none
	init bool
}

type header struct {
	seq    uint32
	length uint32
	crc    uint32
}

func (f *Flash) readSlot(i int) (header, []byte, bool) {
	var h [headerSize]byte
	base := f.Offset + int64(i)*f.SlotSize
	if _, err := f.Dev.ReadAt(h[:], base); err != nil {
		return header{}, nil, false
	}
	if binary.LittleEndian.Uint32(h[0:]) != magic {
		return header{}, nil, false
	}
	hd := header{binary.LittleEndian.Uint32(h[4:]), binary.LittleEndian.Uint32(h[8:]), binary.LittleEndian.Uint32(h[12:])}
	if int64(hd.length) > f.SlotSize-headerSize {
		return header{}, nil, false
	}
	b := make([]byte, hd.length)
	if _, err := f.Dev.ReadAt(b, base+headerSize); err != nil {
		return header{}, nil, false
	}
	if crc32.ChecksumIEEE(b) != hd.crc {
		return header{}, nil, false
	}
	return hd, b, true
}

// newer reports whether sequence a is after b (wrapping).
func newer(a, b uint32) bool { return int32(a-b) > 0 }

// Load returns the newest valid blob.
func (f *Flash) Load() ([]byte, error) {
	f.init, f.slot, f.seq = true, -1, 0
	var best []byte
	for i := 0; i < 2; i++ {
		h, b, ok := f.readSlot(i)
		if !ok {
			continue
		}
		if f.slot < 0 || newer(h.seq, f.seq) {
			f.slot, f.seq, best = i, h.seq, b
		}
	}
	return best, nil
}

// Save writes b to the slot not holding the current state.
func (f *Flash) Save(b []byte) error {
	if int64(len(b)) > f.SlotSize-headerSize {
		return ErrTooLarge
	}
	if !f.init {
		if _, err := f.Load(); err != nil {
			return err
		}
	}
	target := 0
	if f.slot == 0 {
		target = 1
	}
	base := f.Offset + int64(target)*f.SlotSize
	ebs := f.Dev.EraseBlockSize()
	if base%ebs != 0 || f.SlotSize%ebs != 0 {
		return errors.New("storage: slots must be aligned to erase blocks")
	}
	// Erase only what this write needs: the header block plus the data.
	n := (headerSize + int64(len(b)) + ebs - 1) / ebs
	if err := f.Dev.EraseBlocks(base/ebs, n); err != nil {
		return err
	}
	// Data first, header last: a torn write leaves no valid magic.
	if len(b) > 0 {
		if _, err := f.Dev.WriteAt(b, base+headerSize); err != nil {
			return err
		}
	}
	var h [headerSize]byte
	seq := f.seq + 1
	binary.LittleEndian.PutUint32(h[0:], magic)
	binary.LittleEndian.PutUint32(h[4:], seq)
	binary.LittleEndian.PutUint32(h[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(h[12:], crc32.ChecksumIEEE(b))
	if _, err := f.Dev.WriteAt(h[:], base); err != nil {
		return err
	}
	f.slot, f.seq = target, seq
	return nil
}

// Erase wipes both slots (factory reset).
func (f *Flash) Erase() error {
	ebs := f.Dev.EraseBlockSize()
	f.init, f.slot, f.seq = true, -1, 0
	return f.Dev.EraseBlocks(f.Offset/ebs, 2*f.SlotSize/ebs)
}
