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
	// the new blob, never a mix. It must not keep b, which the caller
	// reuses.
	Save(b []byte) error
}

// Streamer is a Store that also takes a blob a piece at a time, so the
// caller never holds all of it: a large block that a small, fragmented
// heap may not have.
type Streamer interface {
	Store
	// SaveFunc replaces the blob with the bytes fill passes to write, in
	// order. As with Save, after a crash Load returns the old or the new
	// blob; if fill or write fails, the old one stays. write must not be
	// kept, and does not keep its argument.
	SaveFunc(fill func(write func(p []byte) error) error) error
}

// Memory is a Store in RAM, for tests and hosts without persistence.
type Memory struct{ b []byte }

// SaveFunc implements Streamer.
func (m *Memory) SaveFunc(fill func(write func(p []byte) error) error) error {
	var b []byte
	if err := fill(func(p []byte) error { b = append(b, p...); return nil }); err != nil {
		return err
	}
	m.b = b
	return nil
}

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

	seq   uint32
	slot  int // slot holding the current state, -1 if none
	init  bool
	stage []byte // aligned staging buffer for writes, allocated once
}

// stageSize is the size of the writes Save makes: the data reaches the
// device in aligned pieces of this size from one small buffer, whatever
// the pieces it is given (the ESP32 flash routines need 4-byte alignment,
// and padding a caller's slice would copy it).
const stageSize = 256

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
	return f.SaveFunc(func(write func([]byte) error) error { return write(b) })
}

// SaveFunc implements Streamer: it writes the pieces to the slot not
// holding the current state, erasing each block as the data reaches it,
// and then the header with the length and CRC (a torn write leaves no
// valid magic, so the other slot stays current).
func (f *Flash) SaveFunc(fill func(write func(p []byte) error) error) error {
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
	if f.stage == nil {
		f.stage = make([]byte, 0, stageSize)
	}
	var (
		st      = f.stage[:0]
		n       int64 // data bytes received
		written int64 // data bytes on flash, a multiple of stageSize
		erased  int64 // bytes of the slot erased, from its start
		crc     uint32
	)
	// eraseTo erases the slot's blocks up to end bytes from its start.
	eraseTo := func(end int64) error {
		for erased < end {
			if err := f.Dev.EraseBlocks((base+erased)/ebs, 1); err != nil {
				return err
			}
			erased += ebs
		}
		return nil
	}
	flush := func() error {
		if len(st) == 0 {
			return nil
		}
		// The last piece is padded to the 4-byte write size with 0xFF,
		// which leaves erased flash as it is; length and CRC exclude it.
		m := len(st)
		for len(st)%4 != 0 {
			st = append(st, 0xFF)
		}
		off := headerSize + written
		if err := eraseTo(off + int64(len(st))); err != nil {
			return err
		}
		if _, err := f.Dev.WriteAt(st, base+off); err != nil {
			return err
		}
		written += int64(m)
		st = st[:0]
		return nil
	}
	if err := eraseTo(headerSize); err != nil { // the old header, at once
		return err
	}
	write := func(p []byte) error {
		if n+int64(len(p)) > f.SlotSize-headerSize {
			return ErrTooLarge
		}
		crc = crc32.Update(crc, crc32.IEEETable, p)
		n += int64(len(p))
		for len(p) > 0 {
			c := copy(st[len(st):stageSize], p)
			st, p = st[:len(st)+c], p[c:]
			if len(st) == stageSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := fill(write); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return err
	}
	var h [headerSize]byte
	seq := f.seq + 1
	binary.LittleEndian.PutUint32(h[0:], magic)
	binary.LittleEndian.PutUint32(h[4:], seq)
	binary.LittleEndian.PutUint32(h[8:], uint32(n))
	binary.LittleEndian.PutUint32(h[12:], crc)
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
