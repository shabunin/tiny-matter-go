//go:build rp2350

package rpota

import (
	"errors"
	"hash/crc32"
	"strconv"

	"firmware/rpflash"

	"github.com/shabunin/tiny-matter-go/ota"
)

// Store writes updates to the partition not running. Its methods implement
// device.ImageStore.
type Store struct {
	// Restart runs before the reboot into an update: save the state, leave
	// the network.
	Restart func()
	// Log, if set, receives progress messages.
	Log func(msg string)

	boot    BootInfo
	bootOK  bool
	target  int // the partition written, or -1
	dev     rpflash.Device
	first   []byte // the image's first sector, written last
	buf     []byte // the sector being filled
	written uint32
	crc     uint32
	ready   bool
}

// NewStore reads how the firmware was booted.
func NewStore() *Store {
	s := &Store{target: -1}
	s.boot, s.bootOK = ReadBootInfo()
	return s
}

func (s *Store) log(msg string) {
	if s.Log != nil {
		s.Log(msg)
	}
}

// Boot is what the boot ROM recorded about this boot.
func (s *Store) Boot() BootInfo { return s.boot }

// Running reports the partition running and whether it is on trial (a
// TBYB image that has not confirmed itself). ok is false when the
// firmware does not run from a partition (no partition table): then it
// cannot be updated.
func (s *Store) Running() (partition int, trial, ok bool) {
	if !s.bootOK || s.boot.Partition < 0 || s.boot.Partition >= len(Partitions) {
		return -1, false, false
	}
	return s.boot.Partition, s.boot.BuyPending, true
}

// Confirm makes a trial image the one to boot (and erases the previous
// one). Call it once the firmware works (it reaches the network). Until
// then any reset starts the previous image.
func (s *Store) Confirm() error {
	if _, trial, ok := s.Running(); !ok || !trial {
		return nil
	}
	var scratch [SectorSize]byte
	if r := explicitBuy(&scratch); r != 0 {
		return errors.New("rpota: explicit buy failed: " + strconv.Itoa(r))
	}
	s.boot.BuyPending = false
	s.log("image confirmed")
	return nil
}

// Begin implements device.ImageStore.
func (s *Store) Begin(h *ota.Header) error {
	p, trial, ok := s.Running()
	if !ok {
		return errors.New("rpota: not running from a partition")
	}
	if trial {
		// Its rollback image is in the other partition.
		return errors.New("rpota: the running image is not confirmed yet")
	}
	s.target = 1 - p
	t := Partitions[s.target]
	if h.PayloadSize < SectorSize || h.PayloadSize > uint64(t.Size()) {
		return errors.New("rpota: image does not fit a partition")
	}
	if s.buf == nil {
		s.first, s.buf = make([]byte, SectorSize), make([]byte, SectorSize)
	}
	s.dev = rpflash.Device{Start: int64(t.Start()), End: int64(t.Start() + t.Size())}
	s.written, s.crc, s.ready = 0, 0, false
	// The partition's first sector holds the image's block loop: with it
	// erased, nothing in the partition can boot while it is written.
	if err := s.eraseFirst(); err != nil {
		return err
	}
	s.log("writing the image to partition " + "AB"[s.target:s.target+1])
	return nil
}

func (s *Store) eraseFirst() error {
	return s.dev.EraseBlocks(s.dev.Start/SectorSize, 1)
}

// sector writes the filled sector at off (from the partition start); the
// first sector is kept for Finish.
func (s *Store) sector(off uint32, b []byte) error {
	if off == 0 {
		if err := CheckUpdate(b); err != nil {
			return err
		}
		copy(s.first, b)
		return nil
	}
	at := s.dev.Start + int64(off)
	if err := s.dev.EraseBlocks(at/SectorSize, 1); err != nil {
		return err
	}
	_, err := s.dev.WriteAt(b, at)
	return err
}

// Write implements device.ImageStore.
func (s *Store) Write(p []byte) error {
	if s.target < 0 {
		return errors.New("rpota: no update")
	}
	if int64(s.written)+int64(len(p)) > s.dev.End-s.dev.Start {
		return errors.New("rpota: image larger than the partition")
	}
	s.crc = crc32.Update(s.crc, crc32.IEEETable, p)
	for len(p) > 0 {
		at := s.written % SectorSize
		n := copy(s.buf[at:], p)
		s.written += uint32(n)
		p = p[n:]
		if s.written%SectorSize == 0 {
			if err := s.sector(s.written-SectorSize, s.buf); err != nil {
				return err
			}
		}
	}
	return nil
}

// Finish implements device.ImageStore: it writes the last sector, checks
// what the flash holds, then writes the first sector, which makes the
// image bootable (by a FLASH_UPDATE reboot only, being TBYB).
func (s *Store) Finish() error {
	if s.target < 0 || s.written < SectorSize {
		return errors.New("rpota: image incomplete")
	}
	if rest := s.written % SectorSize; rest != 0 {
		for i := rest; i < SectorSize; i++ {
			s.buf[i] = 0xFF
		}
		if err := s.sector(s.written-rest, s.buf); err != nil {
			return err
		}
	}
	crc := crc32.Update(0, crc32.IEEETable, s.first)
	for off := uint32(SectorSize); off < s.written; off += SectorSize {
		n := min(SectorSize, s.written-off)
		if _, err := s.dev.ReadAt(s.buf[:n], s.dev.Start+int64(off)); err != nil {
			return err
		}
		crc = crc32.Update(crc, crc32.IEEETable, s.buf[:n])
	}
	if crc != s.crc {
		return errors.New("rpota: flash does not hold the image written")
	}
	if _, err := s.dev.WriteAt(s.first, s.dev.Start); err != nil {
		return err
	}
	if _, err := s.dev.ReadAt(s.buf, s.dev.Start); err != nil {
		return err
	}
	if crc32.ChecksumIEEE(s.buf) != crc32.ChecksumIEEE(s.first) {
		return errors.New("rpota: flash does not hold the image's first sector")
	}
	s.ready = true
	s.log("image written: " + strconv.FormatUint(uint64(s.written), 10) + " bytes")
	return nil
}

// Abort implements device.ImageStore: the partition's first sector is
// erased, so nothing there boots.
func (s *Store) Abort() {
	if s.target >= 0 {
		s.eraseFirst()
	}
	s.target, s.ready = -1, false
}

// Apply implements device.ImageStore: a FLASH_UPDATE reboot into the
// written partition, where the image runs on trial.
func (s *Store) Apply() error {
	if !s.ready {
		return errors.New("rpota: no complete image")
	}
	if s.Restart != nil {
		s.Restart()
	}
	r := rebootFlashUpdated(Partitions[s.target].Start())
	return errors.New("rpota: reboot failed: " + strconv.Itoa(r))
}
