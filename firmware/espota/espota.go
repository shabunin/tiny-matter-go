// Package espota stores OTA software updates for TinyGo ESP32 and ESP32-S3
// firmware started by esp32-loader or esp32s3-loader: it writes a new
// image into the slot the firmware is not running from, adds a boot record
// for it, and confirms the image once it works.
//
// An OTA image's payload is the image prefixed with what its boot record
// needs (espslot payload writes it):
//
//	0x00 magic "TMGI"   0x04 _irom_flash_addr RAM address (0 on classic ESP32)
//	0x08 _drom_flash_addr RAM address   0x0C image length
//	0x10 the ESP image (app.bin)
package espota

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"unsafe"

	"github.com/shabunin/tiny-matter-go/ota"
)

// Common flash layout constants shared by esp32-loader and esp32s3-loader.
const (
	recA     = 0xE000
	recB     = 0xF000
	slotSize = 0x1F0000 // leaves the state area at the top of 4 MB untouched
	sector   = 4096

	recMagic       = 0x42474D54 // "TMGB"
	recTried       = 0x100
	recConfirmed   = 0x104
	payloadMagic   = 0x49474D54 // "TMGI"
	payloadHeader  = 16
	espImageMagic  = 0xE9
	espChipESP32   = 0
	espChipESP32S3 = 9
)

type chipLayout struct {
	slotA    uint32
	slotB    uint32
	slotSize uint32
	bootBase uint32 // 0 on ESP32-S3, 0x1000 on classic ESP32
	chipID   uint16
}

var (
	layoutESP32S3 = chipLayout{slotA: 0x10000, slotB: 0x200000, slotSize: slotSize, bootBase: 0, chipID: espChipESP32S3}
	layoutESP32   = chipLayout{slotA: 0x11000, slotB: 0x201000, slotSize: slotSize, bootBase: 0x1000, chipID: espChipESP32}
)

var errFlash = errors.New("espota: flash operation failed")

// flashBackend lets host tests inject a simulated NOR flash and boot state
// without changing the zero-allocation hardware path on ESP32 / ESP32-S3.
type flashBackend interface {
	flashRead(addr uint32, p []uint32) error
	flashWrite(addr uint32, p []uint32) error
	writeSector(addr uint32, data *[sector / 4]uint32) error
	runningBase() uint32
}

// record is a boot record.
type record struct {
	addr                   uint32 // of its sector
	seq, base, length      uint32
	irom, drom             uint32
	tried, confirmed, good bool
}

// Slots stores updates in the inactive slot. Its methods implement
// device.ImageStore.
type Slots struct {
	// Restart resets the chip (to start the new image).
	Restart func()
	// Log, if set, receives progress messages.
	Log func(msg string)

	dev       flashBackend // nil uses the hardware ROM flash routines
	cfg       *chipLayout  // nil uses defaultLayout for the build target
	buf       []uint32     // 4 KB word-aligned sector buffer on the heap (keeps .bss small on classic ESP32)
	running   record       // the record of the running image
	other     uint32       // the record sector to write
	target    uint32       // slot offset
	header    [payloadHeader]byte
	headerLen int
	length    uint32 // image length from the payload header
	written   uint32 // image bytes in buf or flash
	crc       uint32
	ready     bool
}

func (s *Slots) sectorWords() *[sector / 4]uint32 {
	if len(s.buf) != sector/4 {
		s.buf = make([]uint32, sector/4)
	}
	return (*[sector / 4]uint32)(s.buf)
}

func (s *Slots) bufBytes() []byte {
	w := s.sectorWords()
	return unsafe.Slice((*byte)(unsafe.Pointer(&w[0])), sector)
}

func (s *Slots) layout() chipLayout {
	if s.cfg != nil {
		return *s.cfg
	}
	return defaultLayout
}

func (s *Slots) flashRead(addr uint32, p []uint32) error {
	if s.dev != nil {
		return s.dev.flashRead(addr, p)
	}
	return hwFlashRead(addr, p)
}

func (s *Slots) flashWrite(addr uint32, p []uint32) error {
	if s.dev != nil {
		return s.dev.flashWrite(addr, p)
	}
	return hwFlashWrite(addr, p)
}

func (s *Slots) writeSector(addr uint32) error {
	w := s.sectorWords()
	if s.dev != nil {
		return s.dev.writeSector(addr, w)
	}
	return hwWriteSector(addr, w)
}

func (s *Slots) runningBase() uint32 {
	if s.dev != nil {
		return s.dev.runningBase()
	}
	return hwRunningBase()
}

func (s *Slots) readRecord(addr uint32) record {
	cfg := s.layout()
	r := record{addr: addr}
	var w [7]uint32
	var flags [2]uint32
	if s.flashRead(addr, w[:]) != nil || s.flashRead(addr+recTried, flags[:]) != nil {
		return r
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&w[0])), 24)
	r.seq, r.base, r.length, r.irom, r.drom = w[1], w[2], w[3], w[4], w[5]
	r.tried, r.confirmed = flags[0] == 0, flags[1] == 0
	r.good = w[0] == recMagic && w[6] == crc32.ChecksumIEEE(b) && r.base&0xFFFF == cfg.bootBase && r.base >= cfg.slotA
	return r
}

func (s *Slots) log(msg string) {
	if s.Log != nil {
		s.Log("espota: " + msg)
	}
}

// Running reports the running image's slot and record, and whether the
// loader started it (records exist).
func (s *Slots) Running() (base, seq uint32, confirmed, ok bool) {
	base = s.runningBase()
	a, b := s.readRecord(recA), s.readRecord(recB)
	var cur *record
	for _, r := range []*record{&a, &b} {
		if r.good && r.base == base && (cur == nil || r.seq > cur.seq) {
			cur = r
		}
	}
	if base == 0 || cur == nil {
		return base, 0, false, false
	}
	s.running = *cur
	s.other = recA
	if cur.addr == recA {
		s.other = recB
	}
	// Allocate the 4 KB sector buffer once at boot so a fragmented heap
	// never fails an OTA write later.
	s.sectorWords()
	return base, cur.seq, cur.confirmed, true
}

// Confirm marks the running image good, so the loader keeps starting it.
// Call it once the firmware works (it reaches the network). Until then the
// firmware should let the watchdog reset an image that hangs or does not
// get there in time: the loader then rolls it back.
func (s *Slots) Confirm() error {
	if _, _, confirmed, ok := s.Running(); !ok || confirmed {
		return nil
	}
	zero := [1]uint32{0}
	if err := s.flashWrite(s.running.addr+recConfirmed, zero[:]); err != nil {
		return err
	}
	s.log("image confirmed")
	return nil
}

// Begin implements device.ImageStore.
func (s *Slots) Begin(h *ota.Header) error {
	cfg := s.layout()
	base, _, confirmed, ok := s.Running()
	if !ok {
		return errors.New("espota: not started by boot loader")
	}
	if !confirmed {
		// Its rollback image is in the other slot.
		return errors.New("espota: the running image is not confirmed yet")
	}
	if h.PayloadSize < payloadHeader+24 || h.PayloadSize-payloadHeader > uint64(cfg.slotSize) {
		return errors.New("espota: image does not fit a slot")
	}
	s.target = cfg.slotB
	if base == cfg.slotB {
		s.target = cfg.slotA
	}
	s.headerLen, s.written, s.crc, s.length, s.ready = 0, 0, 0, 0, false
	// No record may point at the slot while it is overwritten.
	if err := s.eraseOther(); err != nil {
		return err
	}
	s.log("writing the image to slot 0x" + hex(s.target))
	return nil
}

// Write implements device.ImageStore.
func (s *Slots) Write(p []byte) error {
	cfg := s.layout()
	if s.target == 0 {
		return errors.New("espota: no update")
	}
	if s.headerLen < payloadHeader {
		n := copy(s.header[s.headerLen:], p)
		s.headerLen += n
		p = p[n:]
		if s.headerLen < payloadHeader {
			return nil
		}
		le := binary.LittleEndian
		s.length = le.Uint32(s.header[12:])
		if le.Uint32(s.header[0:]) != payloadMagic || s.length == 0 || s.length > cfg.slotSize {
			return errors.New("espota: not an ESP slot payload")
		}
	}
	if s.written+uint32(len(p)) > s.length {
		return errors.New("espota: payload longer than its image")
	}
	b := s.bufBytes()
	for len(p) > 0 {
		at := s.written % sector
		n := copy(b[at:], p)
		s.crc = crc32.Update(s.crc, crc32.IEEETable, p[:n])
		s.written += uint32(n)
		p = p[n:]
		if s.written%sector == 0 {
			if err := s.writeSector(s.target + s.written - sector); err != nil {
				return err
			}
		}
	}
	return nil
}

// Finish implements device.ImageStore: it writes the last sector, checks
// what flash holds, and writes the boot record.
func (s *Slots) Finish() error {
	cfg := s.layout()
	if s.target == 0 || s.headerLen < payloadHeader || s.written != s.length {
		return errors.New("espota: image incomplete")
	}
	if rest := s.written % sector; rest != 0 {
		b := s.bufBytes()
		for i := rest; i < sector; i++ {
			b[i] = 0xFF
		}
		if err := s.writeSector(s.target + s.written - rest); err != nil {
			return err
		}
	}
	// Read the image back.
	crc := uint32(0)
	w := s.sectorWords()
	for off := uint32(0); off < s.length; off += sector {
		if err := s.flashRead(s.target+off, w[:]); err != nil {
			return err
		}
		b := s.bufBytes()
		if off == 0 && (b[0] != espImageMagic || binary.LittleEndian.Uint16(b[12:]) != cfg.chipID) {
			return errors.New("espota: image chip ID mismatch")
		}
		crc = crc32.Update(crc, crc32.IEEETable, b[:min(sector, s.length-off)])
	}
	if crc != s.crc {
		return errors.New("espota: flash does not hold the image written")
	}
	// The boot record, newer than the running one, in the other sector.
	le := binary.LittleEndian
	b := s.bufBytes()
	for i := range b {
		b[i] = 0xFF
	}
	le.PutUint32(b[0:], recMagic)
	le.PutUint32(b[4:], s.running.seq+1)
	le.PutUint32(b[8:], s.target)
	le.PutUint32(b[12:], s.length)
	le.PutUint32(b[16:], le.Uint32(s.header[4:]))
	le.PutUint32(b[20:], le.Uint32(s.header[8:]))
	le.PutUint32(b[24:], crc32.ChecksumIEEE(b[:24]))
	if err := s.writeSector(s.other); err != nil {
		return err
	}
	if r := s.readRecord(s.other); !r.good || r.base != s.target || r.seq != s.running.seq+1 {
		return errors.New("espota: boot record not written")
	}
	s.ready = true
	s.log("image and boot record written")
	return nil
}

// Abort implements device.ImageStore: a boot record already written for
// the image is erased.
func (s *Slots) Abort() {
	if s.ready {
		s.eraseOther()
	}
	s.target, s.ready = 0, false
}

// eraseOther erases the record sector the running image does not use.
func (s *Slots) eraseOther() error {
	b := s.bufBytes()
	for i := range b {
		b[i] = 0xFF
	}
	return s.writeSector(s.other)
}

// Apply implements device.ImageStore: it restarts into the new image.
func (s *Slots) Apply() error {
	if !s.ready {
		return errors.New("espota: no image to apply")
	}
	s.log("restarting into the new image")
	s.Restart()
	return errors.New("espota: restart failed")
}

func hex(v uint32) string {
	const digits = "0123456789abcdef"
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = digits[v&15]
		v >>= 4
	}
	return string(b[:])
}
