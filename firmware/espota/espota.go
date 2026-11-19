// Package espota stores OTA software updates for TinyGo ESP32-S3 firmware
// started by esp32s3-loader: it writes a new image into the slot the
// firmware is not running from, adds a boot record for it, and confirms
// the image once it works (see esp32s3-loader for the flash layout).
//
// An OTA image's payload is the image prefixed with what its boot record
// needs (espslot payload writes it):
//
//	0x00 magic "TMGI"   0x04 _irom_flash_addr RAM address
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

// Flash layout (esp32s3-loader).
const (
	recA     = 0xE000
	recB     = 0xF000
	SlotA    = 0x10000
	SlotB    = 0x200000
	slotSize = 0x1F0000 // up to the state area at 0x3F0000
	sector   = 4096

	recMagic       = 0x42474D54 // "TMGB"
	recTried       = 0x100
	recConfirmed   = 0x104
	payloadMagic   = 0x49474D54 // "TMGI"
	payloadHeader  = 16
	espImageMagic  = 0xE9
	espChipESP32S3 = 9
)

var errFlash = errors.New("espota: flash operation failed")

// buf is the sector being written, word aligned for the ROM routines.
var buf [sector / 4]uint32

func bufBytes() []byte { return unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), sector) }

// flashBackend lets host tests inject a simulated NOR flash and boot state
// without changing the zero-allocation hardware path on ESP32-S3.
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

	dev       flashBackend // nil uses the ESP32-S3 ROM flash routines
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
	if s.dev != nil {
		return s.dev.writeSector(addr, &buf)
	}
	return hwWriteSector(addr, &buf)
}

func (s *Slots) runningBase() uint32 {
	if s.dev != nil {
		return s.dev.runningBase()
	}
	return hwRunningBase()
}

func (s *Slots) readRecord(addr uint32) record {
	r := record{addr: addr}
	var w [7]uint32
	var flags [2]uint32
	if s.flashRead(addr, w[:]) != nil || s.flashRead(addr+recTried, flags[:]) != nil {
		return r
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&w[0])), 24)
	r.seq, r.base, r.length, r.irom, r.drom = w[1], w[2], w[3], w[4], w[5]
	r.tried, r.confirmed = flags[0] == 0, flags[1] == 0
	r.good = w[0] == recMagic && w[6] == crc32.ChecksumIEEE(b) && r.base&0xFFFF == 0 && r.base >= SlotA
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
	base, _, confirmed, ok := s.Running()
	if !ok {
		return errors.New("espota: not started by esp32s3-loader")
	}
	if !confirmed {
		// Its rollback image is in the other slot.
		return errors.New("espota: the running image is not confirmed yet")
	}
	if h.PayloadSize < payloadHeader+24 || h.PayloadSize-payloadHeader > slotSize {
		return errors.New("espota: image does not fit a slot")
	}
	s.target = SlotB
	if base == SlotB {
		s.target = SlotA
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
		if le.Uint32(s.header[0:]) != payloadMagic || s.length == 0 || s.length > slotSize {
			return errors.New("espota: not an ESP32-S3 slot payload")
		}
	}
	if s.written+uint32(len(p)) > s.length {
		return errors.New("espota: payload longer than its image")
	}
	b := bufBytes()
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
	if s.target == 0 || s.headerLen < payloadHeader || s.written != s.length {
		return errors.New("espota: image incomplete")
	}
	if rest := s.written % sector; rest != 0 {
		b := bufBytes()
		for i := rest; i < sector; i++ {
			b[i] = 0xFF
		}
		if err := s.writeSector(s.target + s.written - rest); err != nil {
			return err
		}
	}
	// Read the image back.
	crc := uint32(0)
	for off := uint32(0); off < s.length; off += sector {
		if err := s.flashRead(s.target+off, buf[:]); err != nil {
			return err
		}
		b := bufBytes()
		if off == 0 && (b[0] != espImageMagic || binary.LittleEndian.Uint16(b[12:]) != espChipESP32S3) {
			return errors.New("espota: not an ESP32-S3 image")
		}
		crc = crc32.Update(crc, crc32.IEEETable, b[:min(sector, s.length-off)])
	}
	if crc != s.crc {
		return errors.New("espota: flash does not hold the image written")
	}
	// The boot record, newer than the running one, in the other sector.
	le := binary.LittleEndian
	b := bufBytes()
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
	b := bufBytes()
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
