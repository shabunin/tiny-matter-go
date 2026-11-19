package espota

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/shabunin/tiny-matter-go/ota"
)

const (
	flashSize = 4 << 20 // 4 MB flash: loader + records + SlotA + SlotB + 64 KB state area
	stateBase = SlotB + slotSize

	loaderAppDRAMLo = 0x3FC88000
	loaderAppDRAMHi = 0x3FCD8000
	loaderAppIRAMLo = 0x40378000
	loaderAppIRAMHi = 0x403C8000
)

// norFlash simulates a 4 MB SPI NOR flash chip with real NOR physics:
// erased bytes are 0xFF, writes must be 4-byte aligned and may only clear
// bits (1 -> 0), and only a full 4 KB sector erase restores bits to 1.
type norFlash struct {
	mem          []byte
	curBase      uint32
	writes       int
	erases       int
	failAfterOps int // if > 0, fail when writes+erases reaches this count
	corruptRead  uint32
	corruptOnce  bool
}

func newNORFlash() *norFlash {
	mem := make([]byte, flashSize)
	for i := range mem {
		mem[i] = 0xFF
	}
	return &norFlash{mem: mem}
}

func (f *norFlash) flashRead(addr uint32, p []uint32) error {
	n := uint32(len(p) * 4)
	if addr&3 != 0 || uint64(addr)+uint64(n) > uint64(len(f.mem)) {
		return errFlash
	}
	for i := range p {
		off := addr + uint32(i*4)
		w := binary.LittleEndian.Uint32(f.mem[off : off+4])
		if f.corruptOnce && f.corruptRead >= off && f.corruptRead < off+4 {
			w ^= 1 << (8 * (f.corruptRead - off))
			f.corruptOnce = false
		}
		p[i] = w
	}
	return nil
}

func (f *norFlash) flashWrite(addr uint32, p []uint32) error {
	n := uint32(len(p) * 4)
	if addr&3 != 0 || uint64(addr)+uint64(n) > uint64(len(f.mem)) {
		return errFlash
	}
	if f.failAfterOps > 0 && f.writes+f.erases >= f.failAfterOps {
		return errFlash
	}
	for i, w := range p {
		off := addr + uint32(i*4)
		cur := binary.LittleEndian.Uint32(f.mem[off : off+4])
		// Real NOR flash cannot flip a 0 bit back to 1 without an erase.
		if w&^cur != 0 {
			return errors.New("norFlash: write attempted to set 0 bit to 1 without sector erase")
		}
		binary.LittleEndian.PutUint32(f.mem[off:off+4], cur&w)
	}
	f.writes++
	return nil
}

func (f *norFlash) writeSector(addr uint32, data *[sector / 4]uint32) error {
	if addr%sector != 0 || uint64(addr)+sector > uint64(len(f.mem)) {
		return errFlash
	}
	if f.failAfterOps > 0 && f.writes+f.erases >= f.failAfterOps {
		return errFlash
	}
	// Erase sector to 0xFF.
	for i := uint32(0); i < sector; i++ {
		f.mem[addr+i] = 0xFF
	}
	f.erases++
	// Program words.
	if f.failAfterOps > 0 && f.writes+f.erases >= f.failAfterOps {
		return errFlash
	}
	for i, w := range data {
		off := addr + uint32(i*4)
		binary.LittleEndian.PutUint32(f.mem[off:off+4], w)
	}
	f.writes++
	return nil
}

func (f *norFlash) runningBase() uint32 { return f.curBase }

// installConfirmed writes an initial ESP32-S3 image into slot and creates a
// tried+confirmed boot record at recAddr, matching `espslot record`.
func (f *norFlash) installConfirmed(t *testing.T, recAddr, slot, seq uint32, img []byte, irom, drom uint32) {
	t.Helper()
	if slot%sector != 0 || len(img) > slotSize {
		t.Fatalf("bad slot %#x or length %d", slot, len(img))
	}
	copy(f.mem[slot:], img)
	var rec [sector]byte
	for i := range rec {
		rec[i] = 0xFF
	}
	le := binary.LittleEndian
	le.PutUint32(rec[0:], recMagic)
	le.PutUint32(rec[4:], seq)
	le.PutUint32(rec[8:], slot)
	le.PutUint32(rec[12:], uint32(len(img)))
	le.PutUint32(rec[16:], irom)
	le.PutUint32(rec[20:], drom)
	le.PutUint32(rec[24:], crc32.ChecksumIEEE(rec[:24]))
	// Mark tried and confirmed.
	le.PutUint32(rec[recTried:], 0)
	le.PutUint32(rec[recConfirmed:], 0)
	copy(f.mem[recAddr:], rec[:])
	f.curBase = slot
}

func (f *norFlash) assertStateAreaUntouched(t *testing.T) {
	t.Helper()
	for off := uint32(stateBase); off < flashSize; off++ {
		if f.mem[off] != 0xFF {
			t.Fatalf("persistent state flash area modified at %#x (got %#x)", off, f.mem[off])
		}
	}
}

// syntheticImage builds a valid ESP32-S3 binary image with one DRAM segment
// (containing _irom_flash_addr and _drom_flash_addr) and one IRAM segment,
// matching the exact header and XOR checksum format checked by esp32s3-loader.
func syntheticImage(tag byte, extraPayload int) (img []byte, iromPtr, dromPtr uint32) {
	dramAddr := uint32(loaderAppDRAMLo + 0x100)
	dramLen := uint32(64)
	iromPtr = dramAddr + 13 // intentionally unaligned, matching TinyGo
	dromPtr = dramAddr + 21

	iramAddr := uint32(loaderAppIRAMLo + 0x400)
	iramLen := uint32((extraPayload + 3) &^ 3)
	if iramLen < 32 {
		iramLen = 32
	}

	var b bytes.Buffer
	// 24-byte ESP32-S3 extended image header.
	var hdr [24]byte
	hdr[0] = espImageMagic
	hdr[1] = 2 // 2 segments
	binary.LittleEndian.PutUint32(hdr[4:], iramAddr)
	binary.LittleEndian.PutUint16(hdr[12:], espChipESP32S3)
	b.Write(hdr[:])

	dramData := make([]byte, dramLen)
	for i := range dramData {
		dramData[i] = tag ^ byte(i)
	}
	binary.LittleEndian.PutUint32(dramData[iromPtr-dramAddr:], 0x200)
	binary.LittleEndian.PutUint32(dramData[dromPtr-dramAddr:], 0x400)

	iramData := make([]byte, iramLen)
	for i := range iramData {
		iramData[i] = tag + byte(i*3)
	}

	writeSeg := func(addr uint32, data []byte) {
		var sh [8]byte
		binary.LittleEndian.PutUint32(sh[0:], addr)
		binary.LittleEndian.PutUint32(sh[4:], uint32(len(data)))
		b.Write(sh[:])
		b.Write(data)
	}
	writeSeg(dramAddr, dramData)
	writeSeg(iramAddr, iramData)

	sum := byte(0xEF)
	for _, x := range dramData {
		sum ^= x
	}
	for _, x := range iramData {
		sum ^= x
	}
	// Pad so checksum is the last byte of the 16-byte aligned region.
	end := (b.Len() | 15)
	for b.Len() < end {
		b.WriteByte(0)
	}
	b.WriteByte(sum)
	return b.Bytes(), iromPtr, dromPtr
}

func makePayload(img []byte, irom, drom uint32) []byte {
	b := make([]byte, payloadHeader, payloadHeader+len(img))
	le := binary.LittleEndian
	le.PutUint32(b[0:], payloadMagic)
	le.PutUint32(b[4:], irom)
	le.PutUint32(b[8:], drom)
	le.PutUint32(b[12:], uint32(len(img)))
	return append(b, img...)
}

type bootResult struct {
	seq         uint32
	base        uint32
	entry       uint32
	trial       bool
	rolledBack  bool
	patchedIROM uint32
	patchedDROM uint32
}

// simLoader faithfully mirrors firmware/esp32s3-loader/main.go: record
// selection, trial marking, rollback of unconfirmed tried records, segment
// bounds checks, XOR checksum verification, and flash-offset patching.
func simLoaderBoot(f *norFlash) (bootResult, error) {
	readRec := func(addr uint32) record {
		s := &Slots{dev: f}
		return s.readRecord(addr)
	}
	inDRAM := func(a, n uint32) bool {
		return a >= loaderAppDRAMLo && a+n <= loaderAppDRAMHi && a+n >= a
	}
	inIRAM := func(a, n uint32) bool {
		return a >= loaderAppIRAMLo && a+n <= loaderAppIRAMHi && a+n >= a
	}
	load := func(r record) (entry, patchedIROM, patchedDROM uint32, err error) {
		var h [6]uint32
		if err := f.flashRead(r.base, h[:]); err != nil {
			return 0, 0, 0, err
		}
		nseg := (h[0] >> 8) & 0xFF
		entry = h[1]
		chip := h[3] & 0xFFFF
		if h[0]&0xFF != espImageMagic || chip != espChipESP32S3 || nseg == 0 || nseg > 16 {
			return 0, 0, 0, errors.New("loader: bad ESP32-S3 header")
		}
		dram := make([]byte, loaderAppDRAMHi-loaderAppDRAMLo)
		off := r.base + 24
		sum := byte(0xEF)
		patched := 0
		for i := uint32(0); i < nseg; i++ {
			var sh [2]uint32
			if err := f.flashRead(off, sh[:]); err != nil {
				return 0, 0, 0, err
			}
			addr, segLen := sh[0], sh[1]
			off += 8
			if segLen&3 != 0 || addr&3 != 0 {
				return 0, 0, 0, errors.New("loader: unaligned segment")
			}
			if !inDRAM(addr, segLen) && !inIRAM(addr, segLen) {
				return 0, 0, 0, errors.New("loader: segment outside application area")
			}
			if uint64(off)+uint64(segLen) > uint64(len(f.mem)) {
				return 0, 0, 0, errors.New("loader: segment past flash end")
			}
			segBytes := f.mem[off : off+segLen]
			for _, x := range segBytes {
				sum ^= x
			}
			if inDRAM(addr, segLen) {
				copy(dram[addr-loaderAppDRAMLo:], segBytes)
				if r.irom >= addr && r.irom+4 <= addr+segLen {
					patched |= 1
				}
				if r.drom >= addr && r.drom+4 <= addr+segLen {
					patched |= 2
				}
			}
			off += segLen
		}
		end := ((off - r.base) | 15) + r.base
		if int(end) >= len(f.mem) || f.mem[end] != sum {
			return 0, 0, 0, errors.New("loader: bad checksum")
		}
		if patched != 3 {
			return 0, 0, 0, errors.New("loader: flash offset words not in DRAM")
		}
		addLE := func(ptr uint32) uint32 {
			p := dram[ptr-loaderAppDRAMLo : ptr-loaderAppDRAMLo+4]
			w := binary.LittleEndian.Uint32(p) + r.base
			binary.LittleEndian.PutUint32(p, w)
			return w
		}
		patchedIROM = addLE(r.irom)
		patchedDROM = addLE(r.drom)
		return entry, patchedIROM, patchedDROM, nil
	}

	a, b := readRec(recA), readRec(recB)
	var cur, prev *record
	if a.good && (!b.good || a.seq > b.seq) {
		cur = &a
		if b.good {
			prev = &b
		}
	} else if b.good {
		cur = &b
		if a.good {
			prev = &a
		}
	}
	if cur == nil {
		return bootResult{}, errors.New("loader: no bootable record")
	}
	rolledBack := false
	if prev != nil && !cur.confirmed && cur.tried {
		cur = prev
		prev = nil
		rolledBack = true
	}
	if !cur.confirmed && !cur.tried {
		zero := [1]uint32{0}
		if err := f.flashWrite(cur.addr+recTried, zero[:]); err != nil {
			return bootResult{}, err
		}
	}
	entry, pIROM, pDROM, err := load(*cur)
	if err != nil && prev != nil {
		rolledBack = true
		cur = prev
		entry, pIROM, pDROM, err = load(*cur)
	}
	if err != nil {
		return bootResult{}, err
	}
	f.curBase = cur.base
	return bootResult{
		seq:         cur.seq,
		base:        cur.base,
		entry:       entry,
		trial:       !cur.confirmed,
		rolledBack:  rolledBack,
		patchedIROM: pIROM,
		patchedDROM: pDROM,
	}, nil
}

func streamUpdate(s *Slots, payload []byte, chunkSize int) error {
	h := &ota.Header{PayloadSize: uint64(len(payload))}
	if err := s.Begin(h); err != nil {
		return err
	}
	for off := 0; off < len(payload); off += chunkSize {
		if err := s.Write(payload[off:min(off+chunkSize, len(payload))]); err != nil {
			return err
		}
	}
	return s.Finish()
}

func TestSlotsFullPingPongLifecycle(t *testing.T) {
	f := newNORFlash()
	img1, irom1, drom1 := syntheticImage(0x11, 5000)
	f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)

	restarted := 0
	s := &Slots{dev: f, Restart: func() { restarted++ }}
	base, seq, confirmed, ok := s.Running()
	if !ok || base != SlotA || seq != 1 || !confirmed {
		t.Fatalf("initial Running = (%#x, %d, %v, %v)", base, seq, confirmed, ok)
	}

	// Update 1: SlotA (seq 1) -> SlotB (seq 2).
	img2, irom2, drom2 := syntheticImage(0x22, 9500)
	if err := streamUpdate(s, makePayload(img2, irom2, drom2), 1024); err != nil {
		t.Fatalf("update 1: %v", err)
	}
	_ = s.Apply()
	if restarted != 1 {
		t.Fatalf("Restart called %d times, want 1", restarted)
	}

	// Bootloader boots SlotB as trial.
	boot, err := simLoaderBoot(f)
	if err != nil {
		t.Fatalf("boot 1: %v", err)
	}
	if boot.base != SlotB || boot.seq != 2 || !boot.trial || boot.rolledBack {
		t.Fatalf("boot 1 = %+v, want SlotB seq 2 trial", boot)
	}
	if boot.patchedIROM != 0x200+SlotB || boot.patchedDROM != 0x400+SlotB {
		t.Fatalf("patched offsets = (%#x, %#x)", boot.patchedIROM, boot.patchedDROM)
	}

	// While unconfirmed, Slots must refuse another OTA to protect the rollback slot.
	s2 := &Slots{dev: f, Restart: func() { restarted++ }}
	if base, seq, confirmed, ok := s2.Running(); !ok || base != SlotB || seq != 2 || confirmed {
		t.Fatalf("trial Running = (%#x, %d, %v, %v)", base, seq, confirmed, ok)
	}
	img3, irom3, drom3 := syntheticImage(0x33, 6000)
	if err := s2.Begin(&ota.Header{PayloadSize: uint64(payloadHeader + len(img3))}); err == nil {
		t.Fatal("Begin succeeded while running image was unconfirmed")
	}

	// Confirm SlotB, then ping-pong back to SlotA (seq 3).
	if err := s2.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	// Confirm is idempotent.
	if err := s2.Confirm(); err != nil {
		t.Fatalf("second Confirm: %v", err)
	}
	if err := streamUpdate(s2, makePayload(img3, irom3, drom3), 777); err != nil {
		t.Fatalf("update 2: %v", err)
	}
	_ = s2.Apply()

	boot, err = simLoaderBoot(f)
	if err != nil {
		t.Fatalf("boot 2: %v", err)
	}
	if boot.base != SlotA || boot.seq != 3 || !boot.trial || boot.rolledBack {
		t.Fatalf("boot 2 = %+v, want SlotA seq 3 trial", boot)
	}
	if err := (&Slots{dev: f}).Confirm(); err != nil {
		t.Fatalf("Confirm seq 3: %v", err)
	}
	// Subsequent reboot boots SlotA confirmed (not trial).
	boot, err = simLoaderBoot(f)
	if err != nil {
		t.Fatalf("boot 3: %v", err)
	}
	if boot.base != SlotA || boot.seq != 3 || boot.trial || boot.rolledBack {
		t.Fatalf("boot 3 = %+v, want SlotA seq 3 confirmed", boot)
	}
	f.assertStateAreaUntouched(t)
}

func TestSlotsTrialRollback(t *testing.T) {
	f := newNORFlash()
	img1, irom1, drom1 := syntheticImage(0x10, 4000)
	f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)

	s := &Slots{dev: f, Restart: func() {}}
	img2, irom2, drom2 := syntheticImage(0x20, 4500)
	if err := streamUpdate(s, makePayload(img2, irom2, drom2), 512); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Boot 1: loader marks SlotB tried and launches it.
	boot1, err := simLoaderBoot(f)
	if err != nil || boot1.base != SlotB || !boot1.trial {
		t.Fatalf("trial boot = %+v, %v", boot1, err)
	}

	// Simulate hang / watchdog reset BEFORE Confirm().
	// Boot 2: loader sees SlotB was tried and never confirmed, rolls back to SlotA.
	boot2, err := simLoaderBoot(f)
	if err != nil {
		t.Fatalf("rollback boot: %v", err)
	}
	if boot2.base != SlotA || boot2.seq != 1 || boot2.trial || !boot2.rolledBack {
		t.Fatalf("rollback boot = %+v, want SlotA seq 1 rolledBack", boot2)
	}

	// Recovered SlotA must still be able to accept a fixed update.
	sRecovered := &Slots{dev: f, Restart: func() {}}
	img3, irom3, drom3 := syntheticImage(0x30, 5000)
	if err := streamUpdate(sRecovered, makePayload(img3, irom3, drom3), 1024); err != nil {
		t.Fatalf("post-rollback update: %v", err)
	}
	boot3, err := simLoaderBoot(f)
	if err != nil || boot3.base != SlotB || boot3.seq != 2 || !boot3.trial || boot3.rolledBack {
		t.Fatalf("post-rollback boot = %+v, %v", boot3, err)
	}
}

func TestSlotsPowerCutDuringDownload(t *testing.T) {
	img1, irom1, drom1 := syntheticImage(0x01, 4096)
	img2, irom2, drom2 := syntheticImage(0x02, 12000)
	payload := makePayload(img2, irom2, drom2)

	// Measure total flash ops for a complete update, then inject a power cut
	// before every single op up to and including erasing the boot record
	// sector right before programming it.
	probe := newNORFlash()
	probe.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
	if err := streamUpdate(&Slots{dev: probe, Restart: func() {}}, payload, 1024); err != nil {
		t.Fatalf("probe update: %v", err)
	}
	totalOps := probe.writes + probe.erases

	for cutAt := 1; cutAt < totalOps; cutAt++ {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		f.failAfterOps = cutAt

		s := &Slots{dev: f, Restart: func() {}}
		if err := streamUpdate(s, payload, 1024); err == nil {
			t.Fatalf("cutAt=%d/%d: expected flash failure", cutAt, totalOps)
		}
		// Power restored: loader must cleanly boot original SlotA.
		f.failAfterOps = 0
		boot, err := simLoaderBoot(f)
		if err != nil {
			t.Fatalf("cutAt=%d/%d: boot failed: %v", cutAt, totalOps, err)
		}
		if boot.base != SlotA || boot.seq != 1 || boot.trial {
			t.Fatalf("cutAt=%d/%d: booted %+v, want original SlotA seq 1", cutAt, totalOps, boot)
		}
	}
}

func TestSlotsAbortAfterFinish(t *testing.T) {
	f := newNORFlash()
	img1, irom1, drom1 := syntheticImage(0xAA, 4096)
	f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)

	s := &Slots{dev: f, Restart: func() {}}
	img2, irom2, drom2 := syntheticImage(0xBB, 4096)
	if err := streamUpdate(s, makePayload(img2, irom2, drom2), 1024); err != nil {
		t.Fatalf("update: %v", err)
	}
	// Provider tells us Discontinue after Finish(): Abort must erase the new boot record.
	s.Abort()
	if err := s.Apply(); err == nil {
		t.Fatal("Apply succeeded after Abort")
	}
	boot, err := simLoaderBoot(f)
	if err != nil || boot.base != SlotA || boot.seq != 1 {
		t.Fatalf("boot after Abort = %+v, %v; want SlotA seq 1", boot, err)
	}
}

func TestSlotsStreamingChunkBoundaries(t *testing.T) {
	img1, irom1, drom1 := syntheticImage(0x01, 2000)
	img2, irom2, drom2 := syntheticImage(0x55, 8300) // spans >2 sectors, non-multiple of 4096
	payload := makePayload(img2, irom2, drom2)

	for _, chunk := range []int{1, 3, 7, 15, 16, 17, 512, 1024, 4095, 4096, 4097, len(payload)} {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f, Restart: func() {}}
		if err := streamUpdate(s, payload, chunk); err != nil {
			t.Fatalf("chunk=%d: %v", chunk, err)
		}
		if !bytes.Equal(f.mem[SlotB:SlotB+uint32(len(img2))], img2) {
			t.Fatalf("chunk=%d: flashed image bytes mismatch", chunk)
		}
		// Remaining bytes of the final sector must stay 0xFF.
		remEnd := ((uint32(len(img2)) + sector - 1) / sector) * sector
		for off := uint32(len(img2)); off < remEnd; off++ {
			if f.mem[SlotB+off] != 0xFF {
				t.Fatalf("chunk=%d: tail padding at +%d = %#x, want 0xFF", chunk, off, f.mem[SlotB+off])
			}
		}
		boot, err := simLoaderBoot(f)
		if err != nil || boot.base != SlotB || boot.seq != 2 {
			t.Fatalf("chunk=%d: boot = %+v, %v", chunk, boot, err)
		}
	}
}

func TestSlotsValidationErrors(t *testing.T) {
	img1, irom1, drom1 := syntheticImage(0x01, 1000)

	t.Run("not started by loader", func(t *testing.T) {
		f := newNORFlash()
		s := &Slots{dev: f}
		if err := s.Begin(&ota.Header{PayloadSize: 1024}); err == nil {
			t.Fatal("Begin succeeded without loader records")
		}
	})

	t.Run("oversized image", func(t *testing.T) {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f}
		if err := s.Begin(&ota.Header{PayloadSize: payloadHeader + slotSize + 1}); err == nil {
			t.Fatal("Begin accepted oversized image")
		}
	})

	t.Run("bad payload magic", func(t *testing.T) {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f}
		p := makePayload(img1, irom1, drom1)
		p[0] ^= 0xFF
		if err := streamUpdate(s, p, 16); err == nil {
			t.Fatal("accepted bad payload magic")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f}
		p := append(makePayload(img1, irom1, drom1), 0x00)
		if err := streamUpdate(s, p, 64); err == nil {
			t.Fatal("accepted payload longer than declared image")
		}
	})

	t.Run("truncated payload", func(t *testing.T) {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f}
		p := makePayload(img1, irom1, drom1)
		if err := streamUpdate(s, p[:len(p)-1], 64); err == nil {
			t.Fatal("Finish accepted truncated image")
		}
	})

	t.Run("wrong chip id", func(t *testing.T) {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f}
		bad := bytes.Clone(img1)
		binary.LittleEndian.PutUint16(bad[12:], 0) // classic ESP32 instead of S3 (9)
		if err := streamUpdate(s, makePayload(bad, irom1, drom1), 64); err == nil {
			t.Fatal("Finish accepted non-ESP32-S3 image")
		}
	})

	t.Run("flash readback corruption", func(t *testing.T) {
		f := newNORFlash()
		f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)
		s := &Slots{dev: f}
		img2, irom2, drom2 := syntheticImage(0x77, 4500)
		p := makePayload(img2, irom2, drom2)
		if err := s.Begin(&ota.Header{PayloadSize: uint64(len(p))}); err != nil {
			t.Fatal(err)
		}
		if err := s.Write(p); err != nil {
			t.Fatal(err)
		}
		f.corruptRead = SlotB + 100
		f.corruptOnce = true
		if err := s.Finish(); err == nil {
			t.Fatal("Finish missed flash readback bitflip")
		}
	})
}

func TestLoaderRejectsCorruptImageAndFallsBack(t *testing.T) {
	img1, irom1, drom1 := syntheticImage(0x01, 2000)

	cases := []struct {
		name   string
		mutate func(img []byte, irom, drom *uint32)
	}{
		{
			name:   "bad XOR checksum",
			mutate: func(img []byte, _, _ *uint32) { img[len(img)-1] ^= 0x01 },
		},
		{
			name: "segment overlaps loader DRAM",
			mutate: func(img []byte, _, _ *uint32) {
				// First segment header starts at offset 24; point addr into loader DRAM.
				binary.LittleEndian.PutUint32(img[24:], loaderAppDRAMHi-4)
			},
		},
		{
			name: "irom_ptr outside DRAM segment",
			mutate: func(_ []byte, irom, _ *uint32) {
				*irom = loaderAppDRAMHi - 16
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newNORFlash()
			f.installConfirmed(t, recA, SlotA, 1, img1, irom1, drom1)

			img2, irom2, drom2 := syntheticImage(0x42, 2000)
			tc.mutate(img2, &irom2, &drom2)
			s := &Slots{dev: f, Restart: func() {}}
			if err := streamUpdate(s, makePayload(img2, irom2, drom2), 512); err != nil {
				t.Fatalf("flash bad image: %v", err)
			}
			// Loader must reject SlotB and fall back to SlotA.
			boot, err := simLoaderBoot(f)
			if err != nil {
				t.Fatalf("boot: %v", err)
			}
			if boot.base != SlotA || boot.seq != 1 || !boot.rolledBack {
				t.Fatalf("boot = %+v, want fallback to SlotA seq 1", boot)
			}
		})
	}
}

// TestConstantsMatchLoaderAndLinker ensures flash layout and memory-map
// constants in espota, esp32s3-loader/main.go and esp32s3-loader/loader.ld
// never drift out of sync.
func TestConstantsMatchLoaderAndLinker(t *testing.T) {
	loaderSrc, err := os.ReadFile("../esp32s3-loader/main.go")
	if err != nil {
		t.Fatalf("read loader source: %v", err)
	}
	defineRe := regexp.MustCompile(`(?m)^#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)u?`)
	defs := map[string]uint32{}
	for _, m := range defineRe.FindAllStringSubmatch(string(loaderSrc), -1) {
		v, err := strconv.ParseUint(m[2], 0, 32)
		if err != nil {
			t.Fatalf("parse %s=%s: %v", m[1], m[2], err)
		}
		defs[m[1]] = uint32(v)
	}
	wantDefs := map[string]uint32{
		"REC_A":         recA,
		"REC_B":         recB,
		"REC_MAGIC":     recMagic,
		"REC_TRIED":     recTried,
		"REC_CONFIRMED": recConfirmed,
		"APP_DRAM_LO":   loaderAppDRAMLo,
		"APP_DRAM_HI":   loaderAppDRAMHi,
		"APP_IRAM_LO":   loaderAppIRAMLo,
		"APP_IRAM_HI":   loaderAppIRAMHi,
	}
	for k, want := range wantDefs {
		got, ok := defs[k]
		if !ok {
			t.Errorf("esp32s3-loader/main.go missing #define %s", k)
		} else if got != want {
			t.Errorf("esp32s3-loader/main.go %s = %#x, espota expects %#x", k, got, want)
		}
	}

	ldSrc, err := os.ReadFile("../esp32s3-loader/loader.ld")
	if err != nil {
		t.Fatalf("read loader.ld: %v", err)
	}
	dramRe := regexp.MustCompile(`DRAM\s*\([^)]*\)\s*:\s*ORIGIN\s*=\s*(0x[0-9A-Fa-f]+)`)
	m := dramRe.FindStringSubmatch(string(ldSrc))
	if m == nil {
		t.Fatal("loader.ld DRAM ORIGIN not found")
	}
	dramOrigin, err := strconv.ParseUint(m[1], 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if uint32(dramOrigin) < loaderAppDRAMHi {
		t.Errorf("loader.ld DRAM ORIGIN %#x overlaps APP_DRAM_HI %#x", dramOrigin, loaderAppDRAMHi)
	}

	// Verify state area in esp32s3-light does not overlap SlotB.
	if SlotB+slotSize != stateBase || stateBase > flashSize-32*1024 {
		t.Errorf("slot layout overlaps state area: SlotB=%#x slotSize=%#x", SlotB, slotSize)
	}
	if recA >= SlotA || recB >= SlotA || recB != recA+sector {
		t.Errorf("record sectors overlap SlotA: recA=%#x recB=%#x SlotA=%#x", recA, recB, SlotA)
	}
	// Verify espslot agrees on magic values.
	espslotSrc, err := os.ReadFile("../espslot/main.go")
	if err != nil {
		t.Fatalf("read espslot/main.go: %v", err)
	}
	if !strings.Contains(string(espslotSrc), "0x42474D54") || !strings.Contains(string(espslotSrc), "0x49474D54") {
		t.Error("espslot/main.go magic constants do not match espota")
	}
}

// TestRealFirmwareArtifactsOTA runs the full OTA image + Slots + NOR flash +
// bootloader simulation against a real TinyGo-compiled esp32s3-light ELF/BIN
// when TMG_ESP32S3_ELF and TMG_ESP32S3_BIN are set (used in CI).
func TestRealFirmwareArtifactsOTA(t *testing.T) {
	elfPath := os.Getenv("TMG_ESP32S3_ELF")
	binPath := os.Getenv("TMG_ESP32S3_BIN")
	if elfPath == "" || binPath == "" {
		t.Skip("set TMG_ESP32S3_ELF and TMG_ESP32S3_BIN to test real firmware OTA artifacts")
	}
	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("open ELF: %v", err)
	}
	defer ef.Close()
	syms, err := ef.Symbols()
	if err != nil {
		t.Fatalf("ELF symbols: %v", err)
	}
	var irom, drom uint32
	for _, sym := range syms {
		switch sym.Name {
		case "_irom_flash_addr":
			irom = uint32(sym.Value)
		case "_drom_flash_addr":
			drom = uint32(sym.Value)
		}
	}
	if irom == 0 || drom == 0 {
		t.Fatalf("missing _irom_flash_addr (%#x) or _drom_flash_addr (%#x)", irom, drom)
	}
	binData, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read BIN: %v", err)
	}
	if len(binData) > slotSize {
		t.Fatalf("real firmware %d bytes exceeds slotSize %d bytes", len(binData), slotSize)
	}
	t.Logf("real esp32s3-light image: %d bytes (%.1f%% of slot), _irom_flash_addr=%#x, _drom_flash_addr=%#x",
		len(binData), 100*float64(len(binData))/float64(slotSize), irom, drom)

	// Wrap the real firmware into a Matter .ota image and verify through ota.Reader -> espota.Slots.
	payload := makePayload(binData, irom, drom)

	f := newNORFlash()
	f.installConfirmed(t, recA, SlotA, 1, binData, irom, drom)
	if boot, err := simLoaderBoot(f); err != nil || boot.base != SlotA {
		t.Fatalf("initial real image boot from SlotA failed: %+v, %v", boot, err)
	}

	runOTA := func(ver uint32, wantSlot uint32) {
		t.Helper()
		imgBytes, err := ota.Create(ota.Header{
			VendorID:              0xFFF1,
			ProductID:             0x8000,
			SoftwareVersion:       ver,
			SoftwareVersionString: "0.2." + strconv.Itoa(int(ver)),
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		s := &Slots{dev: f, Restart: func() {}}
		var began bool
		r := &ota.Reader{
			OnHeader: func(h *ota.Header) error {
				began = true
				return s.Begin(h)
			},
			Payload: s.Write,
		}
		// Feed in 1024-byte BDX-sized blocks.
		for off := 0; off < len(imgBytes); off += 1024 {
			if err := r.Write(imgBytes[off:min(off+1024, len(imgBytes))]); err != nil {
				t.Fatalf("ota.Reader.Write at %d: %v", off, err)
			}
		}
		if !began {
			t.Fatal("ota.Reader never parsed header")
		}
		if err := r.Close(); err != nil {
			t.Fatalf("ota.Reader.Close: %v", err)
		}
		if err := s.Finish(); err != nil {
			t.Fatalf("Slots.Finish: %v", err)
		}
		boot, err := simLoaderBoot(f)
		if err != nil {
			t.Fatalf("simLoaderBoot into slot %#x: %v", wantSlot, err)
		}
		if boot.base != wantSlot || !boot.trial || boot.rolledBack {
			t.Fatalf("boot = %+v, want trial on %#x", boot, wantSlot)
		}
		t.Logf("booted real image in slot %#x (seq %d), entry=%#x, patched irom=%#x drom=%#x",
			boot.base, boot.seq, boot.entry, boot.patchedIROM, boot.patchedDROM)
	}

	// First update: SlotA -> SlotB, then simulate rollback before confirming.
	runOTA(2, SlotB)
	if boot, err := simLoaderBoot(f); err != nil || boot.base != SlotA || !boot.rolledBack {
		t.Fatalf("rollback of real image failed: %+v, %v", boot, err)
	}

	// Second update: SlotA -> SlotB, confirm, then SlotB -> SlotA and confirm.
	runOTA(2, SlotB)
	if err := (&Slots{dev: f}).Confirm(); err != nil {
		t.Fatalf("confirm SlotB: %v", err)
	}
	runOTA(3, SlotA)
	if err := (&Slots{dev: f}).Confirm(); err != nil {
		t.Fatalf("confirm SlotA: %v", err)
	}
	f.assertStateAreaUntouched(t)
}

const (
	esp32AppDRAMLo = 0x3FFB0000
	esp32AppDRAMHi = 0x3FFE0000
	esp32AppIRAMLo = 0x40080000
	esp32AppIRAMHi = 0x4009C000
	esp32StateBase = 0x3F8000 // last 32 KB of 4 MB flash
)

// syntheticESP32Image builds a valid classic ESP32 image (chip ID 0) with
// one DRAM segment holding _drom_flash_addr (set to 0x20000 as TinyGo does
// for a 0x1000-flashed image) and one IRAM segment.
func syntheticESP32Image(tag byte, extra int) (img []byte, dromPtr uint32) {
	dramAddr := uint32(esp32AppDRAMLo + 0x6000)
	dramLen := uint32(64)
	dromPtr = dramAddr + 12

	iramAddr := uint32(esp32AppIRAMLo)
	iramLen := uint32((extra + 3) &^ 3)
	if iramLen < 32 {
		iramLen = 32
	}

	var b bytes.Buffer
	var hdr [24]byte
	hdr[0] = espImageMagic
	hdr[1] = 2
	binary.LittleEndian.PutUint32(hdr[4:], iramAddr+0x58)
	binary.LittleEndian.PutUint16(hdr[12:], espChipESP32)
	b.Write(hdr[:])

	dramData := make([]byte, dramLen)
	for i := range dramData {
		dramData[i] = tag ^ byte(i)
	}
	binary.LittleEndian.PutUint32(dramData[dromPtr-dramAddr:], 0x20000)

	iramData := make([]byte, iramLen)
	for i := range iramData {
		iramData[i] = tag + byte(i*5)
	}

	writeSeg := func(addr uint32, data []byte) {
		var sh [8]byte
		binary.LittleEndian.PutUint32(sh[0:], addr)
		binary.LittleEndian.PutUint32(sh[4:], uint32(len(data)))
		b.Write(sh[:])
		b.Write(data)
	}
	writeSeg(dramAddr, dramData)
	writeSeg(iramAddr, iramData)

	sum := byte(0xEF)
	for _, x := range dramData {
		sum ^= x
	}
	for _, x := range iramData {
		sum ^= x
	}
	end := b.Len() | 15
	for b.Len() < end {
		b.WriteByte(0)
	}
	b.WriteByte(sum)
	return b.Bytes(), dromPtr
}

// simESP32LoaderBoot faithfully mirrors firmware/esp32-loader/main.go.
func simESP32LoaderBoot(f *norFlash) (bootResult, error) {
	cfg := layoutESP32
	readRec := func(addr uint32) record {
		s := &Slots{dev: f, cfg: &cfg}
		return s.readRecord(addr)
	}
	inDRAM := func(a, n uint32) bool {
		return a >= esp32AppDRAMLo && a+n <= esp32AppDRAMHi && a+n >= a
	}
	inIRAM := func(a, n uint32) bool {
		return a >= esp32AppIRAMLo && a+n <= esp32AppIRAMHi && a+n >= a
	}
	load := func(r record) (entry, patchedDROM uint32, err error) {
		var h [6]uint32
		if err := f.flashRead(r.base, h[:]); err != nil {
			return 0, 0, err
		}
		nseg := (h[0] >> 8) & 0xFF
		entry = h[1]
		chip := h[3] & 0xFFFF
		if h[0]&0xFF != espImageMagic || chip != espChipESP32 || nseg == 0 || nseg > 16 {
			return 0, 0, errors.New("esp32-loader: bad ESP32 header")
		}
		dram := make([]byte, esp32AppDRAMHi-esp32AppDRAMLo)
		off := r.base + 24
		sum := byte(0xEF)
		patched := false
		for i := uint32(0); i < nseg; i++ {
			var sh [2]uint32
			if err := f.flashRead(off, sh[:]); err != nil {
				return 0, 0, err
			}
			addr, segLen := sh[0], sh[1]
			off += 8
			if segLen&3 != 0 || addr&3 != 0 {
				return 0, 0, errors.New("esp32-loader: unaligned segment")
			}
			isDRAM := inDRAM(addr, segLen)
			if !isDRAM && !inIRAM(addr, segLen) {
				return 0, 0, errors.New("esp32-loader: segment outside application area")
			}
			segBytes := f.mem[off : off+segLen]
			for _, x := range segBytes {
				sum ^= x
			}
			if isDRAM {
				copy(dram[addr-esp32AppDRAMLo:], segBytes)
				if r.drom >= addr && r.drom+4 <= addr+segLen {
					patched = true
				}
			}
			off += segLen
		}
		end := ((off - r.base) | 15) + r.base
		if int(end) >= len(f.mem) || f.mem[end] != sum {
			return 0, 0, errors.New("esp32-loader: bad checksum")
		}
		if !patched {
			return 0, 0, errors.New("esp32-loader: _drom_flash_addr not in DRAM")
		}
		p := dram[r.drom-esp32AppDRAMLo : r.drom-esp32AppDRAMLo+4]
		patchedDROM = binary.LittleEndian.Uint32(p) + (r.base - cfg.bootBase)
		binary.LittleEndian.PutUint32(p, patchedDROM)
		return entry, patchedDROM, nil
	}

	a, b := readRec(recA), readRec(recB)
	var cur, prev *record
	if a.good && (!b.good || a.seq > b.seq) {
		cur = &a
		if b.good {
			prev = &b
		}
	} else if b.good {
		cur = &b
		if a.good {
			prev = &a
		}
	}
	if cur == nil {
		return bootResult{}, errors.New("esp32-loader: no bootable record")
	}
	rolledBack := false
	if prev != nil && !cur.confirmed && cur.tried {
		cur = prev
		prev = nil
		rolledBack = true
	}
	if !cur.confirmed && !cur.tried {
		zero := [1]uint32{0}
		if err := f.flashWrite(cur.addr+recTried, zero[:]); err != nil {
			return bootResult{}, err
		}
	}
	entry, pDROM, err := load(*cur)
	if err != nil && prev != nil {
		rolledBack = true
		cur = prev
		entry, pDROM, err = load(*cur)
	}
	if err != nil {
		return bootResult{}, err
	}
	f.curBase = cur.base
	return bootResult{
		seq:         cur.seq,
		base:        cur.base,
		entry:       entry,
		trial:       !cur.confirmed,
		rolledBack:  rolledBack,
		patchedDROM: pDROM,
	}, nil
}

func TestESP32SlotsFullLifecycleAndRollback(t *testing.T) {
	cfg := layoutESP32
	f := newNORFlash()
	img1, drom1 := syntheticESP32Image(0x11, 5000)
	f.installConfirmed(t, recA, cfg.slotA, 1, img1, 0, drom1)

	// Reject an ESP32-S3 image on a classic ESP32 device.
	s3Img, s3IROM, s3DROM := syntheticImage(0x99, 2000)
	if err := streamUpdate(&Slots{dev: f, cfg: &cfg}, makePayload(s3Img, s3IROM, s3DROM), 512); err == nil {
		t.Fatal("classic ESP32 accepted an ESP32-S3 image")
	}

	// Update SlotA (0x11000) -> SlotB (0x201000), boot trial, simulate crash -> rollback.
	img2, drom2 := syntheticESP32Image(0x22, 9000)
	s := &Slots{dev: f, cfg: &cfg, Restart: func() {}}
	if err := streamUpdate(s, makePayload(img2, 0, drom2), 1024); err != nil {
		t.Fatalf("update 1: %v", err)
	}
	boot1, err := simESP32LoaderBoot(f)
	if err != nil || boot1.base != cfg.slotB || !boot1.trial || boot1.patchedDROM != 0x220000 {
		t.Fatalf("trial boot = %+v, %v; want slotB patchedDROM=0x220000", boot1, err)
	}
	// Reset without Confirm -> rolls back to SlotA (0x11000).
	bootRB, err := simESP32LoaderBoot(f)
	if err != nil || bootRB.base != cfg.slotA || !bootRB.rolledBack || bootRB.patchedDROM != 0x30000 {
		t.Fatalf("rollback boot = %+v, %v; want slotA patchedDROM=0x30000", bootRB, err)
	}

	// Re-apply update -> confirm SlotB -> ping-pong back to SlotA -> confirm.
	if err := streamUpdate(&Slots{dev: f, cfg: &cfg, Restart: func() {}}, makePayload(img2, 0, drom2), 777); err != nil {
		t.Fatalf("update 2: %v", err)
	}
	if boot, err := simESP32LoaderBoot(f); err != nil || boot.base != cfg.slotB || !boot.trial {
		t.Fatalf("boot SlotB = %+v, %v", boot, err)
	}
	if err := (&Slots{dev: f, cfg: &cfg}).Confirm(); err != nil {
		t.Fatalf("confirm SlotB: %v", err)
	}
	img3, drom3 := syntheticESP32Image(0x33, 6000)
	if err := streamUpdate(&Slots{dev: f, cfg: &cfg, Restart: func() {}}, makePayload(img3, 0, drom3), 1024); err != nil {
		t.Fatalf("update 3: %v", err)
	}
	if boot, err := simESP32LoaderBoot(f); err != nil || boot.base != cfg.slotA || boot.seq != 3 || boot.patchedDROM != 0x30000 {
		t.Fatalf("boot SlotA seq 3 = %+v, %v", boot, err)
	}
	for off := uint32(esp32StateBase); off < flashSize; off++ {
		if f.mem[off] != 0xFF {
			t.Fatalf("classic ESP32 state area modified at %#x", off)
		}
	}
}

func TestConstantsMatchESP32LoaderAndLinker(t *testing.T) {
	loaderSrc, err := os.ReadFile("../esp32-loader/main.go")
	if err != nil {
		t.Fatalf("read esp32-loader/main.go: %v", err)
	}
	defineRe := regexp.MustCompile(`(?m)^#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|[0-9]+)u?`)
	defs := map[string]uint32{}
	for _, m := range defineRe.FindAllStringSubmatch(string(loaderSrc), -1) {
		v, err := strconv.ParseUint(m[2], 0, 32)
		if err != nil {
			t.Fatalf("parse %s=%s: %v", m[1], m[2], err)
		}
		defs[m[1]] = uint32(v)
	}
	wantDefs := map[string]uint32{
		"BOOT_BASE":     layoutESP32.bootBase,
		"REC_A":         recA,
		"REC_B":         recB,
		"REC_MAGIC":     recMagic,
		"REC_TRIED":     recTried,
		"REC_CONFIRMED": recConfirmed,
		"APP_DRAM_LO":   esp32AppDRAMLo,
		"APP_DRAM_HI":   esp32AppDRAMHi,
		"APP_IRAM_LO":   esp32AppIRAMLo,
		"APP_IRAM_HI":   esp32AppIRAMHi,
	}
	for k, want := range wantDefs {
		if got, ok := defs[k]; !ok || got != want {
			t.Errorf("esp32-loader/main.go %s = %#x (ok=%v), want %#x", k, got, ok, want)
		}
	}
	if layoutESP32.slotB+layoutESP32.slotSize > esp32StateBase {
		t.Fatalf("ESP32 SlotB %#x+%#x overlaps state area %#x", layoutESP32.slotB, layoutESP32.slotSize, esp32StateBase)
	}
}

func TestRealESP32FirmwareArtifactsOTA(t *testing.T) {
	elfPath := os.Getenv("TMG_ESP32_ELF")
	binPath := os.Getenv("TMG_ESP32_BIN")
	if elfPath == "" || binPath == "" {
		t.Skip("set TMG_ESP32_ELF and TMG_ESP32_BIN to test real classic ESP32 firmware OTA artifacts")
	}
	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("open ELF: %v", err)
	}
	defer ef.Close()
	syms, err := ef.Symbols()
	if err != nil {
		t.Fatalf("ELF symbols: %v", err)
	}
	var drom uint32
	for _, sym := range syms {
		if sym.Name == "_drom_flash_addr" {
			drom = uint32(sym.Value)
			break
		}
	}
	if drom == 0 {
		t.Fatal("missing _drom_flash_addr")
	}
	binData, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read BIN: %v", err)
	}
	cfg := layoutESP32
	payload := makePayload(binData, 0, drom)
	f := newNORFlash()
	f.installConfirmed(t, recA, cfg.slotA, 1, binData, 0, drom)
	boot0, err := simESP32LoaderBoot(f)
	if err != nil || boot0.base != cfg.slotA || boot0.patchedDROM&0xFFFF != 0 {
		t.Fatalf("initial real ESP32 boot failed: %+v, %v", boot0, err)
	}
	t.Logf("real esp32 image: %d bytes (%.1f%% of slot), _drom_flash_addr=%#x, SlotA patched DROM=%#x",
		len(binData), 100*float64(len(binData))/float64(cfg.slotSize), drom, boot0.patchedDROM)

	runOTA := func(ver uint32, wantSlot uint32) {
		t.Helper()
		imgBytes, err := ota.Create(ota.Header{
			VendorID: 0xFFF1, ProductID: 0x8000, SoftwareVersion: ver,
			SoftwareVersionString: "0.2." + strconv.Itoa(int(ver)),
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		s := &Slots{dev: f, cfg: &cfg, Restart: func() {}}
		r := &ota.Reader{OnHeader: s.Begin, Payload: s.Write}
		for off := 0; off < len(imgBytes); off += 1024 {
			if err := r.Write(imgBytes[off:min(off+1024, len(imgBytes))]); err != nil {
				t.Fatalf("ota.Reader.Write: %v", err)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatalf("ota.Reader.Close: %v", err)
		}
		if err := s.Finish(); err != nil {
			t.Fatalf("Slots.Finish: %v", err)
		}
		boot, err := simESP32LoaderBoot(f)
		if err != nil || boot.base != wantSlot || !boot.trial || boot.patchedDROM&0xFFFF != 0 {
			t.Fatalf("boot into %#x failed: %+v, %v", wantSlot, boot, err)
		}
		t.Logf("booted real ESP32 image in slot %#x (seq %d), entry=%#x, patched DROM=%#x (64KB aligned!)",
			boot.base, boot.seq, boot.entry, boot.patchedDROM)
	}

	// Update SlotA -> SlotB, rollback before confirm, re-update -> confirm -> SlotB -> SlotA.
	runOTA(2, cfg.slotB)
	if boot, err := simESP32LoaderBoot(f); err != nil || boot.base != cfg.slotA || !boot.rolledBack {
		t.Fatalf("rollback failed: %+v, %v", boot, err)
	}
	runOTA(2, cfg.slotB)
	if err := (&Slots{dev: f, cfg: &cfg}).Confirm(); err != nil {
		t.Fatalf("confirm SlotB: %v", err)
	}
	runOTA(3, cfg.slotA)
	if err := (&Slots{dev: f, cfg: &cfg}).Confirm(); err != nil {
		t.Fatalf("confirm SlotA: %v", err)
	}
	for off := uint32(esp32StateBase); off < flashSize; off++ {
		if f.mem[off] != 0xFF {
			t.Fatalf("classic ESP32 state area modified at %#x", off)
		}
	}
}
