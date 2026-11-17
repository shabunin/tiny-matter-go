//go:build esp32

// Package esp32flash is the flash of a classic ESP32 as a block device
// (storage.BlockDevice), which TinyGo's machine package has only for the
// newer chips. It writes with the ROM's SPI flash routines; the classic
// ESP32 cannot read flash through the cache while it writes, so each write
// or erase runs from IRAM with interrupts off and the cache disabled.
package esp32flash

/*
#include <stdint.h>

#define IRAM __attribute__((section(".iram1.tmgflash"), noinline, used))

typedef int (*rom_read_t)(uint32_t addr, uint32_t *dst, uint32_t len);
typedef int (*rom_write_t)(uint32_t addr, const uint32_t *src, uint32_t len);
typedef int (*rom_erase_t)(uint32_t sector);
typedef void (*rom_cache_t)(int cpu);
typedef int (*rom_status_t)(void *chip, uint32_t *status);
typedef int (*rom_idle_t)(void *chip);

// ESP32 ROM addresses (esp-idf components/esp_rom/esp32/ld).
#define ROM_READ        ((rom_read_t)0x40062ed8)   // esp_rom_spiflash_read
#define ROM_WRITE       ((rom_write_t)0x40062d50)  // esp_rom_spiflash_write
#define ROM_ERASE       ((rom_erase_t)0x40062ccc)  // esp_rom_spiflash_erase_sector
#define CACHE_DISABLE   ((rom_cache_t)0x40009ab8)  // Cache_Read_Disable_rom
#define CACHE_ENABLE    ((rom_cache_t)0x40009a84)  // Cache_Read_Enable_rom
#define CACHE_FLUSH     ((rom_cache_t)0x40009a14)  // Cache_Flush_rom
#define ROM_STATUS      ((rom_status_t)0x40062448) // esp_rom_spiflash_read_statushigh
#define ROM_WAIT_IDLE   ((rom_idle_t)0x400622c0)   // esp_rom_spiflash_wait_idle
#define ROM_CHIP        ((void *)0x3ffae270)       // g_rom_flashchip

static inline uint32_t irq_off(void) {
	uint32_t ps;
	__asm__ volatile ("rsil %0, 15" : "=r"(ps) :: "memory");
	return ps;
}

static inline void irq_restore(uint32_t ps) {
	__asm__ volatile ("wsr %0, ps; rsync" :: "r"(ps) : "memory");
}

// op 0 writes len bytes of src at addr, op 1 erases the sector at addr and
// op 2 reads len bytes at addr into src.
IRAM int tmgflash_op(int op, uint32_t addr, const uint32_t *src, uint32_t len) {
	uint32_t ps = irq_off();
	CACHE_DISABLE(0);
	int r;
	// Run SPI1, which the ROM routines use, at 20 MHz with no extra dummy
	// cycles. At 80 MHz the ESP32-PICO-D4 (M5StickC), whose flash lines
	// partly go through the GPIO matrix, misreads the status register's
	// busy bit: the ROM returns mid-erase, and the cache then fetches
	// garbage. The cache uses SPI0, which keeps its clock.
	volatile uint32_t *spi1_clock = (volatile uint32_t *)0x3FF42018; // SPI1 CLOCK
	volatile uint8_t *dummy_plus = (volatile uint8_t *)0x3ffae290;   // g_rom_spiflash_dummy_len_plus
	uint32_t clock = *spi1_clock;
	uint8_t dummy1 = dummy_plus[1];
	*spi1_clock = (3 << 12) | (1 << 6) | 3; // CLKCNT_N 3, H 1, L 3: APB/4
	dummy_plus[1] = 0;
	if (op == 0) {
		r = ROM_WRITE(addr, src, len);
	} else if (op == 1) {
		r = ROM_ERASE(addr / 4096);
	} else if (op == 2) {
		r = ROM_READ(addr, (uint32_t *)src, len);
	} else {
		r = ROM_STATUS(ROM_CHIP, (uint32_t *)src);
	}
	// Make sure the chip is done before the cache fetches from it again.
	ROM_WAIT_IDLE(ROM_CHIP);
	*spi1_clock = clock;
	dummy_plus[1] = dummy1;
	CACHE_FLUSH(0);
	CACHE_ENABLE(0);
	irq_restore(ps);
	return r;
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Device is a region of the flash, from Offset (4 KB aligned) for Length
// bytes. Reads use the ROM too (the region is not mapped into the cache).
type Device struct {
	Offset, Length int64
}

// Status returns the flash status register (16 bits) and the ROM's
// result code.
func Status() (uint32, int) {
	var st [1]uint32
	r := C.tmgflash_op(3, 0, (*C.uint32_t)(unsafe.Pointer(&st[0])), 0)
	return st[0], int(r)
}

// Chip returns the ROM's flash chip record, for testing.
func Chip() [6]uint32 { return *romChip }

// Configure sets the ROM's flash size from the image header.
func Configure() { configure() }

// LastErr is the ROM result of the last failed operation (testing).
var LastErr int

var (
	errRange = errors.New("esp32flash: out of range")
	errFlash = errors.New("esp32flash: ROM routine failed")
)

// romChip is the ROM's flash chip record (esp_rom_spiflash_chip_t,
// g_rom_flashchip): device ID, size, block, sector and page sizes, status
// mask.
var romChip = (*[6]uint32)(unsafe.Pointer(uintptr(0x3ffae270)))

var configured bool

// configure gives the ROM the flash size from the image header. The ROM
// assumes 2 MB and refuses to read, write or erase beyond it; the esp-idf
// bootloader, which TinyGo does without, would correct it.
func configure() {
	if !configured {
		configured = true
		romChip[1] = uint32(FlashSize())
	}
}

// FlashSize returns the flash size the image header gives (4 MB if it
// gives none).
func FlashSize() int64 {
	var h [4]byte
	readROM(0x1000, h[:]) // the classic ESP32 boots the image at 0x1000
	if h[0] != 0xE9 || h[3]>>4 > 4 {
		return 4 << 20
	}
	return 1 << 20 << (h[3] >> 4)
}

func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > d.Length {
		return 0, errRange
	}
	configure()
	if !readROM(uint32(d.Offset+off), p) {
		return 0, errFlash
	}
	return len(p), nil
}

func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off%4 != 0 || off+int64(len(p)) > d.Length {
		return 0, errRange
	}
	configure()
	// Words in DRAM, padded with 0xFF (which leaves flash bits alone).
	buf := make([]uint32, (len(p)+3)/4)
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*4)
	for i := range b {
		b[i] = 0xFF
	}
	copy(b, p)
	if C.tmgflash_op(0, C.uint32_t(d.Offset+off), (*C.uint32_t)(unsafe.Pointer(&buf[0])), C.uint32_t(len(b))) != 0 {
		return 0, errFlash
	}
	return len(p), nil
}

func (d *Device) Size() int64           { return d.Length }
func (d *Device) WriteBlockSize() int64 { return 4 }
func (d *Device) EraseBlockSize() int64 { return 4096 }

func (d *Device) EraseBlocks(start, n int64) error {
	if d.Offset%4096 != 0 || start < 0 || (start+n)*4096 > d.Length {
		return errRange
	}
	configure()
	for i := int64(0); i < n; i++ {
		if r := C.tmgflash_op(1, C.uint32_t(d.Offset+(start+i)*4096), nil, 0); r != 0 {
			LastErr = int(r)
			return errFlash
		}
	}
	return nil
}

// readROM reads flash at addr into p, through an aligned word buffer. It
// reports whether the ROM read it.
func readROM(addr uint32, p []byte) bool {
	if len(p) == 0 {
		return true
	}
	start := addr &^ 3
	n := (addr - start + uint32(len(p)) + 3) &^ 3
	buf := make([]uint32, n/4)
	if C.tmgflash_op(2, C.uint32_t(start), (*C.uint32_t)(unsafe.Pointer(&buf[0])), C.uint32_t(n)) != 0 {
		return false
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), n)
	copy(p, b[addr-start:])
	return true
}
