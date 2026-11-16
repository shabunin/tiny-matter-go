// Command esp32s3-loader is a second-stage boot loader for TinyGo
// firmware on the ESP32-S3 with two application slots, for over-the-air
// updates with rollback.
//
// The ROM boots the loader from flash offset 0. The loader reads two boot
// records (at 0xE000 and 0xF000), picks the newest valid one and starts
// the image in its slot: it copies the image's RAM segments, then adds
// the slot's flash offset to the two words in which the TinyGo startup
// code finds the physical flash offsets of its code and read-only data
// (_irom_flash_addr and _drom_flash_addr, whose RAM addresses the record
// holds; TinyGo places them unaligned), and jumps to the image's entry point. The image maps its flash
// itself, so it runs from any 64 KB-aligned slot.
//
// A record is tried once: the loader marks it tried before starting its
// image, and the image marks it confirmed once it works. A record that
// was tried and never confirmed (the image crashed or hung and the board
// was reset) is skipped for the other record: the update rolls back.
//
// Boot record (little endian, at the start of its 4 KB sector):
//
//	0x00 magic "TMGB"   0x04 sequence   0x08 slot offset   0x0C image length
//	0x10 _irom_flash_addr RAM address   0x14 _drom_flash_addr RAM address
//	0x18 CRC-32 of 0x00-0x17
//	0x100 tried (0xFFFFFFFF until tried)   0x104 confirmed (0 once confirmed)
//
// The loader is C in the cgo preamble, so no Go runtime runs: the linker
// script makes loader_entry the entry point and places everything in
// SRAM above the application's segments.
//
//	tinygo build -target ./esp32s3-loader/target.json -o loader.elf ./esp32s3-loader
//	esptool --chip esp32s3 elf2image --flash-mode dio --flash-size 8MB -o loader.bin loader.elf
package main

/*
#include <stdint.h>

extern int esp_rom_spiflash_read(uint32_t src, uint32_t *dst, uint32_t len);
extern int esp_rom_spiflash_write(uint32_t dst, const uint32_t *src, uint32_t len);
extern int esp_rom_spiflash_unlock(void);
extern int ets_printf(const char *fmt, ...);

#define REC_A 0xE000u
#define REC_B 0xF000u
#define REC_MAGIC 0x42474D54u
#define REC_TRIED 0x100u
#define REC_CONFIRMED 0x104u

// The application's segments must lie below the loader, which occupies
// DRAM 0x3FCD8000-0x3FCE8000 (its code through the IRAM alias), with the
// ROM stack above it.
#define APP_DRAM_LO 0x3FC88000u
#define APP_DRAM_HI 0x3FCD8000u
#define APP_IRAM_LO 0x40378000u
#define APP_IRAM_HI 0x403C8000u
#define IRAM_TO_DRAM 0x6F0000u

typedef struct {
	uint32_t magic, seq, base, length, irom_ptr, drom_ptr, crc;
	uint32_t tried, confirmed;
	int ok;
} rec_t;

static uint32_t crc32(const uint8_t *p, uint32_t n) {
	uint32_t c = 0xFFFFFFFFu;
	for (uint32_t i = 0; i < n; i++) {
		c ^= p[i];
		for (int k = 0; k < 8; k++) {
			c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
		}
	}
	return ~c;
}

static void read_rec(uint32_t addr, rec_t *r) {
	uint32_t w[7], flags[2];
	r->ok = 0;
	if (esp_rom_spiflash_read(addr, w, sizeof w) != 0 ||
	    esp_rom_spiflash_read(addr + REC_TRIED, flags, sizeof flags) != 0) {
		return;
	}
	r->magic = w[0]; r->seq = w[1]; r->base = w[2]; r->length = w[3];
	r->irom_ptr = w[4]; r->drom_ptr = w[5]; r->crc = w[6];
	r->tried = flags[0]; r->confirmed = flags[1];
	r->ok = r->magic == REC_MAGIC && r->crc == crc32((const uint8_t *)w, 24) &&
		(r->base & 0xFFFFu) == 0 && r->base >= 0x10000u;
}

static int in_dram(uint32_t a, uint32_t n) {
	return a >= APP_DRAM_LO && a + n <= APP_DRAM_HI && a + n >= a;
}

static int in_iram(uint32_t a, uint32_t n) {
	return a >= APP_IRAM_LO && a + n <= APP_IRAM_HI && a + n >= a;
}

// add_le adds v to the little-endian word at addr, byte by byte: TinyGo
// places the flash offset words without alignment.
static void add_le(uint32_t addr, uint32_t v) {
	volatile uint8_t *p = (volatile uint8_t *)addr;
	uint32_t w = p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
	w += v;
	p[0] = w; p[1] = w >> 8; p[2] = w >> 16; p[3] = w >> 24;
}

// load copies the image's RAM segments and patches its flash offsets. It
// returns the entry point, or 0 if the image is unusable.
static uint32_t load(const rec_t *r) {
	uint32_t h[6];
	if (esp_rom_spiflash_read(r->base, h, sizeof h) != 0) {
		ets_printf("loader: cannot read 0x%x\n", r->base);
		return 0;
	}
	uint32_t nseg = (h[0] >> 8) & 0xFF;
	uint32_t entry = h[1];
	uint32_t chip = h[3] & 0xFFFF; // extended header byte 12: chip ID
	if ((h[0] & 0xFF) != 0xE9 || chip != 9 || nseg == 0 || nseg > 16) {
		ets_printf("loader: no ESP32-S3 image at 0x%x\n", r->base);
		return 0;
	}
	uint32_t off = r->base + 24;
	uint8_t sum = 0xEF;
	int patched = 0;
	for (uint32_t i = 0; i < nseg; i++) {
		uint32_t sh[2];
		if (esp_rom_spiflash_read(off, sh, sizeof sh) != 0) {
			return 0;
		}
		uint32_t addr = sh[0], len = sh[1], dst;
		off += 8;
		if ((len & 3) != 0 || (addr & 3) != 0) {
			return 0;
		}
		if (in_dram(addr, len)) {
			dst = addr;
		} else if (in_iram(addr, len)) {
			dst = addr - IRAM_TO_DRAM;
		} else {
			ets_printf("loader: segment 0x%x+0x%x outside the application area\n", addr, len);
			return 0;
		}
		if (len > 0 && esp_rom_spiflash_read(off, (uint32_t *)dst, len) != 0) {
			return 0;
		}
		const uint8_t *p = (const uint8_t *)dst;
		for (uint32_t k = 0; k < len; k++) {
			sum ^= p[k];
		}
		if (in_dram(addr, len)) {
			if (r->irom_ptr >= addr && r->irom_ptr + 4 <= addr + len) {
				patched |= 1;
			}
			if (r->drom_ptr >= addr && r->drom_ptr + 4 <= addr + len) {
				patched |= 2;
			}
		}
		off += len;
	}
	// The checksum is the last byte of the 16-byte aligned header and
	// segments (the SHA-256 digest that may follow is not checked).
	uint32_t end = ((off - r->base) | 15) + r->base;
	uint32_t last[1];
	if (esp_rom_spiflash_read(end - 3, last, 4) != 0 || (uint8_t)(last[0] >> 24) != sum) {
		ets_printf("loader: image at 0x%x: bad checksum\n", r->base);
		return 0;
	}
	if (patched != 3) {
		ets_printf("loader: image at 0x%x: flash offset words not in its data\n", r->base);
		return 0;
	}
	add_le(r->irom_ptr, r->base);
	add_le(r->drom_ptr, r->base);
	return entry;
}

static void start(uint32_t entry) {
	__asm__ volatile("memw\nisync");
	((void (*)(void))entry)();
	for (;;) {
	}
}

// The ROM's flash driver assumes a 2 MB chip until told otherwise; the
// size comes from the loader's own image header (byte 3, high nibble).
typedef struct {
	uint32_t device_id, chip_size, block_size, sector_size, page_size, status_mask;
} rom_flash_chip_t;
extern rom_flash_chip_t *rom_spiflash_legacy_data;

static void set_flash_size(void) {
	uint32_t h;
	if (esp_rom_spiflash_read(0, &h, 4) == 0 && (h & 0xFF) == 0xE9 && (h >> 28) <= 7) {
		rom_spiflash_legacy_data->chip_size = 1u << 20 << (h >> 28);
	}
}

void loader_entry(void) {
	set_flash_size();
	rec_t a, b;
	read_rec(REC_A, &a);
	read_rec(REC_B, &b);
	rec_t *cur = 0, *prev = 0;
	if (a.ok && (!b.ok || a.seq > b.seq)) {
		cur = &a; prev = b.ok ? &b : 0;
	} else if (b.ok) {
		cur = &b; prev = a.ok ? &a : 0;
	}
	uint32_t cur_addr = cur == &a ? REC_A : REC_B;
	if (cur && prev && cur->confirmed != 0 && cur->tried == 0) {
		ets_printf("loader: record %u (slot 0x%x) was tried and never confirmed: rolling back\n", cur->seq, cur->base);
		cur = prev;
		prev = 0;
		cur_addr = cur == &a ? REC_A : REC_B;
	}
	if (!cur) {
		ets_printf("loader: no bootable record\n");
		for (;;) {
		}
	}
	if (cur->confirmed != 0 && cur->tried != 0) {
		uint32_t zero = 0;
		esp_rom_spiflash_unlock();
		esp_rom_spiflash_write(cur_addr + REC_TRIED, &zero, 4);
	}
	ets_printf("loader: record %u, slot 0x%x%s\n", cur->seq, cur->base, cur->confirmed ? " (trial)" : "");
	uint32_t entry = load(cur);
	if (entry == 0 && prev) {
		ets_printf("loader: falling back to record %u\n", prev->seq);
		entry = load(prev);
	}
	if (entry == 0) {
		ets_printf("loader: nothing to start\n");
		for (;;) {
		}
	}
	start(entry);
}
*/
import "C"

func main() {}
