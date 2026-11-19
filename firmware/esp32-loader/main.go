// Command esp32-loader is a second-stage boot loader for TinyGo firmware
// on the classic ESP32 (M5Stack Core / M5GO, M5StickC Plus) with two
// application slots, for over-the-air updates with rollback.
//
// The ROM boots the loader from flash offset 0x1000. The loader reads two
// boot records (at 0xE000 and 0xF000), picks the newest valid one and
// starts the image in its slot: it copies the image's DRAM and IRAM
// segments (word-wise, as classic ESP32 IRAM requires 32-bit accesses),
// then adds (slot - 0x1000) to _drom_flash_addr (the word in which TinyGo's
// startup code finds the physical flash offset of .rodata; .text follows it
// on the next 64 KB boundary), and jumps to the image's entry point.
//
// Because TinyGo builds classic ESP32 images assuming they are flashed at
// 0x1000 (so .rodata lands on a 64 KB MMU page boundary), each slot starts
// at 64 KB * N + 0x1000: Slot A at 0x11000 and Slot B at 0x201000, each
// 0x1F0000 bytes (ending at 0x3F1000, leaving the state store in the last
// 32 KB of the 4 MB flash untouched).
//
// A record is tried once: the loader marks it tried before starting its
// image, and the image marks it confirmed once it works. A record that was
// tried and never confirmed is skipped for the other record: the update
// rolls back.
//
// Boot record (little endian, at the start of its 4 KB sector, same layout
// as esp32s3-loader with irom_ptr = 0):
//
//	0x00 magic "TMGB"   0x04 sequence   0x08 slot offset   0x0C image length
//	0x10 0 (unused)     0x14 _drom_flash_addr RAM address
//	0x18 CRC-32 of 0x00-0x17
//	0x100 tried (0xFFFFFFFF until tried)   0x104 confirmed (0 once confirmed)
//
//	tinygo build -target ./esp32-loader/target.json -o loader.elf ./esp32-loader
//	esptool --chip esp32 elf2image --flash-mode dio --flash-freq 40m --flash-size 4MB -o loader.bin loader.elf
package main

/*
#include <stdint.h>

typedef struct {
	uint32_t device_id, chip_size, block_size, sector_size, page_size, status_mask;
} rom_flash_chip_t;

extern int esp_rom_spiflash_read(uint32_t src, uint32_t *dst, uint32_t len);
extern int esp_rom_spiflash_write(uint32_t dst, const uint32_t *src, uint32_t len);
extern int esp_rom_spiflash_wait_idle(rom_flash_chip_t *chip);
extern int ets_printf(const char *fmt, ...);
extern rom_flash_chip_t g_rom_flashchip;

#define BOOT_BASE 0x1000u
#define REC_A 0xE000u
#define REC_B 0xF000u
#define REC_MAGIC 0x42474D54u
#define REC_TRIED 0x100u
#define REC_CONFIRMED 0x104u

// Application SRAM regions (must not overlap the loader at DRAM 0x3FFF0000
// or IRAM 0x4009C000).
#define APP_DRAM_LO 0x3FFB0000u
#define APP_DRAM_HI 0x3FFE0000u
#define APP_IRAM_LO 0x40080000u
#define APP_IRAM_HI 0x4009C000u

// Run SPI1 at 20 MHz with no extra dummy cycles during ROM flash calls so
// the ESP32-PICO-D4 (M5StickC), whose flash pins go through the GPIO
// matrix, reads the status register cleanly (same workaround as esp32flash).
static int flash_op(int write, uint32_t addr, uint32_t *buf, uint32_t len) {
	volatile uint32_t *spi1_clock = (volatile uint32_t *)0x3FF42018u;
	volatile uint8_t *dummy_plus = (volatile uint8_t *)0x3ffae290u;
	uint32_t clock = *spi1_clock;
	uint8_t dummy1 = dummy_plus[1];
	*spi1_clock = (3u << 12) | (1u << 6) | 3u;
	dummy_plus[1] = 0;
	int r = write ? esp_rom_spiflash_write(addr, buf, len) : esp_rom_spiflash_read(addr, buf, len);
	esp_rom_spiflash_wait_idle(&g_rom_flashchip);
	*spi1_clock = clock;
	dummy_plus[1] = dummy1;
	return r;
}

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
	if (flash_op(0, addr, w, sizeof w) != 0 ||
	    flash_op(0, addr + REC_TRIED, flags, sizeof flags) != 0) {
		return;
	}
	r->magic = w[0]; r->seq = w[1]; r->base = w[2]; r->length = w[3];
	r->irom_ptr = w[4]; r->drom_ptr = w[5]; r->crc = w[6];
	r->tried = flags[0]; r->confirmed = flags[1];
	r->ok = r->magic == REC_MAGIC && r->crc == crc32((const uint8_t *)w, 24) &&
		(r->base & 0xFFFFu) == BOOT_BASE && r->base >= 0x11000u;
}

static int in_dram(uint32_t a, uint32_t n) {
	return a >= APP_DRAM_LO && a + n <= APP_DRAM_HI && a + n >= a;
}

static int in_iram(uint32_t a, uint32_t n) {
	return a >= APP_IRAM_LO && a + n <= APP_IRAM_HI && a + n >= a;
}

static void add_le(uint32_t addr, uint32_t v) {
	volatile uint8_t *p = (volatile uint8_t *)addr;
	uint32_t w = p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
	w += v;
	p[0] = w; p[1] = w >> 8; p[2] = w >> 16; p[3] = w >> 24;
}

// load copies the image's DRAM and IRAM segments and patches _drom_flash_addr.
// Returns the entry point, or 0 if the image is unusable.
static uint32_t load(const rec_t *r) {
	uint32_t h[6];
	if (flash_op(0, r->base, h, sizeof h) != 0) {
		ets_printf("loader: cannot read 0x%x\n", r->base);
		return 0;
	}
	uint32_t nseg = (h[0] >> 8) & 0xFF;
	uint32_t entry = h[1];
	uint32_t chip = h[3] & 0xFFFF; // extended header byte 12: chip ID (0 = ESP32)
	if ((h[0] & 0xFF) != 0xE9 || chip != 0 || nseg == 0 || nseg > 16) {
		ets_printf("loader: no ESP32 image at 0x%x\n", r->base);
		return 0;
	}
	uint32_t off = r->base + 24;
	uint8_t sum = 0xEF;
	int patched = 0;
	uint32_t tmp[64]; // 256-byte staging buffer in DRAM for word-wise IRAM copies
	for (uint32_t i = 0; i < nseg; i++) {
		uint32_t sh[2];
		if (flash_op(0, off, sh, sizeof sh) != 0) {
			return 0;
		}
		uint32_t addr = sh[0], len = sh[1];
		off += 8;
		if ((len & 3) != 0 || (addr & 3) != 0) {
			return 0;
		}
		int dram = in_dram(addr, len);
		if (!dram && !in_iram(addr, len)) {
			ets_printf("loader: segment 0x%x+0x%x outside the application area\n", addr, len);
			return 0;
		}
		volatile uint32_t *dst = (volatile uint32_t *)addr;
		uint32_t rem = len;
		while (rem > 0) {
			uint32_t n = rem > sizeof tmp ? (uint32_t)sizeof tmp : rem;
			if (flash_op(0, off, tmp, n) != 0) {
				return 0;
			}
			const uint8_t *p = (const uint8_t *)tmp;
			for (uint32_t k = 0; k < n; k++) {
				sum ^= p[k];
			}
			for (uint32_t w = 0; w < n / 4; w++) {
				dst[w] = tmp[w];
			}
			dst += n / 4;
			off += n;
			rem -= n;
		}
		if (dram && r->drom_ptr >= addr && r->drom_ptr + 4 <= addr + len) {
			patched = 1;
		}
	}
	// Checksum is the last byte of the 16-byte aligned header and segments.
	uint32_t end = ((off - r->base) | 15) + r->base;
	uint32_t last[1];
	if (flash_op(0, end - 3, last, 4) != 0 || (uint8_t)(last[0] >> 24) != sum) {
		ets_printf("loader: image at 0x%x: bad checksum\n", r->base);
		return 0;
	}
	if (!patched) {
		ets_printf("loader: image at 0x%x: _drom_flash_addr not in its data\n", r->base);
		return 0;
	}
	add_le(r->drom_ptr, r->base - BOOT_BASE);
	return entry;
}

static void start(uint32_t entry) {
	__asm__ volatile("memw\nisync");
	((void (*)(void))entry)();
	for (;;) {
	}
}

// Tell the ROM flash driver the chip size from the loader's header at 0x1000
// (the ROM assumes 2 MB until updated).
static void set_flash_size(void) {
	uint32_t h = 0;
	if (flash_op(0, BOOT_BASE, &h, 4) == 0 && (h & 0xFF) == 0xE9 && (h >> 28) <= 4) {
		g_rom_flashchip.chip_size = 1u << 20 << (h >> 28);
	} else {
		g_rom_flashchip.chip_size = 4u << 20;
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
		flash_op(1, cur_addr + REC_TRIED, &zero, 4);
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
