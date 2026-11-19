//go:build esp32s3

package espota

/*
#include <stdint.h>
extern int esp_rom_spiflash_read(uint32_t src, uint32_t *dst, uint32_t len);
extern int esp_rom_spiflash_write(uint32_t dst, const uint32_t *src, uint32_t len);
extern int esp_rom_spiflash_erase_sector(uint32_t sector);
extern int esp_rom_spiflash_unlock(void);
*/
import "C"

import (
	"runtime/interrupt"
	"unsafe"
)

const (
	// SlotA and SlotB are the two application slot offsets on ESP32-S3.
	SlotA = 0x10000
	SlotB = 0x200000
)

var defaultLayout = layoutESP32S3

//go:linkname flashSafeEnter runtime.esp32s3EnterFlashSafeSection
func flashSafeEnter() (interrupt.State, bool)

//go:linkname flashSafeExit runtime.esp32s3ExitFlashSafeSection
func flashSafeExit(state interrupt.State, multicore bool)

type romFlashChip struct {
	deviceID, chipSize, blockSize, sectorSize, pageSize, statusMask uint32
}

//go:extern rom_spiflash_legacy_data
var romFlashLegacy *romFlashChip

// setChipSize tells the ROM routines the flash size from the image header
// at offset 0 (they assume 2 MB).
func setChipSize() {
	var h uint32
	if C.esp_rom_spiflash_read(0, (*C.uint32_t)(unsafe.Pointer(&h)), 4) == 0 && byte(h) == espImageMagic && h>>28 <= 7 {
		romFlashLegacy.chipSize = 1 << 20 << (h >> 28)
	}
}

func hwFlashRead(addr uint32, p []uint32) error {
	st, mc := flashSafeEnter()
	res := C.esp_rom_spiflash_read(C.uint32_t(addr), (*C.uint32_t)(unsafe.Pointer(&p[0])), C.uint32_t(4*len(p)))
	flashSafeExit(st, mc)
	if res != 0 {
		return errFlash
	}
	return nil
}

// hwFlashWrite programs words (already erased, or only clearing bits).
func hwFlashWrite(addr uint32, p []uint32) error {
	st, mc := flashSafeEnter()
	setChipSize()
	C.esp_rom_spiflash_unlock()
	res := C.esp_rom_spiflash_write(C.uint32_t(addr), (*C.uint32_t)(unsafe.Pointer(&p[0])), C.uint32_t(4*len(p)))
	flashSafeExit(st, mc)
	if res != 0 {
		return errFlash
	}
	return nil
}

// hwWriteSector erases a sector and writes buf to it.
func hwWriteSector(addr uint32, data *[sector / 4]uint32) error {
	st, mc := flashSafeEnter()
	setChipSize()
	C.esp_rom_spiflash_unlock()
	res := C.esp_rom_spiflash_erase_sector(C.uint32_t(addr / sector))
	if res == 0 {
		res = C.esp_rom_spiflash_write(C.uint32_t(addr), (*C.uint32_t)(unsafe.Pointer(&data[0])), sector)
	}
	flashSafeExit(st, mc)
	if res != 0 {
		return errFlash
	}
	return nil
}

// hwRunningBase returns the flash offset of the running image, from the
// MMU entry that maps its read-only data.
func hwRunningBase() uint32 {
	s := "espota running image"
	v := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	if v < 0x3C000000 || v >= 0x3E000000 {
		return 0
	}
	entry := *(*uint32)(unsafe.Pointer(uintptr(0x600C5000) + 4*((v-0x3C000000)>>16)))
	if entry&(1<<14) != 0 { // invalid
		return 0
	}
	phys := entry & 0x3FFF << 16
	switch {
	case phys >= SlotB && phys < SlotB+slotSize:
		return SlotB
	case phys >= SlotA && phys < SlotB:
		return SlotA
	}
	return 0
}
