//go:build rp2350

package rpota

/*
#include <stdint.h>

// Boot ROM functions, looked up in the ROM's table (RP2350 datasheet 5.4.8).
typedef void *(*rom_table_lookup_fn)(uint32_t code, uint32_t mask);
#define ROM_CODE(c1, c2) ((c1) | ((c2) << 8))
#define RT_FLAG_FUNC_ARM_SEC 0x0004

static void *rom_func(uint32_t code) {
	rom_table_lookup_fn lookup = (rom_table_lookup_fn)(uintptr_t)*(uint16_t *)0x16;
	return lookup(code, RT_FLAG_FUNC_ARM_SEC);
}

static int rom_get_sys_info(uint32_t *buf, uint32_t words, uint32_t flags) {
	int (*f)(uint32_t *, uint32_t, uint32_t) = rom_func(ROM_CODE('G', 'S'));
	return f(buf, words, flags);
}

static int rom_explicit_buy(uint8_t *buf, uint32_t size) {
	int (*f)(uint8_t *, uint32_t) = rom_func(ROM_CODE('E', 'B'));
	return f(buf, size);
}

static int rom_reboot(uint32_t flags, uint32_t delay_ms, uint32_t p0, uint32_t p1) {
	int (*f)(uint32_t, uint32_t, uint32_t, uint32_t) = rom_func(ROM_CODE('R', 'B'));
	return f(flags, delay_ms, p0, p1);
}
*/
import "C"

import (
	"runtime/interrupt"
	"strconv"
	"unsafe"
)

const (
	sysInfoBootInfo = 0x0040
	tbybBuyPending  = 0x01

	rebootFlashUpdate = 0x0004
	rebootNoReturn    = 0x0100
)

// BootInfo is what the boot ROM recorded about the last boot.
type BootInfo struct {
	Partition  int  // the partition booted, -1 for none (an image at 0)
	Type       int  // 0 normal, 4 FLASH_UPDATE, ...
	BuyPending bool // a TBYB image that must confirm itself
	Diagnostic uint32
	Param0     uint32 // the last reboot's p0
}

// ReadBootInfo asks the boot ROM about the last boot.
func ReadBootInfo() (BootInfo, bool) {
	var buf [8]uint32
	n := C.rom_get_sys_info((*C.uint32_t)(unsafe.Pointer(&buf[0])), C.uint32_t(len(buf)), sysInfoBootInfo)
	if n < 5 || buf[0]&sysInfoBootInfo == 0 {
		return BootInfo{}, false
	}
	w := buf[1]
	return BootInfo{
		Partition:  int(int8(w >> 16)),
		Type:       int(w >> 8 & 0xff),
		BuyPending: w>>24&tbybBuyPending != 0,
		Diagnostic: buf[2],
		Param0:     buf[3],
	}, true
}

func (b BootInfo) String() string {
	return "partition " + strconv.Itoa(b.Partition) + " type " + strconv.Itoa(b.Type) +
		" buy pending " + strconv.FormatBool(b.BuyPending) +
		" diagnostic 0x" + strconv.FormatUint(uint64(b.Diagnostic), 16) +
		" p0 0x" + strconv.FormatUint(uint64(b.Param0), 16)
}

// explicitBuy confirms the running TBYB image: the ROM clears its flag and
// erases the first sector of the other partition. It needs 4 KB of scratch
// space; interrupts are off while the flash is out of XIP mode.
func explicitBuy(scratch *[SectorSize]byte) int {
	state := interrupt.Disable()
	r := C.rom_explicit_buy((*C.uint8_t)(unsafe.Pointer(&scratch[0])), SectorSize)
	interrupt.Restore(state)
	return int(r)
}

// rebootFlashUpdated reboots so that the boot ROM prefers the image in the
// partition starting at the flash offset start. It returns only on failure.
func rebootFlashUpdated(start uint32) int {
	return int(C.rom_reboot(rebootFlashUpdate|rebootNoReturn, 10, XIPBase+C.uint32_t(start), 0))
}
