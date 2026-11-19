//go:build esp32

package espota

import (
	"firmware/esp32flash"
	"unsafe"
)

const (
	// SlotA and SlotB are the two application slot offsets on classic ESP32
	// (each 64 KB * N + 0x1000, matching TinyGo's 0x1000 boot offset so
	// .rodata lands on a 64 KB MMU page boundary).
	SlotA = 0x11000
	SlotB = 0x201000
)

var defaultLayout = layoutESP32

func hwFlashRead(addr uint32, p []uint32) error {
	return esp32flash.ReadWords(addr, p)
}

func hwFlashWrite(addr uint32, p []uint32) error {
	return esp32flash.WriteWords(addr, p)
}

func hwWriteSector(addr uint32, data *[sector / 4]uint32) error {
	return esp32flash.EraseAndWriteSector(addr, data)
}

// hwRunningBase returns the flash offset of the running image, from entry 0
// of the classic ESP32 PRO CPU flash MMU table (which maps DROM at
// 0x3F400000).
func hwRunningBase() uint32 {
	entry := *(*uint32)(unsafe.Pointer(uintptr(0x3FF10000)))
	if entry&0x100 != 0 { // invalid entry
		return 0
	}
	phys := (entry & 0xFF) << 16
	switch {
	case phys >= SlotB && phys < SlotB+slotSize:
		return SlotB
	case phys >= SlotA && phys < SlotB:
		return SlotA
	}
	return 0
}
