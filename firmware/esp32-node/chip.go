package main

import (
	"device/esp"
	"runtime/volatile"
	"unsafe"

	"github.com/shabunin/tiny-matter-go/clusters"
)

// restart performs a software system reset.
func restart() {
	esp.RTC_CNTL.OPTIONS0.SetBits(esp.RTC_CNTL_OPTIONS0_SW_SYS_RST)
	for {
	}
}

// factoryMAC reads the base MAC (the Wi-Fi station address) from eFuse.
func factoryMAC() [6]byte {
	lo := esp.EFUSE.BLK0_RDATA1.Get()
	hi := esp.EFUSE.BLK0_RDATA2.Get()
	return [6]byte{byte(hi >> 8), byte(hi), byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)}
}

// resetCause returns why the CPU last reset (RTC_CNTL_RESET_CAUSE_PROCPU).
func resetCause() uint32 { return esp.RTC_CNTL.GetRESET_STATE_RESET_CAUSE_PROCPU() }

// bootReason maps the ESP32's reset cause to a General Diagnostics boot
// reason.
func bootReason(cause uint32) uint8 {
	switch cause {
	case 0x01: // power on
		return clusters.BootPowerOn
	case 0x0F:
		return clusters.BootBrownOut
	case 0x07, 0x08: // timer group watchdogs
		return clusters.BootSoftwareWatchdog
	case 0x09, 0x10: // RTC watchdogs
		return clusters.BootHardwareWatchdog
	case 0x03, 0x0C: // software system or CPU reset
		return clusters.BootSoftwareReset
	}
	return clusters.BootUnspecified
}

// hwRand reads the ESP32's hardware random number generator (TinyGo's
// crypto/rand has none on the classic ESP32). Its numbers are true random
// while the radio is on, as it is before any key is made.
type hwRand struct{}

const rngReg = 0x3FF75144 // WDEV_RND_REG

func (hwRand) Read(b []byte) (int, error) {
	r := (*volatile.Register32)(unsafe.Pointer(uintptr(rngReg)))
	for i := 0; i < len(b); i += 4 {
		v := r.Get()
		for j := 0; j < 4 && i+j < len(b); j++ {
			b[i+j] = byte(v >> (8 * j))
		}
		spin(16) // the TRM wants reads no faster than 5 MHz
	}
	return len(b), nil
}

//go:noinline
func spin(n int) {
	for i := 0; i < n; i++ {
		spinSink++
	}
}

var spinSink int
