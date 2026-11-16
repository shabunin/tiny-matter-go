//go:build esp32s3

package espota

import (
	"device/esp"
	"time"
)

// rtcSlowHz is the RTC slow clock the watchdog counts (the internal
// 136 kHz RC oscillator, which TinyGo leaves selected).
const rtcSlowHz = 136_000

const (
	wdtKey        = 0x50D83AA1
	wdtResetRTC   = 4 // stage action: reset the whole chip, RTC included
	wdtResetLen   = 7 // 3.2 µs CPU and system reset pulses
	maxGuardTicks = 1<<32 - 1
)

// Guard arms the RTC watchdog when the running image is on trial (not yet
// confirmed), so an image that hangs instead of crashing also resets and
// the loader rolls it back; Confirm disarms it. Call it first thing in
// main: TinyGo's startup disables every watchdog, so the loader cannot arm
// one. It reports whether it armed the watchdog.
func (s *Slots) Guard(timeout time.Duration) bool {
	if _, _, confirmed, ok := s.Running(); !ok || confirmed {
		return false
	}
	ticks := uint64(timeout/time.Millisecond) * rtcSlowHz / 1000
	// The chip holds stage 0 for 2^(1+WDT_DELAY_SEL) times the value set
	// (an eFuse), as ESP-IDF accounts for.
	ticks >>= 1 + esp.EFUSE.GetRD_REPEAT_DATA1_WDT_DELAY_SEL()
	if ticks > maxGuardTicks {
		ticks = maxGuardTicks
	}
	esp.RTC_CNTL.WDTWPROTECT.Set(wdtKey)
	esp.RTC_CNTL.WDTCONFIG0.Set(0)
	esp.RTC_CNTL.WDTCONFIG1.Set(uint32(ticks))
	esp.RTC_CNTL.WDTCONFIG0.Set(esp.RTC_CNTL_WDTCONFIG0_WDT_EN |
		wdtResetRTC<<esp.RTC_CNTL_WDTCONFIG0_WDT_STG0_Pos |
		wdtResetLen<<esp.RTC_CNTL_WDTCONFIG0_WDT_SYS_RESET_LENGTH_Pos |
		wdtResetLen<<esp.RTC_CNTL_WDTCONFIG0_WDT_CPU_RESET_LENGTH_Pos)
	esp.RTC_CNTL.WDTFEED.Set(esp.RTC_CNTL_WDTFEED_WDT_FEED)
	esp.RTC_CNTL.WDTWPROTECT.Set(0)
	s.guarded = true
	s.log("trial image: watchdog armed for " + timeout.String())
	return true
}

// unguard disarms the watchdog Guard armed.
func (s *Slots) unguard() {
	if !s.guarded {
		return
	}
	esp.RTC_CNTL.WDTWPROTECT.Set(wdtKey)
	esp.RTC_CNTL.WDTCONFIG0.Set(0)
	esp.RTC_CNTL.WDTWPROTECT.Set(0)
	s.guarded = false
}
