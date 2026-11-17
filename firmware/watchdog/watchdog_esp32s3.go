//go:build esp32s3

package watchdog

import "device/esp"

// nominalSlowHz is the nominal frequency of the RTC slow clock the
// watchdog counts: the internal RC oscillator, which TinyGo leaves
// selected.
const nominalSlowHz = 136_000

// rtcTime reads the RTC timer, which counts the slow clock.
func rtcTime() uint64 {
	esp.RTC_CNTL.TIME_UPDATE.Set(esp.RTC_CNTL_TIME_UPDATE_TIME_UPDATE)
	return uint64(esp.RTC_CNTL.TIME_HIGH0.Get()&0xFFFF)<<32 | uint64(esp.RTC_CNTL.TIME_LOW0.Get())
}

// delayShift accounts for the chip holding stage 0 for 2^(1+WDT_DELAY_SEL)
// times the value set (an eFuse), as ESP-IDF does.
func delayShift() uint { return 1 + uint(esp.EFUSE.GetRD_REPEAT_DATA1_WDT_DELAY_SEL()) }

func start(ticks uint32) {
	esp.RTC_CNTL.WDTWPROTECT.Set(wdtKey)
	esp.RTC_CNTL.WDTCONFIG0.Set(0)
	esp.RTC_CNTL.WDTCONFIG1.Set(ticks)
	esp.RTC_CNTL.WDTCONFIG0.Set(esp.RTC_CNTL_WDTCONFIG0_WDT_EN |
		wdtResetRTC<<esp.RTC_CNTL_WDTCONFIG0_WDT_STG0_Pos |
		wdtResetLen<<esp.RTC_CNTL_WDTCONFIG0_WDT_SYS_RESET_LENGTH_Pos |
		wdtResetLen<<esp.RTC_CNTL_WDTCONFIG0_WDT_CPU_RESET_LENGTH_Pos)
	esp.RTC_CNTL.WDTFEED.Set(esp.RTC_CNTL_WDTFEED_WDT_FEED)
	esp.RTC_CNTL.WDTWPROTECT.Set(0)
}

// Feed restarts the watchdog's count.
func Feed() {
	esp.RTC_CNTL.WDTWPROTECT.Set(wdtKey)
	esp.RTC_CNTL.WDTFEED.Set(esp.RTC_CNTL_WDTFEED_WDT_FEED)
	esp.RTC_CNTL.WDTWPROTECT.Set(0)
}

// Stop disarms the watchdog.
func Stop() {
	esp.RTC_CNTL.WDTWPROTECT.Set(wdtKey)
	esp.RTC_CNTL.WDTCONFIG0.Set(0)
	esp.RTC_CNTL.WDTWPROTECT.Set(0)
}
