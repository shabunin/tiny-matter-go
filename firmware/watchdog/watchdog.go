// Package watchdog resets the chip when the firmware stops calling Feed:
// a hang, or a fatal error, on which TinyGo halts for good (abort waits
// for an interrupt forever) instead of restarting.
//
// It drives the RTC watchdog of the ESP32 and ESP32-S3, whose first stage
// resets the whole chip, RTC included; the reset cause reads as an RTC
// watchdog reset (General Diagnostics reports a hardware watchdog boot).
// TinyGo's startup disables every watchdog, so firmware starts it first
// thing in main, then feeds it from its main loop.
package watchdog

import "time"

const (
	wdtKey      = 0x50D83AA1 // write-protection key of the watchdog registers
	wdtResetRTC = 4          // stage action: reset the chip, RTC included
	wdtResetLen = 7          // 3.2 µs CPU and system reset pulses
	maxTicks    = 1<<32 - 1
)

// slowHz is the measured RTC slow clock (see measure).
var slowHz uint64

// SlowClockHz returns the RTC slow clock frequency Start measured, which
// the watchdog counts.
func SlowClockHz() uint32 { return uint32(slowHz) }

// measure returns the frequency of the RTC slow clock, counting the RTC
// timer (which it drives) for 20 ms of the crystal-derived system time:
// TinyGo does not calibrate the internal RC oscillator as ESP-IDF does,
// and uncalibrated it runs far from its nominal frequency (2.5 times
// faster on an ESP32 measured). A result out of range gives the nominal.
func measure() uint64 {
	const window = 20 * time.Millisecond
	t0, start := rtcTime(), time.Now()
	for time.Since(start) < window {
	}
	t1, d := rtcTime(), time.Since(start)
	hz := (t1 - t0) * uint64(time.Second) / uint64(d)
	if hz < 30_000 || hz > 1_000_000 {
		return nominalSlowHz
	}
	return hz
}

// Start arms the watchdog to reset the chip unless Feed is called at least
// every timeout. Calling it again changes the timeout. It takes 20 ms, to
// measure the clock, the first time.
func Start(timeout time.Duration) {
	if slowHz == 0 {
		slowHz = measure()
	}
	ticks := uint64(timeout/time.Millisecond) * slowHz / 1000
	ticks >>= delayShift()
	if ticks > maxTicks {
		ticks = maxTicks
	}
	start(uint32(ticks))
}
