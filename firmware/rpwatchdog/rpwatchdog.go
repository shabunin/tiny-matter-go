//go:build rp2350

// Package rpwatchdog is the RP2350 watchdog: it resets the chip when it is
// not fed, reboots it on request, and tells why the chip last reset.
//
// TinyGo's machine.Watchdog follows the RP2040 (its reset selection leaves
// out the RP2350's processors, and it does not set the tick divider), and
// machine.CPUReset requests a system reset that leaves USB unable to
// enumerate until the board is replugged. This package resets everything
// but the oscillators, as the Pico SDK's watchdog_reboot does.
package rpwatchdog

import (
	"device/rp"
	"time"
)

const (
	// The tick counts 1 µs: the reference clock is the 12 MHz crystal.
	refCyclesPerTick = 12
	// MaxTimeout is the longest timeout the 24-bit counter holds.
	MaxTimeout = time.Duration(rp.WATCHDOG_LOAD_LOAD_Msk) * time.Microsecond
	// everything is every block in PSM WDSEL.
	everything = rp.PSM_WDSEL_PROC1_Msk<<1 - 1
	// armedMark in SCRATCH4 says the watchdog was started by Start, so a
	// timeout reset is a real one. The boot ROM also reboots through the
	// watchdog (after a UF2 download, for one) and overwrites SCRATCH4.
	// The Pico SDK does the same (WATCHDOG_NON_REBOOT_MAGIC).
	armedMark = 0x6ab73121
)

var load uint32

func selectAll() {
	rp.PSM.WDSEL.Set(everything &^ (rp.PSM_WDSEL_ROSC_Msk | rp.PSM_WDSEL_XOSC_Msk))
}

// Start starts the watchdog: the chip resets unless Feed is called within
// timeout (at most MaxTimeout).
func Start(timeout time.Duration) {
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	load = uint32(timeout / time.Microsecond)
	rp.WATCHDOG.CTRL.ClearBits(rp.WATCHDOG_CTRL_ENABLE)
	rp.TICKS.WATCHDOG_CTRL.ClearBits(rp.TICKS_WATCHDOG_CTRL_ENABLE)
	rp.TICKS.WATCHDOG_CYCLES.Set(refCyclesPerTick)
	rp.TICKS.WATCHDOG_CTRL.SetBits(rp.TICKS_WATCHDOG_CTRL_ENABLE)
	selectAll()
	rp.WATCHDOG.SCRATCH4.Set(armedMark)
	rp.WATCHDOG.LOAD.Set(load)
	// Paused while a debugger halts the cores.
	rp.WATCHDOG.CTRL.SetBits(rp.WATCHDOG_CTRL_PAUSE_DBG0 | rp.WATCHDOG_CTRL_PAUSE_DBG1 |
		rp.WATCHDOG_CTRL_PAUSE_JTAG | rp.WATCHDOG_CTRL_ENABLE)
}

// Feed restarts the countdown.
func Feed() { rp.WATCHDOG.LOAD.Set(load) }

// Reboot resets the chip now.
func Reboot() {
	selectAll()
	rp.WATCHDOG.CTRL.SetBits(rp.WATCHDOG_CTRL_TRIGGER_Msk)
	for {
	}
}

// Reason is why the chip last reset.
type Reason uint8

const (
	ReasonUnknown  Reason = iota
	ReasonPowerOn         // power-on, or the RUN pin
	ReasonBrownOut        // supply voltage dropped
	ReasonWatchdog        // the watchdog was not fed
	ReasonReboot          // Reboot, the boot ROM or another software reset
)

// LastReset tells why the chip last reset.
func LastReset() Reason {
	switch r := rp.WATCHDOG.REASON.Get(); {
	case r&rp.WATCHDOG_REASON_FORCE_Msk != 0:
		return ReasonReboot
	case r&rp.WATCHDOG_REASON_TIMER_Msk != 0:
		if rp.WATCHDOG.SCRATCH4.Get() == armedMark {
			return ReasonWatchdog
		}
		return ReasonReboot
	}
	switch c := rp.POWMAN.CHIP_RESET.Get(); {
	case c&rp.POWMAN_CHIP_RESET_HAD_BOR_Msk != 0:
		return ReasonBrownOut
	case c&(rp.POWMAN_CHIP_RESET_HAD_POR_Msk|rp.POWMAN_CHIP_RESET_HAD_RUN_LOW_Msk) != 0:
		return ReasonPowerOn
	case c&rp.POWMAN_CHIP_RESET_HAD_HZD_SYS_RESET_REQ_Msk != 0:
		return ReasonReboot
	}
	return ReasonUnknown
}
