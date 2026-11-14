package main

import (
	"device"
	"device/esp"
	"machine"
	"runtime/interrupt"
	"runtime/volatile"
	"unsafe"
)

// M5Stack Cardputer pins.
const (
	ledPin    = machine.GPIO21 // WS2812 RGB LED data
	ledPower  = machine.GPIO38 // v1.1: RGB LED power switch (v1.0: display backlight)
	buttonPin = machine.GPIO0  // G0 button (active low)
)

func ccount() uint32 { return uint32(device.AsmFull("rsr {}, CCOUNT", nil)) }

// WS2812 timing in CPU cycles at 240 MHz (4.17 ns per cycle).
const (
	t0High = 96  // 0.40 us
	t1High = 192 // 0.80 us
	tBit   = 300 // 1.25 us
)

// setLED shows a colour. The pixel is written twice: the first pass may
// stall on instruction-cache misses (code runs from flash), which would
// stretch pulses; the second runs from cache and overrides it.
func setLED(r, g, b uint8) {
	writePixel(r, g, b)
	busyWait(300 * 240) // > 280 us latch
	writePixel(r, g, b)
}

func busyWait(cycles uint32) {
	start := ccount()
	for ccount()-start < cycles {
	}
}

// writePixel writes one GRB pixel, timing bits with the cycle counter.
func writePixel(r, g, b uint8) {
	set, setMask := ledPin.PortMaskSet()
	clr, clrMask := ledPin.PortMaskClear()
	setReg := (*volatile.Register32)(unsafe.Pointer(set))
	clrReg := (*volatile.Register32)(unsafe.Pointer(clr))
	data := uint32(g)<<16 | uint32(r)<<8 | uint32(b)
	state := interrupt.Disable()
	for i := 23; i >= 0; i-- {
		high := uint32(t0High)
		if data>>uint(i)&1 != 0 {
			high = t1High
		}
		start := ccount()
		setReg.Set(setMask)
		for ccount()-start < high {
		}
		clrReg.Set(clrMask)
		for ccount()-start < tBit {
		}
	}
	interrupt.Restore(state)
}

func initBoard() {
	ledPower.Configure(machine.PinConfig{Mode: machine.PinOutput})
	ledPower.High()
	ledPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	ledPin.Low()
	busyWait(240 * 1000) // let the LED power up
	buttonPin.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
}

func buttonPressed() bool { return !buttonPin.Get() }

// resetCause returns why the CPU last reset (RTC_CNTL_RESET_CAUSE_PROCPU).
func resetCause() uint32 { return esp.RTC_CNTL.GetRESET_STATE_RESET_CAUSE_PROCPU() }

// restart performs a software system reset.
func restart() {
	esp.RTC_CNTL.OPTIONS0.SetBits(esp.RTC_CNTL_OPTIONS0_SW_SYS_RST)
	for {
	}
}

// factoryMAC reads the base MAC (the Wi-Fi station address) from eFuse, so
// it is known before the radio starts.
func factoryMAC() [6]byte {
	lo := esp.EFUSE.RD_MAC_SPI_SYS_0.Get()
	hi := esp.EFUSE.RD_MAC_SPI_SYS_1.Get()
	return [6]byte{byte(hi >> 8), byte(hi), byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)}
}
