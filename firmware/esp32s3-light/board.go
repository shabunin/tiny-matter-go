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
	ledPin    = machine.GPIO21 // WS2812 RGB LED
	buttonPin = machine.GPIO0  // G0 button (active low)
)

func ccount() uint32 { return uint32(device.AsmFull("rsr {}, CCOUNT", nil)) }

// WS2812 timing in CPU cycles at 240 MHz (4.17 ns per cycle).
const (
	t0High = 96  // 0.40 us
	t1High = 192 // 0.80 us
	tBit   = 300 // 1.25 us
)

// setLED writes one GRB pixel, timing bits with the cycle counter.
func setLED(r, g, b uint8) {
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
	ledPin.Configure(machine.PinConfig{Mode: machine.PinOutput})
	ledPin.Low()
	buttonPin.Configure(machine.PinConfig{Mode: machine.PinInputPullup})
}

func buttonPressed() bool { return !buttonPin.Get() }

// restart performs a software system reset.
func restart() {
	esp.RTC_CNTL.OPTIONS0.SetBits(esp.RTC_CNTL_OPTIONS0_SW_SYS_RST)
	for {
	}
}
