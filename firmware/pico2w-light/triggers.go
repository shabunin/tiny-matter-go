package main

import (
	"encoding/hex"
	"machine"
	"time"

	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/im"
)

// testEventKey, set with -X main.testEventKey=<32 hex digits>, enables the
// General Diagnostics test event triggers below. Test builds only.
var testEventKey string

// Test event triggers (vendor 0xFFF1 values).
const (
	// triggerBootloader reboots into the boot ROM's UF2 bootloader, for
	// flashing without the BOOTSEL button.
	triggerBootloader = 0xFFF1000000000001
	// triggerReboot reboots.
	triggerReboot = 0xFFF1000000000002
)

// rebootDelay lets the response to the trigger go out first.
const rebootDelay = 500 * time.Millisecond

// triggers acts on test event triggers. The reboots happen in poll, after
// rebootDelay.
type triggers struct {
	d      *device.Device
	reboot func() // leaves the network, then reboots
	at     time.Time
	boot   bool // into the bootloader
}

// enable turns the triggers on if the build has a test event key.
func (t *triggers) enable() {
	if testEventKey == "" {
		return
	}
	key, err := hex.DecodeString(testEventKey)
	if err != nil || len(key) != 16 {
		println("testEventKey wants 32 hex digits: test event triggers disabled")
		return
	}
	copy(t.d.Diagnostics.EnableKey[:], key)
	t.d.Diagnostics.Trigger = t.trigger
	println("test event triggers enabled")
}

func (t *triggers) trigger(ctx *im.Context, trigger uint64) im.Status {
	switch trigger {
	case triggerBootloader:
		println("test event trigger: rebooting into the bootloader")
		t.boot = true
	case triggerReboot:
		println("test event trigger: rebooting")
	default:
		return im.InvalidCommand
	}
	t.at = ctx.Now.Add(rebootDelay)
	return im.Success
}

func (t *triggers) poll(now time.Time) {
	if t.at.IsZero() || now.Before(t.at) {
		return
	}
	t.d.Flush()
	if t.boot {
		radio.Dev.Leave()
		machine.EnterBootloader()
	}
	t.reboot()
}
