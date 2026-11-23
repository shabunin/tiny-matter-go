package main

import (
	"device/rp"
	"machine"
	"time"
)

// USB often fails to enumerate on this firmware, after any kind of start:
// the host reports "device not accepting address, error -71", tries for
// about two seconds and gives up. The cause is not known yet (the Matter
// side runs regardless). Detaching (dropping the D+ pull-up) and attaching
// again makes the host start over, so the firmware waits for an address at
// start, re-attaching a few times, and then keeps re-attaching from the
// main loop until a host enumerates it. With no USB host, that does
// nothing.
const (
	usbWait     = 1500 * time.Millisecond // for an address, per attempt at start
	usbAttempts = 3
	usbRetry    = 3 * time.Second // between re-attaches later
)

func usbAddressed() bool {
	return rp.USB.ADDR_ENDP.Get()&rp.USB_ADDR_ENDP_ADDRESS_Msk != 0
}

func usbReattach() {
	machine.USBDev.Detach()
	time.Sleep(200 * time.Millisecond)
	machine.USBDev.Attach()
}

// waitUSB waits for the host to enumerate the device, re-attaching it when
// it does not, and reports the attempts it took (0: not enumerated).
func waitUSB() int {
	for i := 1; i <= usbAttempts; i++ {
		deadline := time.Now().Add(usbWait)
		for time.Now().Before(deadline) {
			if usbAddressed() {
				return i
			}
			time.Sleep(10 * time.Millisecond)
		}
		usbReattach()
	}
	return 0
}

// usbKeeper re-attaches USB from the main loop until a host enumerates it.
type usbKeeper struct {
	done bool
	next time.Time
}

func (u *usbKeeper) poll(now time.Time) {
	if u.done || now.Before(u.next) {
		return
	}
	if usbAddressed() {
		u.done = true
		println("USB enumerated")
		return
	}
	usbReattach()
	u.next = now.Add(usbRetry)
}
