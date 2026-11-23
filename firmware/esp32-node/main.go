// Command esp32-node is a Matter device over Wi-Fi for classic ESP32
// boards from M5Stack; the TinyGo target picks the board and what it is:
//
//   - m5stack (an M5Stack Core with the M5GO base): an Extended Color Light
//     on the base's ten RGB LEDs (endpoint 1). An angle unit (a
//     potentiometer) on Port B sets its brightness, button B switches it
//     on and off, and buttons A and C turn its hue round the colour circle
//     (a step per click, smoothly while held). Endpoint 2 is a Color
//     Dimmer Switch: the knob and buttons do the same to the lights it is
//     bound to.
//   - m5stick-c (an M5StickC Plus with an ENV II or III unit on its Grove
//     port): temperature, humidity and pressure sensors (endpoints 1 to 3).
//
// It uses the SDK development attestation credentials (vendor 0xFFF1,
// product 0x8000), test passcode 20202021 and discriminator 3840. Build it
// with a network, which it joins at once, and commission it over IP.
// Goroutine stacks must be 10 KB: commissioning and opening CASE sessions
// take main's to about 6.8 KB, close to the 8 KB default's usable part.
// (Not more: the four goroutines' stacks come from a heap of about 150 KB.)
//
//	tinygo flash -target m5stack -stack-size=10KB -ldflags "-X main.ssid=... -X main.password=..." ./esp32-node
//	chip-tool pairing onnetwork-long 1 20202021 3840
//
// It keeps its fabrics and network in the last 32 KB of the flash and
// restarts commissioned. Hold the reset button (B on the M5GO, the M5
// button on the StickC) for 5 s to erase them (factory reset).
//
// Started by esp32-loader (two flash slots at 0x11000 and 0x201000), it is
// an OTA requestor: tmctl ota-update installs a new build into the inactive
// slot, and the loader rolls back if the new image resets before confirming
// itself on the network.
package main

import (
	"machine"
	"runtime"
	"strconv"
	"time"

	"firmware/esp32flash"
	"firmware/espota"
	"firmware/espwifi"
	"firmware/watchdog"
	"firmware/wifinode"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/storage"
	"tinygo.org/x/espradio"
)

var (
	ssid, password string // the network, set with -ldflags -X

	// The software version, a number, set with -X main.softwareVersion=n.
	softwareVersion = "1"

	// testFault, for testing the watchdog, makes the firmware fail 30 s
	// after it reaches the network: "hang" spins, "panic" panics (TinyGo
	// then halts).
	testFault string
)

const (
	passcode      = 20202021
	discriminator = 3840
	iterations    = 1000

	resetHold = 5 * time.Second // holding button A this long erases the state
	// trialTimeout is how long a new image has to confirm itself (20 s on
	// the network) before the watchdog resets it and the loader rolls back.
	trialTimeout = 3 * time.Minute
	// watchdogTimeout is how long the main loop may go without polling
	// (the longest blocking call, a Wi-Fi connect, takes about 12 s)
	// before the watchdog resets the chip.
	watchdogTimeout = 60 * time.Second
)

func fatal(msg string, err error) {
	for {
		println("FATAL:", msg, err.Error())
		time.Sleep(2 * time.Second)
	}
}

// stateStore keeps fabrics, the ACL, the network and the application
// state in the last 32 KB of the flash, in two 16 KB slots.
func stateStore() *storage.Flash {
	const slot = 16 << 10
	dev := &esp32flash.Device{Offset: esp32flash.FlashSize() - 2*slot, Length: 2 * slot}
	return &storage.Flash{Dev: dev, SlotSize: slot}
}

func main() {
	// The watchdog resets the chip if the main loop stops: a hang, or a
	// fatal error, on which TinyGo halts for good.
	watchdog.Start(watchdogTimeout)
	time.Sleep(time.Second)
	println("watchdog:", watchdogTimeout.String(), "on a", watchdog.SlowClockHz(), "Hz RTC clock")
	slots := &espota.Slots{Restart: restart, Log: func(msg string) { println(msg) }}
	var trialEnd time.Time
	if _, _, confirmed, ok := slots.Running(); ok && !confirmed {
		trialEnd = time.Now().Add(trialTimeout)
		println("trial image: must confirm itself within", trialTimeout.String())
	}
	println("tiny-matter-go", boardName, "starting")
	p256.SetYield(runtime.Gosched)
	store := stateStore()

	radioCfg := espradio.Config{Logging: espradio.LogLevelError}
	if err := espradio.Enable(radioCfg); err != nil {
		fatal("radio", err)
	}
	mac := factoryMAC()
	println("mac", wifinode.HexMAC(mac))
	node := wifinode.New(mac, &espwifi.Radio{Config: radioCfg})
	node.Log = func(msg string) { println(msg) }

	salt := []byte("SPAKE2P Key Salt")
	v, err := spake2p.NewVerifier(passcode, salt, iterations)
	if err != nil {
		fatal("verifier", err)
	}
	dacKey, err := p256.NewPrivateKey(devcreds.DACPrivateKey)
	if err != nil {
		fatal("dac key", err)
	}
	version, err := strconv.ParseUint(softwareVersion, 10, 32)
	if err != nil || version == 0 {
		version = 1
	}
	// Updates go to the other flash slot when esp32-loader started us.
	var updates device.ImageStore
	if base, seq, confirmed, ok := slots.Running(); ok {
		println("running slot", base, "record", seq, "confirmed", confirmed, "version", version)
		updates = slots
	} else {
		println("not started by the loader: OTA updates disabled")
		slots = nil
	}
	d, err := device.New(device.Config{
		Transport: node.Transport, Rand: hwRand{}, Port: wifinode.MatterPort,
		Verifier: v, Salt: salt, Iterations: iterations, Discriminator: discriminator,
		Attestation: &clusters.Attestation{
			DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: productName, ProductID: devcreds.ProductID,
			HardwareVersion: 1, HardwareVersionString: "ESP32",
			SoftwareVersion: uint32(version), SoftwareVersionString: "0.2." + softwareVersion,
			SerialNumber: wifinode.HexMAC(mac), UniqueID: "tmg-" + wifinode.HexMAC(mac),
		},
		DeviceType: deviceType.ID,
		Advertiser: node.Advertiser,
		Store:      store,
		Clock:      time.Now,
		Log:        func(msg string) { println(msg) },
		WiFi:       true,
		Updates:    updates,
		Resolve:    node.Resolve,
	})
	if err != nil {
		fatal("device", err)
	}
	if slots != nil {
		// Save pending state before restarting into an update.
		slots.Restart = func() { d.Flush(); restart() }
	}
	poll := newApp(d)
	reset := &resetButton{pin: resetPin, store: store}
	reset.init()
	cause := resetCause()
	d.Diagnostics.BootReason = bootReason(cause)
	println("reset cause", cause, "boot reason", d.Diagnostics.BootReason, "reboot count", d.Diagnostics.RebootCount)
	node.Attach(d, nil)
	if !d.Commissioned() {
		d.OpenCommissioningWindow()
		println("commissionable: passcode", passcode, "discriminator", discriminator)
	}

	var nw clusters.WiFiNetwork
	switch {
	case len(d.Net.Networks) > 0:
		nw = d.Net.Networks[0]
	case ssid != "":
		nw = clusters.WiFiNetwork{SSID: []byte(ssid), Credentials: []byte(password)}
	default:
		for {
			println("no Wi-Fi network: build with -X main.ssid=... -X main.password=...")
			time.Sleep(5 * time.Second)
		}
	}
	println("connecting to Wi-Fi", string(nw.SSID))
	faultAt := time.Now().Add(time.Hour)
	var confirmAt time.Time
	all := func(now time.Time) {
		if testFault != "" && now.After(faultAt) {
			println("test fault:", testFault)
			if testFault == "panic" {
				panic("test fault")
			}
			for {
			}
		}
		if trialEnd.IsZero() || now.Before(trialEnd) {
			watchdog.Feed()
		}
		poll(now)
		reset.poll(now)
		if slots != nil && !confirmAt.IsZero() && now.After(confirmAt) && node.LinkUp() {
			confirmAt = time.Time{}
			if err := slots.Confirm(); err != nil {
				println("confirming the image:", err.Error())
			} else {
				trialEnd = time.Time{}
			}
		}
	}
	node.Join(nw, all, nil)
	faultAt = time.Now().Add(30 * time.Second)
	confirmAt = time.Now().Add(20 * time.Second)
	node.Run(all)
}

// resetButton erases the state when held for resetHold. The buttons have
// external pull-ups and read low when pressed.
type resetButton struct {
	pin   machine.Pin
	store *storage.Flash
	since time.Time // pressed since (zero: released)
}

func (b *resetButton) init() { b.pin.Configure(machine.PinConfig{Mode: machine.PinInput}) }

func (b *resetButton) poll(now time.Time) {
	if b.pin.Get() {
		b.since = time.Time{}
		return
	}
	if b.since.IsZero() {
		b.since = now
	}
	if now.Sub(b.since) >= resetHold {
		println("factory reset")
		b.store.Erase()
		time.Sleep(500 * time.Millisecond)
		restart()
	}
}
