// Command pico2w-light is a Matter On/Off Light for the Raspberry Pi
// Pico 2 W: endpoint 1 switches the board's LED (on the CYW43439's GPIO 0),
// with Identify, Groups and Scenes. Wi-Fi is the CYW43439 through
// cyw43wifi, random numbers come from the RP2350's TRNG, and the fabrics,
// network and light state live in the last 32 KB of the flash.
//
// It uses the SDK development attestation credentials (vendor 0xFFF1,
// product 0x8000), test passcode 20202021 and discriminator 3840. Built
// without a network, it is commissioned over BLE, which provisions one:
//
//	tmctl commission 34970112332 -ssid <network>
//
// Built with a network (-ldflags "-X main.ssid=... -X main.password=..."),
// it joins it at once and is commissioned over IP.
//
// The flash is partitioned for OTA updates (see rpota). Once, with the
// board in BOOTSEL mode, copy the partition table to its drive, then the
// firmware (TinyGo's own UF2 does not load into a partition: rpslot adds
// the RP2350-E10 workaround):
//
//	go run ./rpslot install -o install.uf2
//	tinygo build -target pico2-w -stack-size=16KB -o app.elf ./pico2w-light
//	go run ./rpslot uf2 -elf app.elf -o app.uf2
//
// Updates are OTA images of rpslot payloads, with a higher softwareVersion:
//
//	tinygo build -target pico2-w -stack-size=16KB -ldflags "-X main.softwareVersion=2" -o app.elf ./pico2w-light
//	go run ./rpslot payload -elf app.elf -o app.payload
//	tmctl ota-image app.payload app-2.ota -vendor 0xFFF1 -product 0x8000 -version 2
//	tmctl ota-update <node> app-2.ota
//
// An update runs on trial and confirms itself 20 s after reaching the
// network; a reset before that starts the previous image again.
//
// The LED blinks briefly every second until the light is commissioned,
// then shows the light; it blinks quickly while a controller identifies it.
// On the USB console, "reboot" restarts the board and "factory-reset"
// erases its state.
package main

import (
	"machine"
	"runtime"
	"strconv"
	"time"

	"firmware/cyw43wifi"
	"firmware/matterble"
	"firmware/rpflash"
	"firmware/rpota"
	"firmware/rptrng"
	"firmware/rpwatchdog"
	"firmware/wifinode"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/storage"
)

var (
	ssid, password string // the network, set with -ldflags -X

	// The software version, a number, set with -X main.softwareVersion=n.
	softwareVersion = "1"
)

const (
	passcode      = 20202021
	discriminator = 3840
	iterations    = 1000

	lightEndpoint = 1

	// hardwareTimeout is the watchdog's own timeout (it can count to
	// about 16 s). A goroutine feeds it while the main loop has passed
	// within loopTimeout: the longest blocking call, a Wi-Fi join, takes
	// about 14 s, and while it waits it lets the feeder run.
	hardwareTimeout = 8 * time.Second
	loopTimeout     = 60 * time.Second

	// joinTimeout is how long to try a network provisioned over BLE
	// before rebooting to be commissioned again.
	joinTimeout = 60 * time.Second

	// trialTimeout is how long an update has to confirm itself (20 s on
	// the network) before the board reboots into the previous image.
	trialTimeout = 3 * time.Minute
	confirmDelay = 20 * time.Second
)

func fatal(msg string, err error) {
	for {
		println("FATAL:", msg, err.Error())
		time.Sleep(2 * time.Second)
	}
}

// stateStore keeps fabrics, the ACL, the network and the application
// state in the last 32 KB of the flash, in two 16 KB slots, after the
// firmware partitions (see rpota).
func stateStore() *storage.Flash {
	const slot = 16 << 10
	dev := &rpflash.Device{Start: rpota.StateStart, End: rpota.FlashSize}
	return &storage.Flash{Dev: dev, Offset: rpota.StateStart, SlotSize: slot}
}

// radio is the Wi-Fi chip (and the LED's).
var radio *cyw43wifi.Radio

// heartbeat is when the main loop last passed (Unix ms).
var heartbeat int64

// startWatchdog resets the chip if the main loop stops for loopTimeout: a
// hang, or a fatal error. A goroutine that does not yield never lets the
// feeder run, and the hardware resets after hardwareTimeout.
func startWatchdog() {
	heartbeat = time.Now().UnixMilli()
	rpwatchdog.Start(hardwareTimeout)
	go func() {
		for {
			if time.Now().UnixMilli()-heartbeat < loopTimeout.Milliseconds() {
				rpwatchdog.Feed()
			}
			time.Sleep(time.Second)
		}
	}()
}

func bootReason(r rpwatchdog.Reason) uint8 {
	switch r {
	case rpwatchdog.ReasonPowerOn:
		return clusters.BootPowerOn
	case rpwatchdog.ReasonBrownOut:
		return clusters.BootBrownOut
	case rpwatchdog.ReasonWatchdog:
		return clusters.BootHardwareWatchdog
	case rpwatchdog.ReasonReboot:
		return clusters.BootSoftwareReset
	}
	return clusters.BootUnspecified
}

func main() {
	reason := rpwatchdog.LastReset()
	startWatchdog()
	usbTries := waitUSB()
	time.Sleep(time.Second) // time for a console to open the port
	println("tiny-matter-go pico2w-light starting; USB enumerated on attempt", usbTries)
	p256.SetYield(runtime.Gosched)
	store := stateStore()
	slots := rpota.NewStore()
	slots.Log = func(msg string) { println(msg) }
	println("boot:", slots.Boot().String())
	var trialEnd time.Time
	if _, trial, _ := slots.Running(); trial {
		trialEnd = time.Now().Add(trialTimeout)
		println("trial image: must confirm itself within", trialTimeout.String())
	}

	var err error
	// Bluetooth is only for commissioning, which needs it when no network
	// is compiled in (a stored one may be gone after a factory reset).
	radio, err = cyw43wifi.New(ssid == "")
	if err != nil {
		fatal("wifi chip", err)
	}
	mac, _ := radio.MAC()
	println("mac", wifinode.HexMAC(mac))
	node := wifinode.New(mac, radio)
	node.Log = func(msg string) { println(msg) }
	tr := node.Transport
	tr.Peer, tr.HasPeer = matterble.Peer, true

	rng := &rptrng.Reader{}
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
	// Updates go to the other partition, when the boot ROM started us from
	// one (see rpota for the one-time setup).
	var updates device.ImageStore
	if p, trial, ok := slots.Running(); ok {
		println("running partition", "AB"[p:p+1], "trial", trial, "version", version)
		updates = slots
	} else {
		println("not running from a partition: OTA updates disabled")
	}
	d, err := device.New(device.Config{
		Transport: node.Transport, Rand: rng, Port: wifinode.MatterPort,
		Verifier: v, Salt: salt, Iterations: iterations, Discriminator: discriminator,
		Attestation: &clusters.Attestation{
			DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: "Pico 2 W Light", ProductID: devcreds.ProductID,
			HardwareVersion: 1, HardwareVersionString: "Pico 2 W",
			SoftwareVersion: uint32(version), SoftwareVersionString: "0.2." + softwareVersion,
			SerialNumber: wifinode.HexMAC(mac), UniqueID: "tmg-" + wifinode.HexMAC(mac),
		},
		DeviceType: clusters.DeviceTypeOnOffLight.ID,
		Advertiser: node.Advertiser,
		Store:      store,
		Clock:      time.Now,
		Log:        func(msg string) { println(msg) },
		WiFi:       true,
		Resolve:    node.Resolve,
		Updates:    updates,
	})
	if err != nil {
		fatal("device", err)
	}
	// Before a deliberate restart, leave the network, so the access point
	// does not keep the old association (see cyw43wifi).
	reboot := func() {
		radio.Dev.Leave()
		rpwatchdog.Reboot()
	}
	// Before rebooting into an update: save the state, leave the network.
	slots.Restart = func() {
		d.Flush()
		radio.Dev.Leave()
	}
	l := newLight(d, radio)
	d.Diagnostics.BootReason = bootReason(reason)
	println("boot reason", d.Diagnostics.BootReason, "reboot count", d.Diagnostics.RebootCount)
	node.Attach(d, nil)
	if !d.Commissioned() {
		d.OpenCommissioningWindow()
		println("commissionable: passcode", passcode, "discriminator", discriminator)
	}

	con := console{d: d, reboot: reboot, store: store}
	trig := triggers{d: d, reboot: reboot}
	trig.enable()
	usb := usbKeeper{done: usbTries > 0}
	var confirmAt time.Time
	all := func(now time.Time) {
		heartbeat = now.UnixMilli()
		l.poll(now)
		con.poll()
		trig.poll(now)
		usb.poll(now)
		if !confirmAt.IsZero() && now.After(confirmAt) && node.LinkUp() {
			confirmAt = time.Time{}
			if err := slots.Confirm(); err != nil {
				println("confirming the image:", err.Error())
			} else {
				trialEnd = time.Time{}
			}
		}
		if !trialEnd.IsZero() && now.After(trialEnd) {
			// A normal boot starts the previous image: this one is still
			// on trial.
			println("trial image did not confirm itself: rebooting")
			reboot()
		}
	}

	// The network: stored, compiled in, or provisioned over BLE.
	var nw clusters.WiFiNetwork
	viaBLE := false
	switch {
	case len(d.Net.Networks) > 0:
		nw = d.Net.Networks[0]
	case ssid != "":
		nw = clusters.WiFiNetwork{SSID: []byte(ssid), Credentials: []byte(password)}
	default:
		nw = commissionOverBLE(d, tr, mac, all)
		viaBLE = true
		// If commissioning does not complete, start over: the fail-safe
		// rolled the network back, so BLE advertising resumes.
		d.FailSafe.OnExpire = append(d.FailSafe.OnExpire, func(now time.Time) {
			if !d.Commissioned() {
				println("commissioning did not complete: rebooting")
				reboot()
			}
		})
	}
	println("connecting to Wi-Fi")
	joinStart := time.Now()
	giveUp := func() bool { return viaBLE && time.Since(joinStart) > joinTimeout }
	if !node.Join(nw, all, giveUp) {
		println("cannot join the network: rebooting")
		reboot()
	}
	if !trialEnd.IsZero() {
		confirmAt = time.Now().Add(confirmDelay)
	}
	node.Run(all)
}

// console reads commands from the USB console.
type console struct {
	d      *device.Device
	reboot func()
	store  *storage.Flash
	line   []byte
}

func (c *console) poll() {
	for machine.Serial.Buffered() > 0 {
		b, err := machine.Serial.ReadByte()
		if err != nil {
			return
		}
		if b != '\r' && b != '\n' {
			if len(c.line) < 32 {
				c.line = append(c.line, b)
			}
			continue
		}
		cmd := string(c.line)
		c.line = c.line[:0]
		switch cmd {
		case "":
		case "reboot":
			println("rebooting")
			c.d.Flush()
			c.reboot()
		case "factory-reset":
			println("factory reset")
			c.store.Erase()
			c.reboot()
		default:
			println("commands: reboot, factory-reset")
		}
	}
}
