// Command esp32s3-light is a Matter colour light over Wi-Fi for ESP32-S3
// boards such as the M5Stack Cardputer. It uses the SDK development
// attestation credentials (vendor 0xFFF1, product 0x8000), test passcode
// 20202021 and discriminator 3840, so commission it with a test
// controller such as chip-tool.
//
// Without a Wi-Fi network it advertises over Bluetooth LE, and a
// commissioner provisions the network over BTP:
//
//	chip-tool pairing ble-wifi 1 <ssid> <password> 20202021 3840
//
// Built with a network (-ldflags "-X main.ssid=... -X main.password=..."),
// it joins it at once and is commissioned over IP:
//
//	chip-tool pairing onnetwork-long 1 20202021 3840
//
// It keeps its fabrics and network in flash and restarts already
// commissioned. Hold the G0 button for 5 s to erase them (factory reset).
// The RGB LED is the light, an Extended Color Light: on/off, level, hue
// and saturation, xy, colour temperature and the colour loop, with scenes
// and groups. While not commissioned, dim cyan means it waits for BLE
// commissioning and dim purple for commissioning over IP; yellow means a
// factory reset. It blinks while a controller identifies an
// endpoint: white for the light, green for the button.
//
// On the Grove port, an M5Stack ENV unit (II or III) adds temperature,
// humidity and pressure sensors (endpoints 3 to 5); anything else is taken
// for a PIR unit, an occupancy sensor (endpoint 6).
//
// Endpoint 1 is the light; endpoint 2 is a Generic Switch, the G0 button,
// whose presses are Switch events (InitialPress, LongPress after 1 s,
// ShortRelease or LongRelease). A test build can enable the General
// Diagnostics test event triggers with a 16-byte key,
// -X main.testEventKey=<32 hex digits>; then trigger 0x003B000000000001
// clicks the button and 0x003B000000000002 holds it for 1.5 s:
//
//	chip-tool generaldiagnostics test-event-trigger hex:<key> 0x003B000000000001 1 0
//
// Started by esp32s3-loader (two flash slots), it is an OTA requestor:
// tmctl ota-update installs a new build, and the loader rolls back to the
// old one if the new one is reset before it reaches the network. Build an
// update with its version set, -X main.softwareVersion=<n>, and wrap it
// with espslot payload and tmctl ota-image (see the README).
//
// It speaks IPv6 (link-local) and IPv4 (DHCP), and advertises itself with
// mDNS on both, so controllers that look over either family find it.
//
// The console is USB-Serial-JTAG: when no host reads it, prints block,
// which stalls the firmware. Keep a serial reader attached while it is
// plugged into a computer.
//
// Goroutine stacks must be 12 KB: commissioning (certificate checks)
// takes main's to about 7.5 KB, past the 8 KB default's usable part.
//
//	tinygo flash -target esp32s3-generic -stack-size=12KB ./esp32s3-light
package main

import (
	"crypto/rand"
	"encoding/hex"
	"machine"
	"runtime"
	"strconv"
	"time"

	"firmware/espota"
	"firmware/matterble"
	"firmware/pir"
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
	ssid, password string // optional compiled-in network, set with -ldflags -X
	stateSlot      string // "1" keeps state in a second flash area (testing)
	testEventKey   string // hex key enabling test event triggers (testing)
	testHang       string // "1" hangs at start (testing the trial watchdog)

	// The software version, a number, set with -X main.softwareVersion=n.
	softwareVersion = "1"
)

const (
	passcode      = 20202021
	discriminator = 3840
	iterations    = 1000

	joinTimeout = 60 * time.Second // give up on a network provisioned over BLE
	// trialTimeout is how long a new image has to confirm itself (20 s on
	// the network) before the watchdog resets it.
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

// stateStore keeps fabrics, the ACL and the Wi-Fi network in the last
// 32 KB of the flash data area, in two 16 KB slots (or the 32 KB before
// it, for a stateSlot=1 test build).
func stateStore() *storage.Flash {
	const slot = 16 << 10
	off := machine.Flash.Size() - 2*slot
	if stateSlot == "1" {
		off -= 2 * slot
	}
	return &storage.Flash{Dev: machine.Flash, Offset: off, SlotSize: slot}
}

func main() {
	// The watchdog resets the chip if the main loop stops (a hang, or a
	// fatal error, on which TinyGo halts for good). An image on trial is
	// fed only until trialTimeout: if it has not confirmed itself by then,
	// it is reset and the loader rolls it back.
	watchdog.Start(watchdogTimeout)
	println("watchdog:", watchdogTimeout.String(), "on a", watchdog.SlowClockHz(), "Hz RTC clock")
	slots := &espota.Slots{Restart: restart, Log: func(msg string) { println(msg) }}
	var trialEnd time.Time
	if _, _, confirmed, ok := slots.Running(); ok && !confirmed {
		trialEnd = time.Now().Add(trialTimeout)
		println("trial image: must confirm itself within", trialTimeout.String())
	}
	alive := func(now time.Time) {
		if trialEnd.IsZero() || now.Before(trialEnd) {
			watchdog.Feed()
		}
	}
	initBoard()
	// Long P-256 computations (PASE, CASE) must let the radio tasks run:
	// over BLE, a stall beyond the supervision timeout drops the link.
	p256.SetYield(runtime.Gosched)
	for _, c := range [][3]uint8{{40, 0, 0}, {0, 40, 0}, {0, 0, 40}} { // boot self-test
		setLED(c[0], c[1], c[2])
		time.Sleep(400 * time.Millisecond)
	}
	setLED(0, 0, 8) // dim blue: starting
	time.Sleep(2 * time.Second)
	store := stateStore()
	println("tiny-matter-go light: starting")
	if testHang == "1" {
		println("test build: hanging")
		for {
		}
	}

	radioCfg := espradio.Config{Logging: espradio.LogLevelError}
	mac := factoryMAC()
	println("mac", wifinode.HexMAC(mac))

	node := wifinode.New(mac, radioCfg)
	node.Log = func(msg string) { println(msg) }
	tr := node.Transport
	tr.Peer, tr.HasPeer = matterble.Peer, true
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
	// Updates go to the other flash slot when the loader started us.
	var updates device.ImageStore
	if base, seq, confirmed, ok := slots.Running(); ok {
		println("running slot", base, "record", seq, "confirmed", confirmed, "version", version)
		updates = slots
	} else {
		println("not started by the loader: OTA updates disabled")
		slots = nil
	}
	d, err := device.New(device.Config{
		Transport: tr, Rand: rand.Reader, Port: wifinode.MatterPort,
		Verifier: v, Salt: salt, Iterations: iterations, Discriminator: discriminator,
		Attestation: &clusters.Attestation{
			DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: "Cardputer Light", ProductID: devcreds.ProductID,
			HardwareVersion: 1, HardwareVersionString: "ESP32-S3",
			SoftwareVersion: uint32(version), SoftwareVersionString: "0.2." + softwareVersion,
			SerialNumber: wifinode.HexMAC(mac), UniqueID: "tmg-" + wifinode.HexMAC(mac),
		},
		DeviceType: clusters.DeviceTypeExtendedColorLight.ID,
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
	// The Wi-Fi driver is initialised (not started) before BLE, so the two
	// can coexist. Its arena (taken from the heap) must hold the BT
	// controller too when the device may be commissioned over BLE: it has
	// no network to join. Otherwise the default, Wi-Fi only, leaves the
	// heap 48 KB more.
	if len(d.Net.Networks) == 0 && ssid == "" {
		radioCfg.ArenaPoolSize = 96 << 10
	}
	node.Radio = radioCfg
	if err := espradio.Enable(radioCfg); err != nil {
		fatal("radio", err)
	}
	if slots != nil {
		// Restarting into an update saves the light's state first (it
		// is otherwise saved a few seconds after it changes).
		slots.Restart = func() { d.Flush(); restart() }
	}
	u := newUI(d, store)
	u.alive = alive
	sensors := newEnv(d)
	var motion *pir.Sensor
	if sensors == nil {
		// Not an ENV unit: a PIR, its output on the port's G1 line.
		motion = pir.Add(d, groveSCL, machine.PinInputPulldown, occupancyEndpoint)
		println("grove: PIR occupancy sensor on endpoint", occupancyEndpoint)
	}
	cause := resetCause()
	d.Diagnostics.BootReason = bootReason(cause)
	println("reset cause", cause, "boot reason", d.Diagnostics.BootReason, "reboot count", d.Diagnostics.RebootCount)
	if testEventKey != "" {
		key, err := hex.DecodeString(testEventKey)
		if err != nil || len(key) != 16 {
			println("testEventKey wants 32 hex digits: test event triggers disabled")
		} else {
			copy(d.Diagnostics.EnableKey[:], key)
			d.Diagnostics.Trigger = u.trigger
			println("test event triggers enabled")
		}
	}
	// During BLE commissioning, BLE has the radio: scans report what a
	// scan saw as it started.
	node.Attach(d, func() []espradio.AccessPoint { return bootScan })
	if !d.Commissioned() {
		d.OpenCommissioningWindow()
		println("commissionable: passcode", passcode, "discriminator", discriminator)
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
		nw = commissionOverBLE(d, tr, u)
		viaBLE = true
	}
	if viaBLE {
		// If commissioning does not complete, start over: the fail-safe
		// rolled the network back, so BLE advertising resumes.
		d.FailSafe.OnExpire = append(d.FailSafe.OnExpire, func(now time.Time) {
			if !d.Commissioned() {
				println("commissioning did not complete: restarting")
				time.Sleep(200 * time.Millisecond)
				restart()
			}
		})
	}

	println("connecting to Wi-Fi", string(nw.SSID))
	joinStart := time.Now()
	giveUp := func() bool { return viaBLE && time.Since(joinStart) > joinTimeout }
	if !node.Join(nw, u.poll, giveUp) {
		println("cannot join the network: restarting")
		restart()
	}
	// A new image is confirmed once it has run on the network for a while;
	// reset before that, the loader rolls it back.
	confirmAt := time.Now().Add(20 * time.Second)
	node.Run(func(now time.Time) {
		u.poll(now)
		sensors.Poll(now)
		motion.Poll(now)
		if slots != nil && !confirmAt.IsZero() && now.After(confirmAt) && node.LinkUp() {
			confirmAt = time.Time{}
			if err := slots.Confirm(); err != nil {
				println("confirming the image:", err.Error())
			} else {
				trialEnd = time.Time{}
			}
		}
	})
}

// bootScan is what a Wi-Fi scan saw as BLE commissioning started.
var bootScan []espradio.AccessPoint

// scanOnce starts Wi-Fi just to scan, so that a commissioner can be told
// which networks are around while BLE has the radio.
func scanOnce() []espradio.AccessPoint {
	if err := espradio.Start(); err != nil {
		println("wifi scan: start:", err.Error())
		return nil
	}
	aps, err := espradio.Scan()
	if err != nil {
		println("wifi scan:", err.Error())
	}
	if err := espradio.Stop(); err != nil {
		println("wifi scan: stop:", err.Error())
	}
	println("wifi scan: access points seen", len(aps))
	return aps
}

// commissionOverBLE advertises the Matter BLE service and serves the
// commissioner over BTP until it provisions a network with ConnectNetwork,
// then closes the BLE link and returns the network to join.
func commissionOverBLE(d *device.Device, tr *wifinode.Transport, u *ui) clusters.WiFiNetwork {
	if err := espradio.BLEInit(); err != nil {
		fatal("ble init", err)
	}
	// Scan before advertising, after BLEInit: BLE keeps the PHY powered
	// when Wi-Fi stops (stopping Wi-Fi first leaves BLE unable to advertise).
	bootScan = scanOnce()
	matterble.Log = func(msg string) { println(msg) }
	b, err := matterble.New(matterble.NewTransport(espradio.VHCITransport{}), discriminator, devcreds.VendorID, devcreds.ProductID)
	if err != nil {
		fatal("ble", err)
	}
	tr.Link = b
	var join *clusters.WiFiNetwork
	d.Net.Connect = func(now time.Time, n clusters.WiFiNetwork) {
		println("ConnectNetwork: closing BLE, joining", string(n.SSID))
		join = &n
		b.Close(now)
	}
	d.HoldSaves = true // a flash erase would stall the link past its timeout
	println("BLE advertising: discriminator", discriminator)
	u.ble = true
	for {
		now := time.Now()
		b.Poll(now, func(msg []byte) {
			if err := d.HandlePacket(now, matterble.Peer, msg); err != nil {
				println("ble drop:", err.Error())
			}
		})
		d.Poll(now)
		if join != nil && !b.Connected() {
			break
		}
		b.Advertise(!b.Connected() && join == nil && d.PASE.WindowOpen())
		u.poll(now)
		time.Sleep(2 * time.Millisecond)
	}
	b.Advertise(false)
	u.ble = false
	d.HoldSaves = false
	tr.Link = nil
	d.Net.Connect = nil
	return *join
}
