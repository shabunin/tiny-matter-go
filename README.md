# tiny-matter-go

[![Go Reference](https://pkg.go.dev/badge/github.com/shabunin/tiny-matter-go.svg)](https://pkg.go.dev/github.com/shabunin/tiny-matter-go)
[![Release](https://img.shields.io/github/v/release/shabunin/tiny-matter-go)](https://github.com/shabunin/tiny-matter-go/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**A Matter device stack in pure Go, small enough for TinyGo on a microcontroller.**

It brings its own IPv6, IPv4 and mDNS over raw Wi-Fi frames, so it runs on bare-metal chips with no OS
and no vendor SDK. A host controller, `tmctl`, comes with it.

- **Commissioning:** PASE, attestation, CASE with resumption, and multi-admin, over BLE or the IP network.
- **Interaction Model:** read, write, invoke, subscribe and events, plus groups over multicast. Subscriptions survive restarts.
- **Devices:** colour, dimmable and on/off lights, plugs, switches, temperature, humidity, pressure, light, occupancy and contact sensors, and bridges.
- **Updates:** over-the-air (Matter OTA), with two flash slots and rollback.
- **Robust by design:** state is saved to flash so it survives power cuts, a watchdog resets the chip if it hangs, the code is sans-IO and safe on 32-bit targets, and it is fuzzed.
- **Conformance:** 185 of 204 of the Matter SDK's YAML conformance tests pass.

> **Status: v0.x, not certified.** The examples use the SDK's public *test* credentials, so only
> controllers in development mode accept them. Do not ship it in products.

## Runs on

| Board | Chip | What it is |
|---|---|---|
| M5Stack Cardputer | ESP32-S3 | Colour light and button; BLE commissioning, OTA updates |
| M5Stack Core + M5GO base | ESP32 | Colour light on the LED bar, colour dimmer switch |
| M5StickC Plus + ENV unit | ESP32 | Temperature, humidity and pressure sensor |
| Your computer | Linux | `cmd/hostdevice`: any of the device types above, over UDP (mDNS via avahi) |

It works with chip-tool, [matter.js](https://github.com/matter-js/matter.js),
[matterctl](https://github.com/cybergarage/go-matter) and `tmctl`, all on the same device at once.

## Quick start

Flash the Cardputer, then hand it your Wi-Fi network over Bluetooth:

```sh
cd firmware
tinygo flash -target esp32s3-generic -stack-size=12KB ./esp32s3-light

go install github.com/shabunin/tiny-matter-go/cmd/tmctl@latest
TMCTL_WIFI_PASSWORD=secret tmctl commission 34970112332 -ssid MyWiFi -label lamp
tmctl invoke lamp 1 OnOff Toggle
```

Or try it with no hardware at all:

```sh
go run ./cmd/hostdevice -type light -state lamp.state
chip-tool pairing onnetwork-long 1 20202021 3840
```

## tmctl

```sh
tmctl discover -ble                       # devices waiting to be commissioned
tmctl read lamp 1 LevelControl currentLevel
tmctl subscribe lamp 2 Switch -events     # button presses, live
tmctl group-join lamp 1 lights            # put the lamp in a group…
tmctl group-invoke lights OnOff Toggle    # …and switch the whole group by multicast
tmctl bind pir 6 lamp 1 OnOff             # a motion sensor drives the lamp by itself
tmctl ota-update lamp app-2.ota           # a firmware update over Matter
```

Clusters, attributes and commands go by their names in the SDK's data model. `tmctl clusters` lists them.

## Roadmap

- [ ] **Raspberry Pi Pico W / Pico 2 W:** Wi-Fi and BLE through the CYW43439, on the same
  IPv6, IPv4 and mDNS stacks. The full device already builds for both (an on/off light is about
  410 KB of flash and 12 KB of static RAM on the Pico 2 W).
- [ ] **Thread:** devices on an 802.15.4 radio (nRF52840, ESP32-C6/H2). Thread datasets are already
  parsed and provisioned, by the device and by `tmctl`, though this is untested on Thread hardware.
- [x] Global IPv6 addresses (SLAAC)
- [ ] More device types: window coverings, locks, thermostats

## Documentation

[**AGENTS.md**](AGENTS.md) is the full reference. It covers the architecture, every package, writing a
cluster, the firmware and OTA, all `tmctl` commands, testing and conformance, and the known pitfalls.
It is written for coding agents and is just as useful to people. Background and measurements are in
[FEASIBILITY.md](FEASIBILITY.md).

```sh
make test          # go vet + go test
make test32        # GOARCH=386
make tinygo-test   # the tests under TinyGo
```

## License

Apache-2.0. Parts derived from the Go standard library are under Go's BSD license (see [NOTICE](NOTICE)).
The test vectors and PAA certificates come from [connectedhomeip](https://github.com/project-chip/connectedhomeip).

Matter is a trademark of the Connectivity Standards Alliance. This project is not affiliated with or
certified by the CSA.
