# tiny-matter-go

A Matter device stack in Go that targets TinyGo on microcontrollers. It
implements commissioning (PASE, attestation, operational credentials, CASE),
the Interaction Model (read, write, invoke, subscribe, events), multi-admin, BLE commissioning (BTP) with Network Commissioning for Wi-Fi
(and Thread datasets, short of a Thread radio), and its own small IPv6/IPv4/mDNS networking over raw Ethernet frames, so it runs on
bare-metal Wi-Fi chips without an OS network stack. Everything is sans-IO,
allocation-conscious and safe on 32-bit targets.

**Status: early (v0.x).** It works end to end on real hardware: an ESP32-S3
(M5Stack Cardputer) colour light is commissioned and controlled over Wi-Fi by
chip-tool, [matter.js](https://github.com/matter-js/matter.js) and
[matterctl](https://github.com/cybergarage/go-matter), all at once, and
chip-tool and this project's controller, `tmctl`, commission it over
Bluetooth LE and hand it the Wi-Fi network.
Its button is a Generic Switch whose presses reach subscribed controllers
as events. The device persists its fabrics and network in flash, and
updates its firmware over the air from `tmctl` (Matter OTA over BDX, into
the other of two flash slots, with rollback). APIs will change. The examples use the
public SDK **test** attestation credentials, so only controllers in
development mode accept them. Not certified; do not use in products.

Background and measurements: [FEASIBILITY.md](FEASIBILITY.md).

## Quick start (ESP32-S3)

Flashed without Wi-Fi credentials, the device advertises over BLE and
waits to be given a network:

    cd firmware
    tinygo flash -target esp32s3-generic -stack-size=12KB -port /dev/ttyACM0 ./esp32s3-light
    chip-tool pairing ble-wifi 1 YOUR_SSID YOUR_PASSWORD 20202021 3840
    # or, with this project's controller (see below):
    tmctl scan 34970112332                  # the networks it sees
    TMCTL_WIFI_PASSWORD=YOUR_PASSWORD tmctl commission 34970112332 -ssid YOUR_SSID

Or compile the credentials in and commission over the IP network:

    tinygo flash -target esp32s3-generic -stack-size=12KB -port /dev/ttyACM0 \
        -ldflags "-X main.ssid=YOUR_SSID -X main.password=YOUR_PASSWORD" ./esp32s3-light

Then commission it with manual code `34970112332` (passcode 20202021,
discriminator 3840), for example with the matter.js shell:

    npx @matter/nodejs-shell
    matter> commission pair --pairing-code 34970112332
    matter> commands onoff toggle 1 1

or `chip-tool pairing code 1 34970112332`. Keep a serial reader attached
while it is plugged into a computer (see the firmware's package comment).
To add another controller, open a commissioning window from an existing one
(Administrator Commissioning, cluster 0x003C).

Endpoint 1 is the light, an Extended Color Light shown on the RGB LED:
On/Off with the Lighting feature (timed on, global scene, start-up
state), Level Control (fades on and off), Color Control (hue and
saturation, enhanced hue, colour loop, xy, colour temperature coupled to
the level), Scenes Management and Groups. Its state and scenes survive
restarts. Endpoint 2 is the G0 button as a Generic Switch:
a press reports the InitialPress and ShortRelease events, a hold of 1 s
or more InitialPress, LongPress and LongRelease. Watch them from a
subscription (`subscribe 1` in the matter.js shell), or in chip-tool's
interactive mode:

    chip-tool interactive start
    >>> any subscribe-event-by-id 0x003B 0xFFFFFFFF 0 60 1 2 --is-urgent true

The device also reports Basic Information StartUp and Leave, the General
Diagnostics BootReason, and Access Control entry changes; `identify
identify 10 1 1` (or TriggerEffect) blinks the LED.

## Controller (tmctl)

`cmd/tmctl` is a command-line Matter controller for Linux (and other hosts)
built on the `controller` package. It keeps its own fabric, a root CA it
generates with the keys in `~/.local/share/tiny-matter-go/controller/`
(readable only by you), commissions devices onto it over the IP network
or Bluetooth LE, and works with them:

    go install github.com/shabunin/tiny-matter-go/cmd/tmctl@latest
    tmctl discover                          # devices in commissioning mode
    tmctl commission 34970112332 -label lamp
    tmctl discover -ble                     # also those advertising over BLE
    tmctl scan 34970112332                  # networks a device in commissioning mode sees
    TMCTL_WIFI_PASSWORD=... tmctl commission 34970112332 -ssid MyWiFi -label lamp
    TMCTL_THREAD_DATASET=$(ot-ctl dataset active -x | head -1) tmctl commission MT:... -thread
    tmctl invoke lamp 1 OnOff Toggle
    tmctl read lamp 1 OnOff onOff
    tmctl write lamp 0 BasicInformation NodeLabel "desk lamp"
    tmctl invoke lamp 1 LevelControl MoveToLevel level=128 transitionTime=10 optionsMask=0 optionsOverride=0
    tmctl invoke lamp 1 ColorControl MoveToHueAndSaturation 170 254 30 0 0
    tmctl invoke lamp 1 ScenesManagement StoreScene 0 1     # group 0, scene 1
    tmctl invoke lamp 1 ScenesManagement RecallScene 0 1 3000
    tmctl events lamp '*' '*'
    tmctl subscribe lamp 2 Switch -events -urgent   # until Ctrl-C
    tmctl open-window lamp                  # codes for another controller
    tmctl update-noc lamp -id 7             # new operational key and certificate (UpdateNOC), as node 7
    tmctl remove lamp                       # RemoveFabric, then forget it
    tmctl group-add 0x101 lights            # a group, with a key set of its own
    tmctl group-join lamp 1 lights          # key set, key map, ACL entry, AddGroup
    tmctl group-invoke lights OnOff Toggle  # to every member, by IPv6 multicast
    tmctl bind pir 6 lamp 1 OnOff           # the sensor switches the lamp itself (Binding, ACL entry)
    tmctl group-bind pir 6 lights OnOff     # ...or the whole group, by multicast (Binding, group key)

Clusters, attributes, commands, events and enum values go by their names
in the Matter SDK's IDL, case aside (a unique prefix will do: `basic` is
BasicInformation), or by number; `tmctl clusters [cluster]` lists them.
Lists and structs are written as JSON. Subscriptions survive a restart
of the device, which resumes them, and are made again if they are lost.

`update-noc` rotates a node's operational credentials: under the
fail-safe the node makes a new key (CSRRequest for UpdateNOC), `tmctl`
issues its certificate, optionally for a new node ID, and commits the
change over a CASE session to the new identity; until then a restart
keeps the old credentials, and the fail-safe rolls them back.

`tmctl` resumes CASE sessions instead of repeating the full handshake,
also from one run to the next: a command takes about 0.2 s instead of
1.4 s with the boards here. Each running `tmctl` locks an identity slot
in the state directory (`identities/`), with a node ID of its own and
the resumption records of its sessions, so runs one after another reuse
the first slot, and runs at the same time (a `subscribe` and an
`invoke`) are distinct peers to a node. Devices keep their records with
their state.

`commission` and `scan` look for the device with mDNS and over Bluetooth
LE at once (unless its QR code says it is not on BLE). A device on the IP
network is commissioned there and keeps its network. One found only over
BLE is commissioned over BTP if there is a network to give it: Wi-Fi with
`-ssid` (password from `-password` or `$TMCTL_WIFI_PASSWORD`), or Thread
with `-thread` and the operational dataset in hex, as `ot-ctl dataset
active -x` prints it (`-dataset` or `$TMCTL_THREAD_DATASET`). The device
is told to join the network (Network Commissioning), then reached on the
IP network for CASE and CommissioningComplete. `-ble` reaches the device
over BLE only, also one that is on a network already; with an address,
that is where it will be on the network. `scan` asks a device in
commissioning mode which networks it sees (ScanNetworks) and leaves it
uncommissioned. Bluetooth goes through BlueZ over the D-Bus system bus
(Linux). A Thread device is reached through a Thread border router on the
host's network; that has not been tried with real Thread hardware yet.

Device attestation is verified against the production PAAs of the Matter
Distributed Compliance Ledger, which are built in (see Third-party data),
and the CSA's certification declaration keys. The SDK test PAAs and test
certification declarations are trusted too, for development devices such
as the ones here, unless `-strict` is given. More PAAs go in
`~/.local/share/tiny-matter-go/controller/paa`, or pass `-paa`. A device
that already has a controller joins through a commissioning window opened
there, for example `chip-tool pairing open-commissioning-window <node> 1
600 1000 3840`, whose code goes to `tmctl commission`.

Tested against the devices here (over BLE, the Cardputer is commissioned
onto Wi-Fi in 13 to 25 s, most of it spent joining the network), a
[matter.js](https://github.com/matter-js/matter.js) device, and chip-tool,
which commissions devices through windows `tmctl open-window` opens; the
production trust store was checked against a commercial device's
attestation chain and certification declaration.

## Software updates (OTA)

A device with an `ImageStore` (`device.Config.Updates`) is an OTA
Software Update Requestor: a provider announces itself
(AnnounceOTAProvider) or is set in DefaultOTAProviders (queried every 24
h); the device asks it for an image (QueryImage), downloads it over BDX,
checks the image header (vendor, product, version, applicable versions)
and its SHA-256 digest, saves that it is applying the update, asks the
provider (ApplyUpdateRequest) and restarts into the new version. Started
on it, it reports VersionApplied, boot reason SoftwareUpdateCompleted
and tells the provider (NotifyUpdateApplied), over a CASE session of its
own if need be. `tmctl` is a provider for one image at a time:

    tmctl ota-image new.bin new.ota -vendor 0xFFF1 -product 0x8000 -version 2
    tmctl ota-info new.ota
    tmctl ota-update lamp new.ota

`ota-update` serves the image, announces itself to the node and follows
the download, the apply request and the restart until the node runs the
new version. With `-default` it writes itself into the node's
DefaultOTAProviders instead and waits for the node's query; a node with
no session to its provider finds it with DNS-SD (`device.Config.Resolve`,
`mdns.NodeResolver`), and `tmctl` advertises its operational service with
avahi while it serves. On the Cardputer, General Diagnostics test event
trigger 0x002A000000000100 (the SDK's) makes the node query its default
providers at once. `cmd/hostdevice -updates <dir>` updates itself this way: the
payload is a new hostdevice binary (version set at build time with
`-ldflags "-X main.softwareVersion=2"`), which it executes in its place.

On the ESP32-S3, `firmware/esp32s3-loader` is a small second-stage boot
loader for two application slots (0x10000 and 0x200000; boot records at
0xE000 and 0xF000; device state stays at the top of the first 4 MB). The
running firmware writes an update into the other slot (`firmware/espota`)
and adds a boot record for it; the loader starts the new image once, as a
trial, and the firmware confirms it after it has been on the network for
20 s. If the board is reset before that, the loader starts the previous
image again and the device reports the failed update (DownloadError).
An image on trial arms the RTC watchdog first thing (TinyGo's start-up
code disables the watchdogs, so the loader cannot), and confirming
disarms it: an image that hangs, or cannot reach the network, resets
after 3 minutes and is rolled back too.
Setting the board up once over USB:

    cd firmware
    tinygo build -target ./esp32s3-loader/target.json -o loader.elf ./esp32s3-loader
    esptool --chip esp32s3 elf2image --flash-mode dio --flash-freq 80m --flash-size 8MB -o loader.bin loader.elf
    tinygo build -target esp32s3-generic -stack-size=12KB -o app.elf ./esp32s3-light   # same flags for both
    tinygo build -target esp32s3-generic -stack-size=12KB -o app.bin ./esp32s3-light
    go run ./espslot record -elf app.elf -bin app.bin -slot 0x10000 -seq 1 -o rec.bin
    esptool --port /dev/ttyACM0 write-flash 0 loader.bin 0xE000 rec.bin 0x10000 app.bin

and each update after that:

    tinygo build -target esp32s3-generic -stack-size=12KB -ldflags "-X main.softwareVersion=2 ..." -o app.elf ./esp32s3-light
    tinygo build -target esp32s3-generic -stack-size=12KB -ldflags "-X main.softwareVersion=2 ..." -o app.bin ./esp32s3-light
    go run ./espslot payload -elf app.elf -bin app.bin -o app.payload
    tmctl ota-image app.payload app-2.ota -vendor 0xFFF1 -product 0x8000 -version 2
    tmctl ota-update lamp app-2.ota

On the Cardputer a 1 MB image downloads in about 22 s and the whole update
takes about a minute. Firmware flashed with `tinygo flash` (at offset 0,
without the loader) runs as before, with updates disabled.

## Layout

| Path | What |
|---|---|
| `tlv/` | Matter TLV codec (spec Appendix A): reflection-free, zero-copy reader, 32-bit safe |
| `crypto/p256/` | P-256 ECDSA (raw r‖s, hedged RFC 6979 nonces), ECDH, point/scalar ops for SPAKE2+; explicit `io.Reader` RNG |
| `crypto/ccm/` | AES-CCM as a `cipher.AEAD`, allocation-free |
| `message/` | Message and protocol headers, message encryption (`Cipher`), counters and replay windows; group keys (operational, privacy, session ID) and header privacy |
| `exchange/` | Sessions, exchanges and MRP (acks, retransmission, backoff; skipped on reliable transports such as BTP); group messages (trust-first counters per sender, unanswered, sent with privacy to the group's multicast address); sans-IO, driven by `HandlePacket` and `Poll(now)` |
| `btp/` | Bluetooth Transport Protocol (spec 4.19), sans-IO, peripheral and central: handshake, segmentation and reassembly, windows and acks; BLE advertising data, and parsing it |
| `crypto/spake2p/` | SPAKE2+ (P-256, RFC 9383 as used by Matter) and the passcode verifier (W0, L) |
| `securechannel/` | Secure Channel opcodes, status reports, session parameters, session key derivation, opcode dispatcher |
| `securechannel/pase/` | PASE: device responder (commissioning window, busy handling, attempt limit) and commissioner initiator |
| `im/` | Interaction Model server: Read (wildcards, data version filters, chunked reports, lists too large for a message split into list appends, cluster-specific statuses), Subscribe (change reports with min/max intervals, keep-alives, chunked priming; subscriptions kept when the subscriber stops answering, saved, and resumed under their ID), Write, Invoke, Timed; group Invoke and Write (no endpoint, no response); events (a compact log per priority, event reads with filters, urgent and batched event reports, fabric-sensitive events); data model of endpoints and clusters with global attributes |
| `bdx/` | Bulk Data Exchange (spec 11.22), synchronous and receiver-driven as OTA uses it: a download (receiver) and a file server (sender), with the SDK's message encodings |
| `ota/` | OTA image files: header encoding and parsing, image creation with the SHA-256 digest, and a streaming reader that checks the digest |
| `clusters/` | Server clusters: OTA Software Update Requestor and Provider (with the commands' codecs), Descriptor, Access Control (and the ACL checker, with entry-change events), Basic Information (StartUp, Leave), General Commissioning (fail-safe), Administrator Commissioning (enhanced and basic windows, multi-admin), Operational Credentials, Network Commissioning (Wi-Fi or Thread, with fail-safe rollback), General Diagnostics (boot reason, network interfaces, test event triggers), Group Key Management (trust-first key sets, key map, group table), Groups (with names), Scenes Management (per fabric and group, recalled with a transition), On/Off (with the Lighting feature), Level Control and Color Control (all modes, transitions in Poll, start-up values), Identify (with effects), Switch (momentary, with long press), Fixed Label and User Label, Localization Configuration, Time Format Localization and Unit Localization, Power Source (wired or battery); RGB conversion for lights |
| `clusters/unittesting/` | The SDK's Unit Testing cluster (an attribute of every data type, list, struct and fabric-scoped attributes, echo commands, test events) for running the SDK's YAML conformance tests against a host device |
| `securechannel/casesession/` | CASE (Sigma1-3) responder and initiator, and session resumption (Sigma2_Resume) from a store of resumption records shared by both roles |
| `credentials/` | Matter TLV certificates: decode/encode, X.509 reconstruction (byte-exact against SDK vectors), chain validation, CSR, attestation elements; `devcreds/` holds the SDK development DAC/PAI/CD |
| `fabric/` | Fabric table with pending/commit for commissioning and for UpdateNOC (the committed credentials kept for rollback and saving), compressed fabric ID, operational IPK |
| `dnssd/` | DNS-SD service descriptions (commissionable `_matterc._udp`, operational `_matter._tcp`) for an mDNS advertiser |
| `ip6/` | Minimal IPv6 host over raw Ethernet frames: EUI-64 link-local address, Neighbor Discovery, Echo, multicast groups with MLDv2 reports, UDP |
| `ip4/` | Minimal IPv4 host over the same frames: DHCP client (renew/rebind/expiry), ARP, default gateway, Echo, IGMPv2 reports, UDP |
| `mdns/` | Small dual-stack mDNS/DNS-SD responder (PTR/SRV/TXT/A/AAAA over IPv6 and IPv4, announcements, goodbyes, legacy and QU replies; a `dnssd.Advertiser`), querier (browse, resolve, cache), and a frugal resolver of operational nodes for devices |
| `onboarding/` | Onboarding payloads: QR codes (`MT:` base-38) and 11/21-digit manual pairing codes (Verhoeff check digit) |
| `credentials/attestation/` | Device attestation for commissioners: DAC/PAI/PAA chain, certification declaration (CMS, CSA and SDK test signing keys), attestation and NOCSR signatures; PAA trust stores, with the production and SDK test PAAs built in |
| `controller/` | Matter controller for hosts: own fabric (persisted), OTA provider (serves an image over BDX; accepts CASE from its nodes), mDNS and BLE discovery, commissioning over IP or BLE, chosen by where the device is found (PASE, attestation, CSR, NOC, Wi-Fi or Thread network provisioning, CASE), network scans, read/write/invoke, subscriptions that re-establish themselves, commissioning windows, node removal, groups (key sets, setting nodes up, multicast commands from a fixed sender with a saved counter) |
| `cmd/tmctl/` | Command-line controller over `controller` (see above) |
| `thread/` | Thread operational datasets: parsing and checking the TLVs a commissioner hands a device |
| `internal/dbus/` | Minimal D-Bus client: wire format by signature, system bus connection (EXTERNAL auth), method calls, signals |
| `internal/bluez/` | BLE central over BlueZ's D-Bus API: LE discovery with service data, connect, GATT writes and indications for the Matter service |
| `internal/datamodel/` | Cluster, attribute, command and event names and types from the SDK's IDL; formats TLV with names and encodes typed values for `tmctl` |
| `storage/` | Persistent state as one blob: `Store` interface, in-memory store, and an A/B flash store (CRC, sequence numbers, power-cut safe) over a TinyGo block device |
| `device/` | Assembles a node: sessions, PASE, CASE, IM server, root clusters, ACL, fail-safe, commissioning completion, advertising, boot events, persistence of fabrics, ACL, networks, groups, event numbers, the group message counter, the reboot count, subscriptions (resumed after a restart, or when the subscriber answers again, over a CASE session the device opens, as the SDK does) and application cluster state (saved a few seconds after it changes); commands through bindings (to a node over a CASE session it opens or reuses, to a group by multicast) (reopens commissioning when the last fabric is removed); the OTA requestor (query, download, apply, report after the restart) over an `ImageStore` |
| `cmd/hostdevice/` | An Extended Color Light (with scenes and groups; logs the colour it would show) and a push button (Generic Switch, worked from standard input or test event triggers) over UDP on a host (SDK dev credentials, passcode 20202021, discriminator 3840, avahi mDNS), updating itself over OTA with `-updates`; label, localization and power source clusters on the root endpoint, and the Unit Testing cluster with `-unit-testing`; chip-tool and matter.js commission and control it |
| `internal/simnet/` | Deterministic simulated network for multi-node tests |
| `crypto/internal/` | Go's constant-time `nistec`/`fiat` P-256 and `bigmod`, vendored (BSD, `LICENSE-GO`) with the base table moved to flash |
| `tools/chipvectors.py` | Converts connectedhomeip crypto test-vector headers to JSON test data |
| `firmware/esp32s3-loader/` | Second-stage boot loader (C, no Go runtime) for two application slots with boot records, trial starts and rollback |
| `firmware/espota/` | ESP32-S3 `ImageStore`: writes an update into the inactive slot through the ROM flash routines, checks it, adds its boot record, confirms a working image |
| `firmware/espslot/` | Host tool: boot records and OTA payloads for the two-slot layout |
| `firmware/matterble/` | Matter BLE peripheral for TinyGo: the Matter GATT service over `tinygo.org/x/bluetooth`'s HCI stack, driving `btp` |
| `firmware/esp32s3-light/` | Matter Extended Color Light on the RGB LED (with Scenes and Groups, listening on its groups' multicast addresses) and push button (G0 as a Generic Switch) over Wi-Fi for ESP32-S3 (M5 Cardputer): espradio frames + `ip6` + `ip4` + `mdns` + `device`, BLE commissioning via `matterble`. Separate module. chip-tool, matter.js and matterctl commission it over Wi-Fi in about 3-4 s (real attestation) and control it, all at once (multi-admin) |
| `probe/onchip/` | Device and controller commissioning each other on the microcontroller (no radio), with timings |
| `probe/` | Feasibility probes, TinyGo benchmarks and a large-memory QEMU Cortex-M target |

## Checks

    make test         # go vet + go test
    make test32       # GOARCH=386: catches 64-bit int assumptions
    make tinygo-test  # tests under TinyGo
    make cross        # build for pico2-w, pico-w, xiao-ble, esp32c3, esp32s3
    make bench-qemu   # instruction counts on emulated Cortex-M3

The SDK's YAML conformance tests (`src/app/tests/suites` in
connectedhomeip, run with its `chiptool.py` runner and chip-tool) run against
`cmd/hostdevice -unit-testing`: the cluster tests for what the device
implements, and the SDK's own TestCluster family, pass.

## Third-party data

From [connectedhomeip](https://github.com/project-chip/connectedhomeip), the
Matter SDK (Apache-2.0, Copyright Project CHIP Authors):

- test vectors under `*/testdata/` and inlined in some tests, used only for
  testing;
- the test PAA certificates in `credentials/attestation/testpaa/`, which
  `attestation.TestPAAs` trusts for development devices;
- the production PAA certificates in `credentials/attestation/prodpaa/`
  (the SDK's mirror of the Distributed Compliance Ledger's PAAs; see
  `SOURCE.md` there), which `attestation.ProductionPAAs` trusts;
- `internal/datamodel/controller-clusters.matter`, the IDL of the clusters
  a controller knows, embedded in `tmctl` for names and types.

## License

Apache License 2.0, see [LICENSE](LICENSE). Parts derived from the Go
standard library are under Go's BSD license; see [NOTICE](NOTICE).

Matter is a trademark of the Connectivity Standards Alliance. This project
is not affiliated with or certified by the Connectivity Standards Alliance.
