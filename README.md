# tiny-matter-go

A Matter device stack in Go that targets TinyGo on microcontrollers. It
implements commissioning (PASE, attestation, operational credentials, CASE),
the Interaction Model (read, write, invoke, subscribe, events), multi-admin, BLE commissioning (BTP) with Network Commissioning for Wi-Fi
(and Thread datasets, short of a Thread radio), and its own small IPv6/IPv4/mDNS networking over raw Ethernet frames, so it runs on
bare-metal Wi-Fi chips without an OS network stack. Everything is sans-IO,
allocation-conscious and safe on 32-bit targets.

**Status: early (v0.x).** It works end to end on real hardware: an ESP32-S3
(M5Stack Cardputer) on/off light is commissioned and controlled over Wi-Fi by
chip-tool, [matter.js](https://github.com/matter-js/matter.js) and
[matterctl](https://github.com/cybergarage/go-matter), all at once, and
chip-tool and this project's controller, `tmctl`, commission it over
Bluetooth LE and hand it the Wi-Fi network.
Its button is a Generic Switch whose presses reach subscribed controllers
as events. The device persists its fabrics and network in flash. APIs will change. The examples use the
public SDK **test** attestation credentials, so only controllers in
development mode accept them. Not certified; do not use in products.

Background and measurements: [FEASIBILITY.md](FEASIBILITY.md).

## Quick start (ESP32-S3)

Flashed without Wi-Fi credentials, the device advertises over BLE and
waits to be given a network:

    cd firmware
    tinygo flash -target esp32s3-generic -port /dev/ttyACM0 ./esp32s3-light
    chip-tool pairing ble-wifi 1 YOUR_SSID YOUR_PASSWORD 20202021 3840
    # or, with this project's controller (see below):
    tmctl scan 34970112332                  # the networks it sees
    TMCTL_WIFI_PASSWORD=YOUR_PASSWORD tmctl commission 34970112332 -ssid YOUR_SSID

Or compile the credentials in and commission over the IP network:

    tinygo flash -target esp32s3-generic -port /dev/ttyACM0 \
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

Endpoint 1 is the light. Endpoint 2 is the G0 button as a Generic Switch:
a press reports the InitialPress and ShortRelease events, a hold of 1 s
or more InitialPress, LongPress and LongRelease. Watch them from a
subscription (`subscribe 1` in the matter.js shell), or in chip-tool's
interactive mode:

    chip-tool interactive start
    >>> any subscribe-event-by-id 0x003B 0xFFFFFFFF 0 60 1 2 --is-urgent true

The device also reports Basic Information StartUp and Leave, the General
Diagnostics BootReason, and Access Control entry changes; `identify
identify 10 1 1` blinks the LED.

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
    tmctl events lamp '*' '*'
    tmctl subscribe lamp 2 Switch -events -urgent   # until Ctrl-C
    tmctl open-window lamp                  # codes for another controller
    tmctl remove lamp                       # RemoveFabric, then forget it

Clusters, attributes, commands, events and enum values go by their names
in the Matter SDK's IDL, case aside (a unique prefix will do: `basic` is
BasicInformation), or by number; `tmctl clusters [cluster]` lists them.
Lists and structs are written as JSON. Subscriptions come back by
themselves after the device restarts.

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

## Layout

| Path | What |
|---|---|
| `tlv/` | Matter TLV codec (spec Appendix A): reflection-free, zero-copy reader, 32-bit safe |
| `crypto/p256/` | P-256 ECDSA (raw r‖s, hedged RFC 6979 nonces), ECDH, point/scalar ops for SPAKE2+; explicit `io.Reader` RNG |
| `crypto/ccm/` | AES-CCM as a `cipher.AEAD`, allocation-free |
| `message/` | Message and protocol headers, message encryption (`Cipher`), counters and replay windows |
| `exchange/` | Sessions, exchanges and MRP (acks, retransmission, backoff; skipped on reliable transports such as BTP); sans-IO, driven by `HandlePacket` and `Poll(now)` |
| `btp/` | Bluetooth Transport Protocol (spec 4.19), sans-IO, peripheral and central: handshake, segmentation and reassembly, windows and acks; BLE advertising data, and parsing it |
| `crypto/spake2p/` | SPAKE2+ (P-256, RFC 9383 as used by Matter) and the passcode verifier (W0, L) |
| `securechannel/` | Secure Channel opcodes, status reports, session parameters, session key derivation, opcode dispatcher |
| `securechannel/pase/` | PASE: device responder (commissioning window, busy handling, attempt limit) and commissioner initiator |
| `im/` | Interaction Model server: Read (wildcards, data version filters, chunked reports), Subscribe (change reports with min/max intervals, keep-alives, chunked priming), Write, Invoke, Timed; events (a compact log per priority, event reads with filters, urgent and batched event reports, fabric-sensitive events); data model of endpoints and clusters with global attributes |
| `clusters/` | Server clusters: Descriptor, Access Control (and the ACL checker, with entry-change events), Basic Information (StartUp, Leave), General Commissioning (fail-safe), Administrator Commissioning (enhanced and basic windows, multi-admin), Operational Credentials, Network Commissioning (Wi-Fi or Thread, with fail-safe rollback), General Diagnostics (boot reason, network interfaces, test event triggers), On/Off, Identify, Switch (momentary, with long press) |
| `securechannel/casesession/` | CASE (Sigma1-3) responder and initiator; resumption falls back to a full handshake |
| `credentials/` | Matter TLV certificates: decode/encode, X.509 reconstruction (byte-exact against SDK vectors), chain validation, CSR, attestation elements; `devcreds/` holds the SDK development DAC/PAI/CD |
| `fabric/` | Fabric table with pending/commit for commissioning, compressed fabric ID, operational IPK |
| `dnssd/` | DNS-SD service descriptions (commissionable `_matterc._udp`, operational `_matter._tcp`) for an mDNS advertiser |
| `ip6/` | Minimal IPv6 host over raw Ethernet frames: EUI-64 link-local address, Neighbor Discovery, Echo, MLDv2 reports, UDP |
| `ip4/` | Minimal IPv4 host over the same frames: DHCP client (renew/rebind/expiry), ARP, default gateway, Echo, IGMPv2 reports, UDP |
| `mdns/` | Small dual-stack mDNS/DNS-SD responder (PTR/SRV/TXT/A/AAAA over IPv6 and IPv4, announcements, goodbyes, legacy and QU replies; a `dnssd.Advertiser`) and querier (browse, resolve, cache) |
| `onboarding/` | Onboarding payloads: QR codes (`MT:` base-38) and 11/21-digit manual pairing codes (Verhoeff check digit) |
| `credentials/attestation/` | Device attestation for commissioners: DAC/PAI/PAA chain, certification declaration (CMS, CSA and SDK test signing keys), attestation and NOCSR signatures; PAA trust stores, with the production and SDK test PAAs built in |
| `controller/` | Matter controller for hosts: own fabric (persisted), mDNS and BLE discovery, commissioning over IP or BLE, chosen by where the device is found (PASE, attestation, CSR, NOC, Wi-Fi or Thread network provisioning, CASE), network scans, read/write/invoke, subscriptions that re-establish themselves, commissioning windows, node removal |
| `cmd/tmctl/` | Command-line controller over `controller` (see above) |
| `thread/` | Thread operational datasets: parsing and checking the TLVs a commissioner hands a device |
| `internal/dbus/` | Minimal D-Bus client: wire format by signature, system bus connection (EXTERNAL auth), method calls, signals |
| `internal/bluez/` | BLE central over BlueZ's D-Bus API: LE discovery with service data, connect, GATT writes and indications for the Matter service |
| `internal/datamodel/` | Cluster, attribute, command and event names and types from the SDK's IDL; formats TLV with names and encodes typed values for `tmctl` |
| `storage/` | Persistent state as one blob: `Store` interface, in-memory store, and an A/B flash store (CRC, sequence numbers, power-cut safe) over a TinyGo block device |
| `device/` | Assembles a node: sessions, PASE, CASE, IM server, root clusters, ACL, fail-safe, commissioning completion, advertising, boot events, persistence of fabrics, ACL, networks, event numbers and the reboot count (reopens commissioning when the last fabric is removed) |
| `cmd/hostdevice/` | An on/off light and a push button (Generic Switch, worked from standard input or test event triggers) over UDP on a host (SDK dev credentials, passcode 20202021, discriminator 3840, avahi mDNS); chip-tool and matter.js commission and control it |
| `internal/simnet/` | Deterministic simulated network for multi-node tests |
| `crypto/internal/` | Go's constant-time `nistec`/`fiat` P-256 and `bigmod`, vendored (BSD, `LICENSE-GO`) with the base table moved to flash |
| `tools/chipvectors.py` | Converts connectedhomeip crypto test-vector headers to JSON test data |
| `firmware/matterble/` | Matter BLE peripheral for TinyGo: the Matter GATT service over `tinygo.org/x/bluetooth`'s HCI stack, driving `btp` |
| `firmware/esp32s3-light/` | Matter on/off light and push button (G0 as a Generic Switch) over Wi-Fi for ESP32-S3 (M5 Cardputer): espradio frames + `ip6` + `ip4` + `mdns` + `device`, BLE commissioning via `matterble`. Separate module. chip-tool, matter.js and matterctl commission it over Wi-Fi in about 3-4 s (real attestation) and control it, all at once (multi-admin) |
| `probe/onchip/` | Device and controller commissioning each other on the microcontroller (no radio), with timings |
| `probe/` | Feasibility probes, TinyGo benchmarks and a large-memory QEMU Cortex-M target |

## Checks

    make test         # go vet + go test
    make test32       # GOARCH=386: catches 64-bit int assumptions
    make tinygo-test  # tests under TinyGo
    make cross        # build for pico2-w, pico-w, xiao-ble, esp32c3, esp32s3
    make bench-qemu   # instruction counts on emulated Cortex-M3

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
