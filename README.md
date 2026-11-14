# tiny-matter-go

A Matter device stack in Go that targets TinyGo on microcontrollers. It
implements commissioning (PASE, attestation, operational credentials, CASE),
the Interaction Model (read, write, invoke, subscribe), multi-admin, BLE commissioning (BTP) with Network Commissioning for Wi-Fi,
and its own small IPv6/IPv4/mDNS networking over raw Ethernet frames, so it runs on
bare-metal Wi-Fi chips without an OS network stack. Everything is sans-IO,
allocation-conscious and safe on 32-bit targets.

**Status: early (v0.x).** It works end to end on real hardware: an ESP32-S3
(M5Stack Cardputer) on/off light is commissioned and controlled over Wi-Fi by
chip-tool, [matter.js](https://github.com/matter-js/matter.js) and
[matterctl](https://github.com/cybergarage/go-matter), all at once, and
chip-tool commissions it over Bluetooth LE and hands it the Wi-Fi network.
The device persists its fabrics and network in flash. APIs will change. The examples use the
public SDK **test** attestation credentials, so only controllers in
development mode accept them. Not certified; do not use in products.

Background and measurements: [FEASIBILITY.md](FEASIBILITY.md).

## Quick start (ESP32-S3)

Flashed without Wi-Fi credentials, the device advertises over BLE and
waits to be given a network:

    cd firmware
    tinygo flash -target esp32s3-generic -port /dev/ttyACM0 ./esp32s3-light
    chip-tool pairing ble-wifi 1 YOUR_SSID YOUR_PASSWORD 20202021 3840

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

## Layout

| Path | What |
|---|---|
| `tlv/` | Matter TLV codec (spec Appendix A): reflection-free, zero-copy reader, 32-bit safe |
| `crypto/p256/` | P-256 ECDSA (raw r‖s, hedged RFC 6979 nonces), ECDH, point/scalar ops for SPAKE2+; explicit `io.Reader` RNG |
| `crypto/ccm/` | AES-CCM as a `cipher.AEAD`, allocation-free |
| `message/` | Message and protocol headers, message encryption (`Cipher`), counters and replay windows |
| `exchange/` | Sessions, exchanges and MRP (acks, retransmission, backoff; skipped on reliable transports such as BTP); sans-IO, driven by `HandlePacket` and `Poll(now)` |
| `btp/` | Bluetooth Transport Protocol (spec 4.19), sans-IO server side: handshake, segmentation and reassembly, windows and acks; BLE advertising data |
| `crypto/spake2p/` | SPAKE2+ (P-256, RFC 9383 as used by Matter) and the passcode verifier (W0, L) |
| `securechannel/` | Secure Channel opcodes, status reports, session parameters, session key derivation, opcode dispatcher |
| `securechannel/pase/` | PASE: device responder (commissioning window, busy handling, attempt limit) and commissioner initiator |
| `im/` | Interaction Model server: Read (wildcards, data version filters, chunked reports), Subscribe (change reports with min/max intervals, keep-alives, chunked priming), Write, Invoke, Timed; data model of endpoints and clusters with global attributes |
| `clusters/` | Server clusters: Descriptor, Access Control (and the ACL checker), Basic Information, General Commissioning (fail-safe), Administrator Commissioning (enhanced and basic windows, multi-admin), Operational Credentials, Network Commissioning (Wi-Fi, with fail-safe rollback), On/Off |
| `securechannel/casesession/` | CASE (Sigma1-3) responder and initiator; resumption falls back to a full handshake |
| `credentials/` | Matter TLV certificates: decode/encode, X.509 reconstruction (byte-exact against SDK vectors), chain validation, CSR, attestation elements; `devcreds/` holds the SDK development DAC/PAI/CD |
| `fabric/` | Fabric table with pending/commit for commissioning, compressed fabric ID, operational IPK |
| `dnssd/` | DNS-SD service descriptions (commissionable `_matterc._udp`, operational `_matter._tcp`) for an mDNS advertiser |
| `ip6/` | Minimal IPv6 host over raw Ethernet frames: EUI-64 link-local address, Neighbor Discovery, Echo, MLDv2 reports, UDP |
| `ip4/` | Minimal IPv4 host over the same frames: DHCP client (renew/rebind/expiry), ARP, default gateway, Echo, IGMPv2 reports, UDP |
| `mdns/` | Small dual-stack mDNS/DNS-SD responder (PTR/SRV/TXT/A/AAAA over IPv6 and IPv4, announcements, goodbyes, legacy and QU replies); a `dnssd.Advertiser` |
| `storage/` | Persistent state as one blob: `Store` interface, in-memory store, and an A/B flash store (CRC, sequence numbers, power-cut safe) over a TinyGo block device |
| `device/` | Assembles a node: sessions, PASE, CASE, IM server, root clusters, ACL, fail-safe, commissioning completion, advertising, persistence of fabrics, ACL and Wi-Fi networks (reopens commissioning when the last fabric is removed) |
| `cmd/hostdevice/` | An on/off light over UDP on a host (SDK dev credentials, passcode 20202021, discriminator 3840, avahi mDNS); chip-tool commissions and controls it |
| `internal/simnet/` | Deterministic simulated network for multi-node tests |
| `crypto/internal/` | Go's constant-time `nistec`/`fiat` P-256 and `bigmod`, vendored (BSD, `LICENSE-GO`) with the base table moved to flash |
| `tools/chipvectors.py` | Converts connectedhomeip crypto test-vector headers to JSON test data |
| `firmware/matterble/` | Matter BLE peripheral for TinyGo: the Matter GATT service over `tinygo.org/x/bluetooth`'s HCI stack, driving `btp` |
| `firmware/esp32s3-light/` | Matter on/off light over Wi-Fi for ESP32-S3 (M5 Cardputer): espradio frames + `ip6` + `ip4` + `mdns` + `device`, BLE commissioning via `matterble`. Separate module. chip-tool, matter.js and matterctl commission it over Wi-Fi in about 3-4 s (real attestation) and control it, all at once (multi-admin) |
| `probe/onchip/` | Device and controller commissioning each other on the microcontroller (no radio), with timings |
| `probe/` | Feasibility probes, TinyGo benchmarks and a large-memory QEMU Cortex-M target |

## Checks

    make test         # go vet + go test
    make test32       # GOARCH=386: catches 64-bit int assumptions
    make tinygo-test  # tests under TinyGo
    make cross        # build for pico2-w, pico-w, xiao-ble, esp32c3, esp32s3
    make bench-qemu   # instruction counts on emulated Cortex-M3

## Third-party test data

Test vectors under `*/testdata/` and inlined in some tests come from
[connectedhomeip](https://github.com/project-chip/connectedhomeip)
(Apache-2.0), the Matter SDK, and are used only for testing.

## License

Apache License 2.0, see [LICENSE](LICENSE). Parts derived from the Go
standard library are under Go's BSD license; see [NOTICE](NOTICE).

Matter is a trademark of the Connectivity Standards Alliance. This project
is not affiliated with or certified by the Connectivity Standards Alliance.
