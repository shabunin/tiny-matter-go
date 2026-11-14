# tiny-matter-go

A Matter device stack in Go that targets TinyGo on microcontrollers
(first target: Raspberry Pi Pico 2 W). See [FEASIBILITY.md](FEASIBILITY.md).

## Layout

| Path | What |
|---|---|
| `tlv/` | Matter TLV codec (spec Appendix A): reflection-free, zero-copy reader, 32-bit safe |
| `crypto/p256/` | P-256 ECDSA (raw r‖s, hedged RFC 6979 nonces), ECDH, point/scalar ops for SPAKE2+; explicit `io.Reader` RNG |
| `crypto/ccm/` | AES-CCM as a `cipher.AEAD`, allocation-free |
| `message/` | Message and protocol headers, message encryption (`Cipher`), counters and replay windows |
| `exchange/` | Sessions, exchanges and MRP (acks, retransmission, backoff); sans-IO, driven by `HandlePacket` and `Poll(now)` |
| `crypto/spake2p/` | SPAKE2+ (P-256, RFC 9383 as used by Matter) and the passcode verifier (W0, L) |
| `securechannel/` | Secure Channel opcodes, status reports, session parameters, session key derivation, opcode dispatcher |
| `securechannel/pase/` | PASE: device responder (commissioning window, busy handling, attempt limit) and commissioner initiator |
| `im/` | Interaction Model server: Read (wildcards, data version filters, chunked reports), Write, Invoke, Timed; data model of endpoints and clusters with global attributes |
| `clusters/` | Server clusters: Descriptor, Access Control (and the ACL checker), Basic Information, General Commissioning (fail-safe), Operational Credentials, On/Off |
| `securechannel/casesession/` | CASE (Sigma1-3) responder and initiator; resumption falls back to a full handshake |
| `credentials/` | Matter TLV certificates: decode/encode, X.509 reconstruction (byte-exact against SDK vectors), chain validation, CSR, attestation elements; `devcreds/` holds the SDK development DAC/PAI/CD |
| `fabric/` | Fabric table with pending/commit for commissioning, compressed fabric ID, operational IPK |
| `dnssd/` | DNS-SD service descriptions (commissionable `_matterc._udp`, operational `_matter._tcp`) for an mDNS advertiser |
| `ip6/` | Minimal IPv6 host over raw Ethernet frames: EUI-64 link-local address, Neighbor Discovery, Echo, MLDv2 reports, UDP |
| `mdns/` | Small mDNS/DNS-SD responder (PTR/SRV/TXT/AAAA, announcements, goodbyes, legacy and QU replies); a `dnssd.Advertiser` |
| `storage/` | Persistent state as one blob: `Store` interface, in-memory store, and an A/B flash store (CRC, sequence numbers, power-cut safe) over a TinyGo block device |
| `device/` | Assembles a node: sessions, PASE, CASE, IM server, root clusters, ACL, fail-safe, commissioning completion, advertising, persistence of fabrics and ACL (reopens commissioning when the last fabric is removed) |
| `cmd/hostdevice/` | An on/off light over UDP on a host (SDK dev credentials, passcode 20202021, discriminator 3840, avahi mDNS); chip-tool commissions and controls it |
| `internal/simnet/` | Deterministic simulated network for multi-node tests |
| `crypto/internal/` | Go's constant-time `nistec`/`fiat` P-256 and `bigmod`, vendored (BSD, `LICENSE-GO`) with the base table moved to flash |
| `tools/chipvectors.py` | Converts connectedhomeip crypto test-vector headers to JSON test data |
| `firmware/esp32s3-light/` | Matter on/off light over Wi-Fi for ESP32-S3 (M5 Cardputer): espradio frames + `ip6` + `mdns` + `device`. Separate module. chip-tool commissions it over Wi-Fi in about 4 s (real attestation) and controls it |
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
