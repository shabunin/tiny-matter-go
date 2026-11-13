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
| `crypto/internal/` | Go's constant-time `nistec`/`fiat` P-256 and `bigmod`, vendored (BSD, `LICENSE-GO`) with the base table moved to flash |
| `tools/chipvectors.py` | Converts connectedhomeip crypto test-vector headers to JSON test data |
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
