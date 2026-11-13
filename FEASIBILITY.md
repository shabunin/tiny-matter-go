# Matter device stack on TinyGo: feasibility (2026-11-13)

Toolchain: TinyGo 0.44.0 (Go 1.26.10, LLVM 22). Probes are in `probe/`.

## Verdict
Feasible on Wi-Fi MCUs (Pico 2 W / Pico W, ESP32-C3/S3). Thread is not realistic yet.
The protocol core is portable. The work is in our own P-256 layer, IPv6/mDNS on lneto, BLE indications and an RNG driver.

## Verified here
| Item | Result |
|---|---|
| SHA-256, HMAC, HKDF, PBKDF2, AES (stdlib) | Compile for pico2-w, pico-w, xiao-ble, esp32c3/c6/s3, and run correctly on emulated Cortex-M |
| P-256 point math (`elliptic` ScalarMult/Add, needed for SPAKE2+) | Runs on emulated Cortex-M |
| stdlib `ecdsa` / `ecdh` on bare metal | **Fatal at runtime.** Go 1.26 ignores the caller's RNG and reads `/dev/urandom`. TinyGo ignores `//go:debug cryptocustomrand=1`. We need our own ECDSA/ECDH on vendored `nistec` (BSD-licensed fiat code) |
| stdlib P-256 precomputed table | 88 KB placed in **RAM** (`.data`) by TinyGo. Must be replaced by a flash-resident or smaller table |
| `crypto/rand` | Not wired on rp2040/rp2350 or esp32c6 in TinyGo. RP2350 has a TRNG, so we write a small driver |
| AES-CCM | Not in stdlib. gomat's `ccm` package compiles for pico2-w as-is (BSD-2) |
| go-matter (Apache-2.0) | Assumes 64-bit `int` (TLV encoder, `go-safecast`): fails on 32-bit. With 64-bit `int`, the TLV/message/PASE/CASE/IM/MRP/session packages compile under TinyGo. Its mDNS/device packages need `net.ListenMulticastUDP` (absent) |
| gomat (BSD-2) | `mattertlv` and `ccm` compile for pico2-w. The root package has the same `int` overflow. It is controller-only |

## Cost estimate (QEMU instruction counts, `probe/bench`, `-opt=2`)
Conversions to ms assume 150 MHz and about 1.3 cycles per instruction. They are estimates, not measured on silicon.

| Op | Instructions | ≈ ms on RP2350 |
|---|---|---|
| P-256 ScalarMult | 6.0 M | 50 |
| P-256 ScalarBaseMult (with the big table) | 1.2 M | 10 |
| PBKDF2 ×1000 | 44 M | 380 (avoidable: store w0/L) |
| SHA-256 1 KB | 60 K | 0.5 |

PASE on the device is about 4 variable-base scalar multiplications, roughly 0.2–0.3 s. CASE is about 5–6, roughly 0.3–0.4 s. Both are well inside Matter's timeouts.

Flash for the crypto set is 300–450 KB at `-opt=z`. That includes `fmt`/`strconv` pulled in by stdlib, so there is room to trim.

## Networking and radio (from web/source research, not yet verified on hardware)
- **soypat/lneto** has IPv6 and UDP6. It lacks SLAAC/link-local generation and MLD, and holds only one IPv6 address per stack.
- **lneto mDNS** has no AAAA records and no subtype PTRs.
- **cyw43439** has a hardware multicast filter, but the IPv6 mDNS entry is not set up.
- **ESP32 Wi-Fi** works through tinygo-org/espradio on ESP32, C3 and S3, but not on C6 or H2.
- **tinygo bluetooth**: the peripheral role works on nRF52840, CYW43439 and espradio. Server-side **indications are not implemented**, and Matter's BTP needs them, so this needs a patch. The nRF SoftDevice MTU is fixed at 23.
- **Thread**: only experimental pure-Go OpenThread (hilli/gothread) exists, with no hardware radio driver.
- **Prior art**: no Matter-on-TinyGo project found.

## Suggested path
1. A pure-Go core with no `net`/`os` dependency, `int`-width safe, and an injected RNG/clock/transport:
   - TLV, message framing, MRP, PASE, CASE, Interaction Model, data model
   - our own P-256 ECDSA/ECDH/SPAKE2+
2. A host transport (`net`) for development, commissioned on-network by chip-tool. All of this is testable on a PC.
3. A Pico 2 W port: CYW43439 + lneto, with the IPv6 and mDNS gaps filled, and the RP2350 TRNG.
4. BLE commissioning (BTP) after patching indications into tinygo bluetooth. ESP32-C3/S3 via espradio.
