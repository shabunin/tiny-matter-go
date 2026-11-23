# AGENTS.md: tiny-matter-go reference

This is the complete working reference for this repository, for coding agents and for people. The
README is the short introduction; this file is meant to be enough to change the code safely.

## 1. What this is

tiny-matter-go is a Matter (CSA smart-home standard, spec 1.4) **device** stack in Go. It targets
**TinyGo on microcontrollers** and also runs under regular Go on hosts. It contains:

- **Secure channel:** PASE (SPAKE2+), device attestation, operational credentials, and CASE with
  session resumption.
- **Interaction Model:** read, write, invoke, timed, subscribe and events, plus group messaging.
- **Clusters:** a large set of server clusters (lights, plugs, switches, sensors, bridge, scenes,
  groups, OTA, diagnostics).
- **Commissioning:** BLE (BTP) and on-network commissioning.
- **Networking:** its own minimal IPv6, IPv4 and mDNS stacks over raw Ethernet frames, so it runs on
  bare-metal Wi-Fi chips (ESP32 via `tinygo.org/x/espradio`, the Pico 2 W's CYW43439 via
  `soypat/cyw43439`) without an OS network stack.
- **A host controller:** the `controller` package and the `tmctl` CLI.

Status: v0.x, and APIs change freely. It is not certified. The examples use the Matter SDK's public
**test** attestation credentials (vendor 0xFFF1, product 0x8000, passcode 20202021, discriminator
3840), which only controllers in development mode accept.

## 2. Repository map

There are three Go modules:

| Module | Path | Notes |
|---|---|---|
| `github.com/shabunin/tiny-matter-go` | `/` | The stack, controller, tmctl, hostdevice. `make test` covers this module only. |
| `firmware` | `firmware/` | TinyGo firmware for ESP32/ESP32-S3 and the Pico 2 W; `replace` points at `../`. Builds only with TinyGo. |
| `probe` | `probe/` | Feasibility probes, benchmarks, size checks; `replace` points at `../`. |

### Packages of the root module

| Path | What |
|---|---|
| `tlv/` | Matter TLV codec (spec Appendix A). Reflection-free, zero-copy `Reader`; `Writer` with `Checkpoint`/`Rollback`, `PutRaw`; `NewStreamWriter` pushes output through a fixed buffer into a sink (used to save state without a whole-state buffer). 32-bit safe. |
| `crypto/p256/` | P-256 ECDSA (raw r‖s, hedged RFC 6979 nonces), ECDH, point and scalar ops for SPAKE2+. Explicit `io.Reader` RNG. |
| `crypto/ccm/` | AES-CCM as a `cipher.AEAD`, allocation-free. |
| `crypto/spake2p/` | SPAKE2+ (RFC 9383 as Matter uses it) and the passcode verifier (W0, L). |
| `crypto/internal/` | Go's constant-time `nistec`/`fiat` P-256 and `bigmod`, vendored (BSD, `LICENSE-GO`); base table moved to flash; ECDSA scalar math through `fiat.P256Scalar` (no heap allocations). |
| `message/` | Message and protocol headers, message encryption (`Cipher`), counters and replay windows; group keys (operational, privacy, session ID) and header privacy. |
| `exchange/` | Sessions, exchanges and MRP (acks, retransmission, backoff; skipped on reliable transports such as BTP); group messages (trust-first counters per sender, multicast with privacy). Sans-IO: `HandlePacket` and `Poll(now)`. |
| `btp/` | Bluetooth Transport Protocol (spec 4.19), peripheral and central: handshake, segmentation and reassembly, windows and acks; BLE advertising data. Sans-IO. |
| `securechannel/` | Secure Channel opcodes, status reports, session parameters, key derivation, dispatcher. |
| `securechannel/pase/` | PASE device responder (commissioning window, busy handling, attempt limit) and commissioner initiator. |
| `securechannel/casesession/` | CASE (Sigma1-3) responder and initiator; resumption (Sigma2_Resume) from a `ResumptionStore` shared by both roles. |
| `credentials/` | Matter TLV certificates: decode/encode, X.509 reconstruction (byte-exact against SDK vectors), chain validation, CSR, attestation elements. `devcreds/`: the SDK development DAC/PAI/CD. |
| `credentials/attestation/` | Attestation for commissioners: DAC/PAI/PAA chain, certification declaration (CMS; CSA and SDK test signing keys), attestation and NOCSR signatures; PAA trust stores with production (`prodpaa/`) and SDK test (`testpaa/`) PAAs embedded. |
| `fabric/` | Fabric table with pending/commit (commissioning, UpdateNOC; committed credentials kept for rollback), compressed fabric ID, operational IPK. |
| `im/` | Interaction Model server and client codecs, and the data model (`Node`, `Endpoint`, `Cluster`). See §4. |
| `clusters/` | Server clusters, see §5. `clusters/unittesting/`: the SDK's Unit Testing cluster (host tests only). |
| `device/` | Assembles a node from all of the above. See §6. |
| `storage/` | Persistent state: `Store` (one blob), `Streamer` (streamed save), `Memory`, and `Flash`: an A/B store over a `BlockDevice` with CRC and sequence numbers, safe against power cuts. |
| `bdx/` | Bulk Data Exchange (spec 11.22), synchronous and receiver-driven as OTA uses it: download (receiver) and file server (sender). |
| `ota/` | OTA image files: header encode/parse, image creation with SHA-256, a streaming reader that checks the digest. |
| `dnssd/` | DNS-SD service descriptions (commissionable `_matterc._udp`, operational `_matter._tcp`) and the `Advertiser` interface. |
| `ip6/` | Minimal IPv6 host over Ethernet frames: EUI-64 link-local address, Neighbor Discovery, Echo, multicast with MLDv2, UDP. Link-local only (no SLAAC). |
| `ip4/` | Minimal IPv4 host: DHCP client (renew/rebind/expiry), ARP, default gateway, Echo, IGMPv2, UDP. |
| `mdns/` | Dual-stack mDNS/DNS-SD responder (PTR/SRV/TXT/A/AAAA, announcements, goodbyes, legacy and QU replies), querier (browse, resolve, cache), and `NodeResolver`, a small resolver of operational nodes for devices. |
| `onboarding/` | QR codes (`MT:` base-38) and 11/21-digit manual pairing codes (Verhoeff). |
| `thread/` | Thread operational datasets: parsing and checking the TLVs. There is no Thread radio support. |
| `controller/` | Host controller: own fabric (persisted), commissioning over IP or BLE (PASE, attestation, CSR, NOC, Wi-Fi/Thread provisioning, CASE), network scans, read/write/invoke/subscribe (self-re-establishing), events, commissioning windows, UpdateNOC, node removal, groups, bindings, OTA provider. |
| `cmd/tmctl/` | CLI over `controller`. See §9. |
| `cmd/hostdevice/` | The device on a host over UDP, for interop and conformance testing. See §7. |
| `internal/simnet/` | Deterministic simulated network and clock for multi-node tests. |
| `internal/datamodel/` | Names and types from the SDK IDL (`controller-clusters.matter`, embedded); formats TLV with names, encodes typed values for `tmctl`. |
| `internal/dbus/`, `internal/bluez/` | Minimal D-Bus client; BLE central over BlueZ (discovery, connect, GATT writes and indications). |
| `internal/avahi/` | Advertises DNS-SD services on Linux through `avahi-publish` processes. |
| `internal/mcast/` | Sends UDP to IPv6 multicast out of every host interface. |
| `tools/chipvectors.py` | Converts connectedhomeip crypto test-vector headers to JSON test data. |

### The firmware module

| Path | What |
|---|---|
| `firmware/esp32s3-light/` | ESP32-S3 (M5Stack Cardputer) firmware. Endpoint 1: Extended Color Light on the RGB LED, with scenes and groups. Endpoint 2: the G0 button as a Generic Switch. Optional Grove units: an ENV sensor on endpoints 3-5, a PIR on endpoint 6. Commissioning over BLE, or over IP when Wi-Fi credentials are compiled in. OTA requestor when started by the loader. |
| `firmware/esp32-node/` | Classic ESP32 boards; the TinyGo target picks the board. `m5stack` is an M5Stack Core with the M5GO base: a colour light on the LED bar plus a Color Dimmer Switch (endpoint 2) worked by an angle unit and buttons. `m5stick-c` is an M5StickC Plus with an ENV unit: temperature, humidity and pressure (endpoints 1-3). Commissioned over IP only. |
| `firmware/pico2w-light/` | Raspberry Pi Pico 2 W firmware: an On/Off Light on the LED (endpoint 1) with Identify, Groups and Scenes. Commissioning over BLE, or over IP when Wi-Fi credentials are compiled in. OTA requestor when running from a partition. Test builds can reboot into the UF2 bootloader by a test event trigger. |
| `firmware/wifinode/` | Shared Wi-Fi runner over a `Radio` interface: joins the network (rejoining for radios that don't), runs `ip6` and `ip4`, advertises with `mdns`, resolves nodes, joins group addresses (and programs the radio's multicast filter), feeds the device. |
| `firmware/espwifi/` | The ESP32 and ESP32-S3 radio (`espradio`) as a `wifinode.Radio`. |
| `firmware/cyw43wifi/` | The Pico W / Pico 2 W CYW43439 as a `wifinode.Radio`: leaves before rejoining, 10-entry multicast filter, network scans (also before joining, for BLE commissioning). Optionally starts the Bluetooth controller for HCI. |
| `firmware/rptrng/` | RP2350 TRNG reader with the health tests on and SHA-256 conditioning. |
| `firmware/rpwatchdog/` | RP2350 watchdog, reboot (a full chip reset, USB included) and last reset reason. |
| `firmware/rpflash/` | A range of the RP2350 flash as a `storage.BlockDevice` at physical offsets (read through the untranslated XIP window), with aligned sector erases and whole-page writes. |
| `firmware/rpota/` | RP2350 OTA on the boot ROM's A/B partitions: the layout, the partition table and UF2 encoding (host-testable), and a `device.ImageStore` that writes the other partition, confirms a trial image (`explicit_buy`) and reboots into an update (FLASH_UPDATE). |
| `firmware/rpslot/` | Host tool: the one-time partition-table UF2, firmware UF2s with the RP2350-E10 workaround, and OTA payloads (the image flagged TBYB). |
| `firmware/matterble/` | Matter BLE peripheral over `tinygo.org/x/bluetooth`'s HCI stack, driving `btp`. `Options` caps the MTU for controllers with short HCI writes and runs vendor setup (an address) after the reset. |
| `firmware/climate/`, `firmware/envsensor/` | ENV unit endpoints; SHT3x and BMP280 drivers. |
| `firmware/pir/` | PIR as an Occupancy Sensor endpoint. |
| `firmware/softi2c/` | Bit-banged I2C (the M5StickC HAT header, which TinyGo's hardware I2C cannot drive). |
| `firmware/esp32flash/` | Classic ESP32 flash as a `storage.BlockDevice`, through the ROM routines from IRAM with the cache off. |
| `firmware/watchdog/` | RTC watchdog: resets the chip if `Feed` stops (hangs, fatal errors). Measures the slow clock at `Start`. |
| `firmware/esp32s3-loader/` | Second-stage boot loader (C, no Go runtime) for ESP32-S3: two application slots, boot records, trial starts and rollback. |
| `firmware/esp32-loader/` | Second-stage boot loader (C, no Go runtime) for classic ESP32 (M5Stack Core / M5StickC Plus): two slots at `0x11000` / `0x201000` with trial starts and rollback. |
| `firmware/espota/` | ESP32 and ESP32-S3 `device.ImageStore`: writes an update into the inactive slot, checks it, adds its boot record, confirms a working image. |
| `firmware/espslot/` | Host tool: boot records, OTA payloads and static ELF/BIN verification for the two-slot layouts. |
| `firmware/flashtest/` | Flash store test program. |

### The probe module

| Path | What |
|---|---|
| `probe/onchip/` | Full commissioning (device and controller) on the microcontroller over an in-memory loopback, with timings. |
| `probe/devicesize/` | Builds a complete on/off light to measure flash and RAM. |
| `probe/p256time/` | Times P-256 operations on a real board (serial output). |
| `probe/p256bench/`, `probe/bench/` | Instruction counts on an emulated Cortex-M3 (QEMU `-icount`). |
| `probe/stackcheck/` | Two exchange managers over memory on an MCU target. |

## 3. Architecture and core rules

- **Sans-IO everywhere.** Protocol packages never read sockets, sleep or start goroutines. Input
  arrives through `HandlePacket(now, from, pkt)` (or a `Transport` for output). Timers are driven by
  `Poll(now) time.Time`, which does due work and returns when it next needs to run (zero means
  idle). The caller owns the clock and the loop. Tests use `internal/simnet` for deterministic time.
- **Layering:** `message` → `exchange` (sessions, MRP) → `securechannel` (PASE/CASE) and `im`
  (Interaction Model) → `clusters` → `device` (assembly) → firmware or `cmd/hostdevice`
  (transport, radio, LEDs). `controller` uses the same lower layers from the client side.
- **TinyGo first.** Code must compile and run under TinyGo on 32-bit targets:
  - No reflection-based encoding.
  - Watch integer widths. `make test32` runs the tests with GOARCH=386.
  - Avoid packages TinyGo lacks.
- **Memory discipline.** A classic ESP32 has about 150 KB of Go heap, and the TinyGo GC does not
  compact, so out-of-memory failures are usually fragmentation:
  - Allocate large buffers once at boot and reuse them.
  - Never allocate multi-KB blocks per message.
  - Stream large encodings (`tlv.NewStreamWriter`).
  - Return package-level slices from `Attributes()`/`AcceptedCommands()`, not fresh literals.
- **Randomness is explicit.** Pass an `io.Reader`. Crypto takes the RNG as a parameter.
- **Constant-time crypto** comes from Go's vendored `nistec`/`fiat`. Do not replace it with
  variable-time math.

## 4. The Interaction Model and the data model (`im/`)

### Node, endpoints, clusters

```go
n := im.NewNode(seed)                       // data versions start from seed
ep := n.AddEndpoint(1, clusters.DeviceTypeExtendedColorLight)
n.AddCluster(ep, clusters.Descriptor{}, onOff, level, color)
n.Changed(1, clusters.IDOnOff, 0)            // bump the data version; triggers subscription reports
n.Emit(now, im.Event{Path: ..., Priority: im.PriorityInfo, Fields: func(w *tlv.Writer) {...}})
```

`im.Cluster`:

```go
type Cluster interface {
    ID() uint32
    Revision() uint16
    FeatureMap() uint32
    Attributes() []uint32          // cluster-specific attribute IDs, ascending; globals are added
    AcceptedCommands() []uint32
    GeneratedCommands() []uint32
    ReadAttribute(ctx *Context, attr uint32, w *tlv.Writer, tag tlv.Tag) Status
    WriteAttribute(ctx *Context, attr uint32, appendItem bool, r *tlv.Reader) Status
    Invoke(ctx *Context, cmd uint32, r *tlv.Reader, resp *Response) Status
}
```

Embed `im.ClusterBase` for defaults: no features, no commands, writes unsupported. The framework
serves the global attributes (ClusterRevision, FeatureMap, AttributeList, AcceptedCommandList,
GeneratedCommandList).

Optional interfaces a cluster may implement:

| Interface | Purpose |
|---|---|
| `im.PrivilegeInfo` | `ReadPrivilege(attr)`, `WritePrivilege(attr)`, `InvokePrivilege(cmd)`. The defaults are View to read and Operate to write and invoke. |
| `im.Persister` | `EncodeState(w, tag)` / `DecodeState(r)`: state that survives restarts. `device` saves it a few seconds after `Changed`, and restores it when the cluster is added (`DecodeState` is where start-up behaviour applies). Endpoint 0 clusters may persist too. |
| `im.Poller` | `Poll(n, endpoint, now) time.Time`, for timers and transitions. |
| `im.EventInfo` | `Events() []uint32` lists the events generated. This is descriptive only. |
| `im.EventPrivilegeInfo` | An event read privilege above View. |

`im.Context` passes `Now`, `Node`, `Session` (`Session.FabricIndex` is the accessing fabric),
`Endpoint`, `FabricFiltered` (on reads) and `Timed` (true inside a timed interaction).

Conventions inside callbacks:

- **Status codes:** return `im.UnsupportedAttribute`, `im.UnsupportedWrite`,
  `im.UnsupportedCommand`, `im.ConstraintError`, `im.InvalidDataType`, `im.InvalidCommand`,
  `im.NeedsTimedInteraction`, and so on.
- **Cluster-specific status:** for an attribute, `return ctx.ClusterStatus(code)`; for a command,
  `return resp.ClusterStatus(code)`. Both yield FAILURE with the cluster code.
- **Command responses:** `w := resp.Fields(responseCmdID)`, write the fields with context tags, then
  return `im.Success`. The framework closes the containers.
- **Lists:** a write with `appendItem` set carries one item to append, as in chunked list writes.
  Without it, the write is a full replacement (an array).
- **Changes:** call `ctx.Node.Changed(ctx.Endpoint, ID, attr)` after any change a client could
  observe.
- **Fabric-scoped lists:** filter on `ctx.FabricFiltered`; write fabric-sensitive fields only for the
  accessing fabric.
- **Decoding helpers:** `im.ForEachField(r, func(r *tlv.Reader, tag uint8) error)`. `clusters` has
  internal helpers such as `eachItem`, `filter` and `accessingFabric`.
- **Testing outside a server:** `im.NewResponse(w, path)` builds a `Response` for calling `Invoke` in
  a test.

A minimal cluster:

```go
type Counter struct {
    im.ClusterBase
    n uint32
}

var counterAttrs, counterCmds = []uint32{0}, []uint32{0}

func (*Counter) ID() uint32                  { return 0xFFF1FC10 }
func (*Counter) Revision() uint16            { return 1 }
func (*Counter) Attributes() []uint32        { return counterAttrs }
func (*Counter) AcceptedCommands() []uint32  { return counterCmds }

func (c *Counter) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
    if attr != 0 {
        return im.UnsupportedAttribute
    }
    w.PutUint(tag, uint64(c.n))
    return im.Success
}

func (c *Counter) Invoke(ctx *im.Context, cmd uint32, r *tlv.Reader, resp *im.Response) im.Status {
    if cmd != 0 {
        return im.UnsupportedCommand
    }
    c.n++
    ctx.Node.Changed(ctx.Endpoint, c.ID(), 0)
    return im.Success
}
```

### Server behaviour worth knowing

- **Reads:** wildcards, data version filters and chunked reports. A list attribute too large for one
  message is sent as the attribute with the items that fit, then the rest as list-append reports
  (path ListIndex null) in later chunks. A non-list value that does not fit gets RESOURCE_EXHAUSTED.
- **Subscriptions:**
  - Change reports honour the min/max intervals; keep-alives; chunked priming.
  - When a report goes unanswered, the subscription is kept as *lost*, saved, and resumed under the
    same ID over a CASE session the device opens. The backoff is 5 s, 30 s, 2 m, 5 m, 15 m, 30 m,
    1 h, 2 h, 4 h, 6 h, 6 h, after which it is dropped.
  - A session closed by the peer drops its subscriptions, as the SDK does.
  - A subscribe whose paths name no existing attribute or event is refused with INVALID_ACTION.
- **Events:**
  - A compact log per priority; urgent and batched reports; fabric-sensitive events.
  - A path naming an event the cluster does not generate matches nothing. No UNSUPPORTED_EVENT is
    returned, as in the SDK.
- **Timed:** a TimedRequest precedes a write or invoke. Clusters check `ctx.Timed` for attributes
  and commands that need it.
- **Groups:** group Invoke and Write over multicast; no response.
- **Limits:** one path per invoke (as the SDK's default); a bounded number of paths per read.

## 5. Clusters (`clusters/`)

The root node, wired by `device`:

- Descriptor, Access Control (ACL checker, entry-change events), Basic Information (StartUp, Leave
  events).
- General Commissioning (fail-safe), Administrator Commissioning (enhanced and basic windows),
  Operational Credentials (UpdateNOC).
- Network Commissioning (Wi-Fi or Thread, fail-safe rollback).
- General, Software and Wi-Fi Network Diagnostics (boot reason, interfaces, test event triggers).
- Group Key Management (trust-first key sets, key map, group table).
- OTA Software Update Requestor (and the Provider codecs, for the controller).

Application clusters:

- **Lighting:** On/Off (Lighting feature: timed on, global scene, start-up), Level Control and Color
  Control (all modes, transitions in Poll, start-up values, temperature coupled to level), and RGB
  conversion (`colorconv.go`).
- **Groups and scenes:** Groups (with names); Scenes Management (per fabric and group, transitions,
  table size 16 and 7 per fabric as the SDK's default).
- **Switches and binding:** Identify (with effects), Switch (momentary, long press; events), Binding
  (to nodes and to groups).
- **Sensors (`sensors.go`):** Temperature, Relative Humidity, Pressure, Illuminance, Occupancy,
  Boolean State (contact).
- **Bridge (`bridge.go`):** Aggregator, Bridged Device Basic Information.
- **Utility:** Fixed Label, User Label (Manage to write, persisted, at most 10 labels of 16 bytes);
  Localization Configuration, Time Format Localization (CALFMT when calendar types are set) and
  Unit Localization (TEMP), all persisted; Power Source (WIRED, or BAT with optional RECHG, sampled
  through a `State` callback). The Power Source device type is `clusters.DeviceTypePowerSource`.

`clusters/unittesting` (cluster 0xFFF1FC05) follows the SDK's `test-cluster-server.cpp`:

- an attribute of every data type, with the reference app's defaults and ranges;
- list, struct and fabric-scoped attributes;
- generalErrorBoolean (INVALID_DATA_TYPE) and clusterErrorBoolean (cluster status 17);
- a timed-write boolean;
- echo commands, and test events, including the MEI ones.

It is for the conformance tests only; do not put it on firmware.

Scenes behave like the SDK in two ways:

- FabricSceneInfo lists a fabric once it has had a scene, with CurrentScene 0 until one is current.
- CopyScene returns RESOURCE_EXHAUSTED whenever the fabric has no capacity, even to replace a scene.

Scene values from AddScene are clamped to each attribute's spec constraints. For example, colour
temperature is clamped to the physical range. The SDK clamps only to the type's range.

## 6. Assembling a device (`device/`)

```go
d, err := device.New(device.Config{
    Transport: tr, Rand: rng, Port: 5540,
    Verifier: v, Salt: salt, Iterations: 1000, Discriminator: 3840,
    Attestation: &clusters.Attestation{DACKey: k, DACCert: devcreds.DACCert,
        PAICert: devcreds.PAICert, CertificationDeclaration: devcreds.CertificationDeclaration},
    Basic: &clusters.BasicInformation{VendorID: devcreds.VendorID, ProductID: devcreds.ProductID, ...},
    DeviceType: clusters.DeviceTypeExtendedColorLight.ID,
    Advertiser: adv,          // dnssd.Advertiser (mdns responder or avahi)
    Store:      store,        // storage.Store; fabrics, ACL, networks, groups, cluster state...
    Clock:      time.Now,
    WiFi:       true,         // Network Commissioning (set d.Net.Connect after New)
    Updates:    imageStore,   // OTA requestor
    Resolve:    resolver.Resolve, // find other nodes (bindings, OTA provider) by DNS-SD
})
ep := d.Node.AddEndpoint(1, clusters.DeviceTypeExtendedColorLight)
d.Node.AddCluster(ep, clusters.Descriptor{}, onOff, level, color, d.NewScenes(), d.NewGroups(identify))
if !d.Commissioned() { d.OpenCommissioningWindow() }
for {
    // feed packets: d.HandlePacket(now, from, pkt)
    next := d.Poll(now)  // run until next, or until a packet arrives
}
```

- **What it holds:** `Device` exposes `Node`, `Root` (endpoint 0), `Server`, `Fabrics`, `ACL`,
  `FailSafe`, `PASE`, `General`, `OpCreds`, `Admin`, `Net`, `Diagnostics`, `Software`,
  `WiFiDiagnostics`, `Groups`, `Resumptions`, `OTA`, and `OnMulticast` (the group addresses to
  join).
- **Bindings and bridges:** `SendBound(now, ep, cluster, cmd, fields)` sends a command to the
  endpoint's bindings, to a node over CASE or to a group by multicast. Bridges add and remove
  endpoints at runtime with `AddedEndpoint` / `RemoveEndpoint`.
- **What persists:** fabrics, ACL, networks, groups and keys, event number epoch, group message
  counter, reboot count, CASE resumption records, lost subscriptions, and `Persister` cluster state.
  - State is streamed through a small buffer (never one whole-state buffer).
  - `HoldSaves` defers saving.
  - `Flush` saves now.
- **Commissioning:** removing the last fabric reopens commissioning. Boot events and the boot reason
  are reported at start.
- **OTA requestor:** query, BDX download, header and digest checks, apply, restart, then
  NotifyUpdateApplied. A provider is found by AnnounceOTAProvider or DefaultOTAProviders (queried
  every 24 h; `CheckForUpdate` queries now).

## 7. The host device (`cmd/hostdevice`)

It runs the stack over UDP on Linux, with mDNS through `avahi-publish`. It uses the SDK development
credentials, passcode 20202021 and discriminator 3840.

```
-type light|onofflight|dimlight|ctlight|plug|dimplug|temperature|humidity|pressure|lightsensor|occupancy|contact|bridge
-state <file>        keep fabrics and state across restarts
-listen [::]:5540    -passcode, -discriminator, -mdns=false
-test-key <32 hex>   enable General Diagnostics test event triggers
-updates <dir>       OTA requestor; the payload is a new hostdevice binary it executes
-unit-testing        add the Unit Testing cluster on endpoint 1 (conformance tests)
```

Every type also has, on endpoint 0: Fixed and User Label, the three localization clusters, and a
wired Power Source. Endpoint 1 has labels too.

Lines on stdin work the device:

- **Button:** `press`, `release`, `click`, `long`.
- **Sensors:** `contact open|closed`, `occupancy on|off`, `temp 21.5`, `humidity 40`,
  `pressure 1013`, `lux 300`.
- **Bridge:** `add <kind> [label]`, `remove <ep>`, `reach <ep> on|off`.
- `@<ep> <cmd>` picks the endpoint.

The software version is set with `-ldflags "-X main.softwareVersion=N"`.

## 8. Firmware

Toolchain: TinyGo 0.44 (Go 1.26, LLVM 22).

**ESP32-S3 (M5Stack Cardputer):**

```sh
cd firmware
tinygo flash -target esp32s3-generic -stack-size=12KB ./esp32s3-light                 # BLE commissioning
tinygo flash -target esp32s3-generic -stack-size=12KB \
    -ldflags "-X main.ssid=SSID -X main.password=PW" ./esp32s3-light                    # on-network
```

**Classic ESP32:**

```sh
tinygo flash -target m5stack   -stack-size=10KB -ldflags "-X main.ssid=... -X main.password=..." ./esp32-node
tinygo flash -target m5stick-c -stack-size=10KB -ldflags "-X main.ssid=... -X main.password=..." ./esp32-node
```

**Raspberry Pi Pico 2 W:** the flash is partitioned for OTA. Once, with the board in BOOTSEL mode,
copy the partition table to its drive, then the firmware:

```sh
go run ./rpslot install -o install.uf2                                  # copy to the RP2350 drive
tinygo build -target pico2-w -stack-size=16KB -o app.elf ./pico2w-light  # BLE commissioning
tinygo build -target pico2-w -stack-size=16KB \
    -ldflags "-X main.ssid=... -X main.password=..." -o app.elf ./pico2w-light  # on-network
go run ./rpslot uf2 -elf app.elf -o app.uf2                              # copy to the drive
```

- **Stack sizes are required:** 12 KB on the S3, 10 KB on the ESP32 and 16 KB on the Pico 2 W
  (520 KB of RAM). Commissioning takes the main goroutine past the 8 KB default: on the Pico 2 W
  that overflowed with a HardFault at AddTrustedRootCertificate. Do not go higher on the ESP32: goroutine stacks come out of the
  ~150 KB heap.
- **Wi-Fi credentials go only through `-ldflags -X`.** Never commit them, and never print them in
  logs.
- **Factory reset:** hold G0 (Cardputer), button B (M5GO) or the M5 button (StickC) for 5 s.
- **Cardputer LED states:**
  - Dim cyan: waiting for BLE commissioning.
  - Dim purple: waiting for commissioning over IP.
  - Yellow: factory reset.
  - Blinking white or green: identify on the light or the button endpoint.
- **The S3 console is USB-Serial-JTAG.** When no host reads it, prints block and stall the firmware.
  Keep a serial reader attached while the board is plugged into a computer.
- **Test event triggers:** a test build with `-X main.testEventKey=<32 hex>` enables them on the
  Cardputer. 0x003B000000000001 clicks G0, 0x003B000000000002 holds it, and 0x002A000000000100 makes
  the node query its default OTA providers.

**Pico 2 W notes:**

- **Flash layout (`rpota`):** the partition table in sector 0, partition A at `0x2000`,
  partition B at `0x1FD000` (about 2 MB each), and the state in the last 32 KB (`0x3F8000`), outside
  both. The boot ROM maps the partition it boots at `0x10000000`, so one image runs from either.
  Fabrics survive reflashing and updates.
- **OTA updates:**
  - The image is written to the partition that isn't running, with its IMAGE_DEF flagged "try
    before you buy" (TBYB), and started by a FLASH_UPDATE reboot. The ROM boots a TBYB image only
    then.
  - The image confirms itself (`explicit_buy`) 20 s after reaching the network; the ROM then erases
    the other partition's first sector. A reset before that, or 3 minutes without confirming,
    starts the previous image, and the device reports the failed update.
  - An 800 KB image downloads in about 22 s.

  ```sh
  go run ./rpslot payload -elf app.elf -o app.payload   # built with -X main.softwareVersion=N
  tmctl ota-image app.payload app-N.ota -vendor 0xFFF1 -product 0x8000 -version N
  tmctl ota-update <node> app-N.ota
  ```

- **Reflashing over USB:** a UF2 dropped on the drive also goes to the partition that isn't running
  and takes over, without a trial. Images without a partition table (`tinygo flash`) run with
  updates disabled.
- BLE commissioning (`tmctl commission <code> -ssid <network>`) takes about 25 s, mostly the Wi-Fi
  join. The controller's firmware starts with the same public address on every board; the
  firmware sets the Wi-Fi address plus one, as the Pico SDK does. The driver writes HCI packets
  of at most 252 bytes, so the ATT MTU is 243. If the provisioned network cannot be joined within
  60 s, the board reboots and advertises again.
- Only a network provisioned over BLE is stored. A board commissioned over IP with compiled-in
  credentials and then reflashed without them has a fabric but no network: factory-reset it.
- USB often fails to enumerate (the host logs "device not accepting address, error -71"), after
  any kind of start. TinyGo's RP2 driver (0.44) waits at most 570 µs in its interrupt handler for
  the status stage of SET_ADDRESS, and stalls it if the host is later; hosts take up to a frame
  (612 µs was measured; the fix is in §13). Until TinyGo is fixed, the firmware re-attaches USB
  (drops the D+ pull-up) until a host enumerates it, which takes up to about 10 s. The Matter side
  runs regardless.
- `machine.CPUReset` leaves USB dead until a replug: reboot with `rpwatchdog.Reboot`.
- A test build (`-X main.testEventKey=<32 hex>`) reboots into the UF2 bootloader on test event
  trigger `0xFFF1000000000001`, for flashing without the button, and reboots on
  `0xFFF1000000000002`:

  ```sh
  tmctl invoke <node> 0 GeneralDiagnostics TestEventTrigger enableKey=hex:<key> eventTrigger=0xFFF1000000000001
  ```

- On the USB console, `reboot` and `factory-reset` work the board.
- The LED blinks briefly every second until commissioned, and quickly while identifying.

### OTA on the ESP32 and ESP32-S3 (two slots)

**Layouts:**

- **ESP32-S3 (`esp32s3-loader`):** loader at `0x0`, boot records at `0xE000` and `0xF000`, slots at
  `0x10000` and `0x200000`. Device state is at the top of the first 4 MB.
- **Classic ESP32 (`esp32-loader`, M5Stack Core and M5StickC Plus):** loader at `0x1000`, boot
  records at `0xE000` and `0xF000`, slots at `0x11000` and `0x201000` (each 64 KB * N + `0x1000` so
  TinyGo's `.rodata` stays 64 KB-aligned for the MMU). Device state is in the last 32 KB of 4 MB
  (`0x3F8000`–`0x400000`).

**How an update runs:**

- The running firmware writes the update into the other slot (`espota`) and adds a boot record.
- The loader starts it once, as a trial. The firmware confirms it 20 s after reaching the network.
- If the board resets before that, the loader starts the previous image and the device reports
  DownloadError.
- A trial image arms the RTC watchdog first thing (TinyGo's start-up disables the watchdogs), so an
  image that hangs or never reaches the network resets after 3 minutes and is rolled back.

One-time setup over USB (ESP32-S3):

```sh
cd firmware
tinygo build -target ./esp32s3-loader/target.json -o loader.elf ./esp32s3-loader
esptool --chip esp32s3 elf2image --flash-mode dio --flash-freq 80m --flash-size 8MB -o loader.bin loader.elf
tinygo build -target esp32s3-generic -stack-size=12KB -o app.elf ./esp32s3-light   # same flags for both
tinygo build -target esp32s3-generic -stack-size=12KB -o app.bin ./esp32s3-light
go run ./espslot record -elf app.elf -bin app.bin -slot 0x10000 -seq 1 -o rec.bin
esptool --port /dev/ttyACM0 write-flash 0 loader.bin 0xE000 rec.bin 0x10000 app.bin
```

One-time setup over USB (classic ESP32: `m5stack` or `m5stick-c`):

```sh
cd firmware
tinygo build -target ./esp32-loader/target.json -o loader.elf ./esp32-loader
esptool --chip esp32 elf2image --flash-mode dio --flash-freq 40m --flash-size 4MB -o loader.bin loader.elf
tinygo build -target m5stack -stack-size=10KB -ldflags "-X main.ssid=... -X main.password=..." -o app.elf ./esp32-node
tinygo build -target m5stack -stack-size=10KB -ldflags "-X main.ssid=... -X main.password=..." -o app.bin ./esp32-node
go run ./espslot record -elf app.elf -bin app.bin -seq 1 -o rec.bin
esptool --chip esp32 --port /dev/ttyUSB0 write-flash --flash-size 4MB 0x1000 loader.bin 0xE000 rec.bin 0x11000 app.bin
```

Each update after that (same flow for ESP32-S3 and classic ESP32):

```sh
tinygo build ... -ldflags "-X main.softwareVersion=N ..." -o app.elf ./esp32-node
tinygo build ... -ldflags "-X main.softwareVersion=N ..." -o app.bin ./esp32-node
go run ./espslot payload -elf app.elf -bin app.bin -o app.payload
tmctl ota-image app.payload app-N.ota -vendor 0xFFF1 -product 0x8000 -version N
tmctl ota-update <node> app-N.ota
```

A 1.1–1.2 MB image downloads in about 30 s, and the whole update takes about a minute. Firmware
flashed directly with `tinygo flash` (no loader) runs with updates disabled.

## 9. `tmctl` (`cmd/tmctl`)

```
info | discover [s] [-ble] | commission <code> [addr] [-id n] [-label t] [-skip-attestation] [-ble]
     [-ssid name [-password pw] | -thread [-dataset hex]] | scan <code> [addr] [-ble] | nodes | label <node> <t>
read <node> <ep|*> <cluster|*> [attr|*]... [-all-fabrics]
write <node> <ep> <cluster> <attr> <value> [-timed ms]
invoke <node> <ep> <cluster> <cmd> [field=value|value]... [-timed ms]
events <node> <ep|*> <cluster|*> [event|*]... [-since n]
subscribe <node> <ep|*> <cluster|*> [attr|*]... [-events [-urgent]] [-min s] [-max s]
open-window <node> [min] | close-window <node> | remove <node> | forget <node> | update-noc <node> [-id n]
groups | group-add <g> [name] | group-delete <g> | group-join <node> <ep> <g> | group-leave <node> <ep> <g>
group-invoke <g> <cluster> <cmd> [args]
bind <node> <ep> <target> <target-ep> <cluster> | unbind ... | bindings <node> <ep>
group-bind <node> <ep> <g> <cluster> | group-unbind ...
ota-image <payload> <out.ota> -vendor id -product id -version n [-version-string s] [-min n] [-max n] [-notes url]
ota-info <image.ota> | ota-update <node> <image.ota> [-wait d] [-default [-query-wait d]]
clusters [cluster]

global flags: -dir <state dir> -paa <dir> -strict -timeout <d> (default 30s)
```

- **Names:** names come from the SDK IDL, case-insensitive, and a unique prefix works (`basic` means
  BasicInformation). Numbers work too. Lists and structs are written as JSON.
- **State:** in `~/.local/share/tiny-matter-go/controller/` (mode 0600): the fabric's root CA,
  nodes, groups, and `identities/`.
  - Each running `tmctl` locks an identity slot, with its own node ID and CASE resumption records.
    Concurrent runs are distinct peers; sequential runs reuse a slot.
  - With resumption, a command takes about 0.2 s instead of 1.4 s.
- **Commissioning:** `commission` and `scan` look for the device over mDNS and BLE at once.
  - A device on the network is commissioned there.
  - A BLE-only device is commissioned over BTP and given Wi-Fi (`-ssid`, with the password from
    `-password` or `$TMCTL_WIFI_PASSWORD`) or Thread (`-thread`, with the dataset from `-dataset` or
    `$TMCTL_THREAD_DATASET`).
  - Bluetooth goes through BlueZ.
- **Attestation:** checked against the embedded production PAAs and the CSA CD keys. SDK test PAAs
  and CDs are accepted unless `-strict` is given. Extra PAAs go in `.../controller/paa` or `-paa`.
- **Subscriptions** re-establish themselves. `update-noc` rotates a node's key and certificate under
  the fail-safe.

## 10. Testing

```sh
make test         # go vet + go test (root module)
make test32       # GOARCH=386
make tinygo-test  # selected packages under TinyGo
make fuzz         # TLV, message, PASE, IM server, CASE, ip6, ip4, mdns (60 s each)
make cross        # sizes for pico2-w, pico-w, xiao-ble, esp32c3, esp32s3
make bench-qemu   # Cortex-M3 instruction counts
```

Also compile the firmware after changes to shared packages. It is a separate module, so `make test`
does not see it:

```sh
cd firmware
tinygo build -target esp32s3-generic -stack-size=12KB -o /tmp/s3.elf ./esp32s3-light
tinygo build -target m5stack -stack-size=10KB -o /tmp/m5.bin ./esp32-node
tinygo build -target m5stick-c -stack-size=10KB -o /tmp/stick.bin ./esp32-node
tinygo build -target pico2-w -stack-size=16KB -o /tmp/pico.elf ./pico2w-light
```

`make build-firmware` builds them all.

- **Multi-node tests** use `internal/simnet` (deterministic clock and packet delivery; `Drop` hooks).
  `im` tests have a fixture with a device node and a client session (`im/im_test.go`). `device`
  tests have a harness that commissions over simnet.
- **Regression tests:** add one for every behaviour change, in the package's existing style.

### SDK YAML conformance tests

The connectedhomeip YAML suites (`src/app/tests/suites`, at tag v1.5.1.0 to match chip-tool v1.5.1)
run against `cmd/hostdevice -unit-testing`, using:

- the SDK's own runner (`scripts/tests/chipyaml/chiptool.py` with `matter_yamltests`), driving
  `chip-tool interactive server`;
- DUT node ID 0x12344321, endpoint 1;
- a PICS file generated from the device's own FeatureMap, AttributeList and AcceptedCommandList (a
  wildcard read), on top of the SDK's `ci-pics-values`;
- the SDK's `SystemCommands` (Reboot/FactoryReset), replaced by a pseudo-cluster that restarts the
  host device.

Notes for running them:

- Long tests (OO_2_3, CC_9_1, CADMIN_1_6) take 4-5 minutes each. Give each test about 450 s.
- Test_TC_PS_2_1 needs `--endpoint 0`, because the Power Source is on the root endpoint.

Last full run (v0.2.0): **185 of 204 pass**, including TestCluster (805/805) and the other Unit
Testing tests. The rest:

- **`_Simulated` tests (7):** the DUT must act as a client. They are not applicable.
- **Known failures:** Test_TC_G_2_4, BINFO_2_1, CC_6_5, CADMIN_1_16, DD_2_1 and DD_3_11 (runner
  errors), TestGroupMessaging, TestDescriptorCluster, TestBasicInformation,
  TestOperationalCredentialsCluster and TestAccessControlCluster (specific steps).
- **TestScenesFabricSceneInfo (one step):** it expects a Mode Select cluster and unclamped scene
  values (see §5).
- **TestPurposefulFailureNotNullConstraint:** it is meant to fail.

Treat any new failure outside this list as a regression.

## 11. Where the code follows the SDK rather than the spec

- Unknown event IDs in an event path match nothing (no UNSUPPORTED_EVENT).
- A subscription with no existing paths is refused with INVALID_ACTION.
- Scenes: FabricSceneInfo listing, CurrentScene 0, and the CopyScene capacity check (see §5).
- A closed session drops its subscriptions; only an unanswered report keeps one for resumption.

When the spec and the SDK disagree, the official tests (SDK behaviour) win, and the code comments
say so.

## 12. Conventions

- **Go style:** standard Go with gofmt and `go vet` clean.
- **Comments:** comments are plain prose sentences that say *why* and *what*. Doc comments on every
  exported identifier. Cite spec sections or SDK files where behaviour comes from them.
- **Names:** cluster IDs are `ID<Name>` constants and device types `DeviceType<Name>`. Attributes and
  commands are unexported constants inside the cluster file.
- **Errors in clusters** are IM `Status` values, not Go errors. Decoding errors map to
  `InvalidCommand` (commands) or `InvalidDataType`/`ConstraintError` (writes).
- **Commit messages:** `area[, area]: summary` in lower case, with no trailing period (for example
  `im: split large lists across reports`). Then a blank line and a prose body explaining what and
  why.
- **Never commit:**
  - Wi-Fi credentials, local paths or personal data. The repository is public.
  - Built binaries (for example a `hostdevice` binary in the root).
- **Matter only:** control devices through Matter, not vendor-private APIs.
- **Dependencies:** keep the root module dependency-light (standard library plus TinyGo-compatible
  code). The firmware module adds `tinygo.org/x/bluetooth`, `tinygo.org/x/espradio` and
  `github.com/soypat/cyw43439` (replaced by the fork with `Leave`, `RSSI` and `Scan`).

## 13. Pitfalls (learned the hard way)

- **TinyGo out-of-memory is usually fragmentation.** On the classic ESP32 (about 150 KB heap), OOM
  happened with 45 KB free but no free run above 3 KB.
  - Never allocate multi-KB blocks after boot: new goroutines (10 KB stacks), whole-state copies.
  - Diagnose with a private TinyGo root whose `runtime/gc_blocks.go` prints the size and caller
    before the fatal error, then map the address with `llvm-nm`.
- **TinyGo allocates where Go doesn't.**
  - `string(a) == string(b)` on byte slices allocates under TinyGo: use `bytes.Equal`.
  - `bigmod`'s Montgomery multiplication heap-allocates its scratch on 8 limbs. That is why ECDSA
    scalar math uses `fiat.P256Scalar`.
- **TinyGo's `abort()` on ESP32 halts forever** (waits for an interrupt with no reset), which is why
  `firmware/watchdog` exists. Feed it from the main loop; the timeout is 60 s.
- **The ESP32 RC slow clock is uncalibrated under TinyGo:** about 390 kHz instead of the nominal
  150 kHz on the ESP32, 145 vs 136 kHz on the S3. Fixed-frequency watchdog timeouts fire early.
  `watchdog.Start` measures the clock against the RTC timer.
- **USB-Serial-JTAG console blocks** without a reader (S3).
- **Board timings jitter about ±8% with code layout** (32 KB flash cache). Compare against an
  untouched operation.
- **The M5GO's chip has 16 MB of flash,** although images report 4 MB from their header.
- **Wi-Fi access points keep stale associations.** After a station resets without leaving (crash,
  power cut, reflash), the next join may associate but never finish the WPA handshake, and every
  retry keeps that state alive. `cyw43wifi` leaves (WLC_DISASSOC) before each retry, and the
  firmware leaves before deliberate reboots. The driver lacks `Leave` (and `RSSI` and `Scan`) upstream; the
  firmware module uses a fork (`github.com/shabunin/cyw43439`, branch `leave-rssi`).
- **cyw43439 calls the receive handler under its lock:** sending a reply from inside it deadlocks.
  Copy the frame out and handle it after `PollOne`.
- **TinyGo's RP2 `machine.Flash` is unsafe for a store:** its offsets start at the end of the
  program image, which is rarely 4 KB-aligned, so erases miss their sectors and the state is
  corrupted (seen as a lost fabric after reflashing). Use `rpflash`. TinyGo's RP2 watchdog is
  RP2040-shaped too (reset selection, tick); use `rpwatchdog`.
- **TinyGo's RP2 `crypto/rand` and `machine.GetRNG` sample the ring oscillator:** not for keys.
  Use `rptrng`.
- **The RP2350 A2 boot ROM ignores UF2s for a partition** (erratum RP2350-E10) unless an
  absolute-family block comes first. `rpslot uf2` adds one, aimed at the unused slot-1 sector;
  picotool's default target, the end of 16 MB, is the end of the 4 MB flash, where the state lives.
  So once the partition table is in, `tinygo flash` and TinyGo's UF2s are silently ignored (the
  drive accepts the copy and nothing happens).
- **TinyGo's `-o app.bin` for the RP2350 writes a UF2,** not a raw image. `rpslot` reads the ELF.
- **TinyGo's RP2 USB driver drops SET_ADDRESS when the host is slow** (TinyGo 0.44 and `dev` as of
  2026-11; RP2040 and RP2350 share the code). `handleUSBSetAddress` in
  `src/machine/machine_rp2{040,350}_usb.go` sends the status-stage ZLP, then busy-waits in the
  interrupt handler for `SIE_STATUS.ACK_REC` for at most 570 µs, and stalls EP0 if the ACK has not
  come. The host fetches that status stage up to a frame later: on a Linux xHCI host the ACK came
  139-612 µs after the setup interrupt, so some attempts were stalled. The kernel then logs
  "Device not responding to setup address" and "device not accepting address N, error -71".
  - **The fix, verified on the Pico 2 W:** 20 of 20 reboots enumerated on the first attempt, with
    no kernel errors; before it, 1 boot in 8 failed. It follows the Pico SDK:
    - In `handleUSBSetAddress`:
      - store the address and set a pending flag;
      - clear a stale EP0 IN bit (`BUFF_STATUS.Set(1)`);
      - send the ZLP and return true, with no waiting.
    - In the `BUFF_STATUS` branch, after reading and clearing `s2`: if `s2&1` (EP0 IN done) and the
      flag is set, clear the flag and write the address to `ADDR_ENDP`.
    - On bus reset, clear the flag.
  - Not reported upstream. It only affects the USB console, and the firmware works around it (§8).
- **Once the boot ROM runs an image from a partition, `0x10000000` is that partition,** and flash
  beyond its size faults. Read physical flash through `0x1C000000` (no translation, no cache), as
  `rpflash` does. The ROM's flash program and erase functions take physical offsets.

## 14. Performance (classic ESP32 at 160 MHz, TinyGo)

| Operation | Time |
|---|---|
| ECDSA Verify | 181 ms |
| ScalarMult | 124 ms |
| ECDH | 130 ms |
| Sign | ~42 ms |
| ScalarBaseMult | 22 ms |
| Field mul | ~25 µs |

- CASE Sigma3 to done takes about 440 ms.
- Commissioning the Cardputer over Wi-Fi takes about 3-4 s. Over BLE it takes 13-25 s, mostly
  joining the network.
- The 32-bit fiat backend was tried and gave no gain, so don't retry it.
- Levers left:
  - fiat Mul/Square in IRAM;
  - the ESP RSA/MPI accelerator;
  - 240 MHz (needs PLL setup in TinyGo);
  - ScalarMult's 57 allocations.

## 15. Roadmap

Planned work, in rough order. Each item needs hardware, so check that the boards are on hand before
starting it.

### Raspberry Pi Pico W / Pico 2 W (RP2040 / RP2350 with a CYW43439)

Already in place (Pico 2 W, `firmware/pico2w-light`): Wi-Fi through `cyw43wifi` with the hardware
multicast filter and network scans, BLE commissioning through the CYW43439's HCI and `matterble`,
OTA updates on the boot ROM's A/B partitions (`rpota`), the RP2350 TRNG, flash persistence, the
watchdog. Commissioned with `tmctl` in about 2 s; the firmware is about 820 KB of flash.

To do:

- **USB enumeration:** fix SET_ADDRESS in TinyGo's RP2 USB driver (see §8), then drop the
  re-attach workaround in `pico2w-light/usb.go`.
- **Pico W (RP2040):** entropy from the ring oscillator with conditioning, a flash device and a
  second-stage loader for OTA (the RP2040 boot ROM has no partitions).

### Thread

Already in place:

- `thread/` parses and checks operational datasets.
- `device.Config.Thread` adds Network Commissioning with the Thread feature: the commissioner
  provisions a dataset, and `Net.Connect` hands it to the radio.
- `controller`/`tmctl` commission Thread devices (`-thread`, a dataset from `ot-ctl dataset
  active -x`), then reach them through a border router. This has not been tried with real Thread
  hardware.

To do:

- **An IEEE 802.15.4 radio driver:** nRF52840 (TinyGo-supported) or ESP32-C6/H2 (no espradio
  support yet).
- **A Thread stack:** 6LoWPAN, MLE (attach as a Minimal End Device or Sleepy End Device first),
  mesh-local and global addresses, SRP for DNS-SD instead of mDNS. This is the large part. The only
  pure-Go attempt known is experimental (hilli/gothread); an RCP or NCP setup with a host is an
  alternative for host devices.
- **Sleepy devices:** ICD Management cluster, slow MRP intervals, and polling behaviour in
  `exchange`.

### Smaller items

- More device types and clusters: Window Covering, Door Lock, Thermostat, Fan Control, Mode Select.
  Mode Select would also clear the remaining TestScenesFabricSceneInfo step.
- P-256 speed: hot fiat routines in IRAM, the ESP RSA/MPI accelerator, 240 MHz on the ESP32 (§14).

## 16. Third-party data and license

From [connectedhomeip](https://github.com/project-chip/connectedhomeip) (Apache-2.0, Project CHIP
Authors):

- the test vectors in `*/testdata/` and some tests;
- the test PAAs (`credentials/attestation/testpaa/`) and production PAAs
  (`credentials/attestation/prodpaa/`, mirrored from the DCL; see `SOURCE.md`);
- `internal/datamodel/controller-clusters.matter`.

Apache-2.0 (`LICENSE`). Code derived from the Go standard library is BSD (`NOTICE`, `crypto/internal/LICENSE-GO`).
Matter is a trademark of the CSA; this project is not affiliated with or certified by the CSA.
