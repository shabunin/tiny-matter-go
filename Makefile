PKGS := ./...  # this module only; firmware/ and probe/ are separate modules
QEMU_TARGET := probe/qemu-m3-big.json
FUZZTIME ?= 60s

.PHONY: test test-race test32 test-firmware tinygo-test fuzz fuzz-smoke cross build-firmware verify-esp32s3-ota verify-esp32-ota bench-qemu all

all: test test-race test32 test-firmware tinygo-test cross build-firmware verify-esp32s3-ota verify-esp32-ota

test:
	go vet $(PKGS)
	go test $(PKGS)

test-race:
	go test -race -count=1 $(PKGS)

# 32-bit int: catches width assumptions that break on microcontrollers.
test32:
	GOARCH=386 go test $(PKGS)

# Host-runnable tests in the firmware module (sensors, BLE HCI, ESP32-S3 OTA slot/loader simulation).
test-firmware:
	cd firmware && go vet ./envsensor ./matterble ./espslot ./espota
	cd firmware && go test -race -count=1 ./envsensor ./matterble ./espslot ./espota

tinygo-test:
	tinygo test ./tlv ./ota ./bdx ./crypto/internal/nistec/fiat ./crypto/p256 ./crypto/ccm ./crypto/spake2p ./message ./exchange ./securechannel ./securechannel/pase ./securechannel/casesession ./im ./credentials ./credentials/devcreds ./fabric ./device ./ip4 ./ip6 ./mdns ./storage ./onboarding ./thread

fuzz:
	go test ./tlv -run '^$$' -fuzz FuzzRoundTrip -fuzztime $(FUZZTIME)
	go test ./message -run '^$$' -fuzz FuzzDecode -fuzztime $(FUZZTIME)
	go test ./securechannel/pase -run '^$$' -fuzz FuzzDecode -fuzztime $(FUZZTIME)
	go test ./im -run '^$$' -fuzz FuzzServer -fuzztime $(FUZZTIME) -fuzzminimizetime 0s
	go test ./securechannel/casesession -run '^$$' -fuzz FuzzDecode -fuzztime $(FUZZTIME)
	go test ./ip6 -run '^$$' -fuzz FuzzHandleFrame -fuzztime $(FUZZTIME)
	go test ./ip4 -run '^$$' -fuzz FuzzHandleFrame -fuzztime $(FUZZTIME)
	go test ./mdns -run '^$$' -fuzz FuzzHandlePacket -fuzztime $(FUZZTIME)

fuzz-smoke:
	$(MAKE) fuzz FUZZTIME=5s

# Cross-compile the P-256 benchmark for real boards and print flash/RAM use.
cross:
	@cd probe && for t in pico2-w pico-w xiao-ble esp32c3-generic esp32s3-generic; do \
		printf "%-16s " $$t; tinygo build -target=$$t -opt=z -size=short -o /dev/null ./p256bench | tail -1; done
	@echo "full device (on/off light):"
	@cd probe && for t in pico2-w pico-w esp32c3-generic; do \
		printf "%-16s " $$t; tinygo build -target=$$t -opt=z -size=short -o /dev/null ./devicesize | tail -1; done
	@echo "Wi-Fi light firmware:"
	@cd firmware && printf "%-16s " esp32s3-generic; tinygo build -target=esp32s3-generic -size=short -o /dev/null ./esp32s3-light | tail -1

# Build all real MCU firmware images to catch TinyGo/target regressions.
build-firmware:
	cd firmware && tinygo build -target ./esp32s3-loader/target.json -o /dev/null ./esp32s3-loader
	cd firmware && tinygo build -target esp32s3-generic -stack-size=12KB -o /dev/null ./esp32s3-light
	cd firmware && tinygo build -target ./esp32-loader/target.json -o /dev/null ./esp32-loader
	cd firmware && tinygo build -target m5stack -stack-size=10KB -o /dev/null ./esp32-node
	cd firmware && tinygo build -target m5stick-c -stack-size=10KB -o /dev/null ./esp32-node
	cd firmware && tinygo build -target pico2-w -stack-size=16KB -o /dev/null ./pico2w-light

# Build the real ESP32-S3 loader and firmware, statically verify all memory-map,
# symbol, checksum and headroom invariants, package a real Matter .ota file, and
# simulate flashing, booting, rollback and slot ping-pong on NOR flash.
verify-esp32s3-ota:
	@set -eu; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	(cd firmware && tinygo build -target ./esp32s3-loader/target.json -o "$$tmp/loader.elf" ./esp32s3-loader); \
	(cd firmware && tinygo build -target esp32s3-generic -stack-size=12KB -o "$$tmp/app.elf" ./esp32s3-light); \
	(cd firmware && tinygo build -target esp32s3-generic -stack-size=12KB -o "$$tmp/app.bin" ./esp32s3-light); \
	(cd firmware && go run ./espslot verify -elf "$$tmp/app.elf" -bin "$$tmp/app.bin" -loader-elf "$$tmp/loader.elf"); \
	(cd firmware && go run ./espslot record -elf "$$tmp/app.elf" -bin "$$tmp/app.bin" -slot 0x10000 -seq 1 -o "$$tmp/rec.bin"); \
	(cd firmware && go run ./espslot payload -elf "$$tmp/app.elf" -bin "$$tmp/app.bin" -o "$$tmp/app.payload"); \
	go run ./cmd/tmctl ota-image "$$tmp/app.payload" "$$tmp/app-2.ota" -vendor 0xFFF1 -product 0x8000 -version 2; \
	go run ./cmd/tmctl ota-info "$$tmp/app-2.ota"; \
	(cd firmware && TMG_ESP32S3_ELF="$$tmp/app.elf" TMG_ESP32S3_BIN="$$tmp/app.bin" TMG_ESP32S3_LOADER_ELF="$$tmp/loader.elf" \
		go test -race -v -run 'TestVerifyRealArtifacts|TestRealFirmwareArtifactsOTA' ./espslot ./espota)

# Build the real classic ESP32 loader and both M5Stack targets (m5stack and
# m5stick-c), verify memory-map/symbol/checksum invariants, package Matter
# .ota images, and simulate flashing, booting, rollback and slot ping-pong.
verify-esp32-ota:
	@set -eu; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	(cd firmware && tinygo build -target ./esp32-loader/target.json -o "$$tmp/loader.elf" ./esp32-loader); \
	for board in m5stack m5stick-c; do \
		echo "=== verifying $$board OTA ==="; \
		(cd firmware && tinygo build -target "$$board" -stack-size=10KB -o "$$tmp/$$board.elf" ./esp32-node); \
		(cd firmware && tinygo build -target "$$board" -stack-size=10KB -o "$$tmp/$$board.bin" ./esp32-node); \
		(cd firmware && go run ./espslot verify -elf "$$tmp/$$board.elf" -bin "$$tmp/$$board.bin" -loader-elf "$$tmp/loader.elf"); \
		(cd firmware && go run ./espslot record -elf "$$tmp/$$board.elf" -bin "$$tmp/$$board.bin" -seq 1 -o "$$tmp/$$board.rec"); \
		(cd firmware && go run ./espslot payload -elf "$$tmp/$$board.elf" -bin "$$tmp/$$board.bin" -o "$$tmp/$$board.payload"); \
		go run ./cmd/tmctl ota-image "$$tmp/$$board.payload" "$$tmp/$$board-2.ota" -vendor 0xFFF1 -product 0x8000 -version 2; \
		go run ./cmd/tmctl ota-info "$$tmp/$$board-2.ota"; \
		(cd firmware && TMG_ESP32_ELF="$$tmp/$$board.elf" TMG_ESP32_BIN="$$tmp/$$board.bin" TMG_ESP32_LOADER_ELF="$$tmp/loader.elf" \
			go test -race -v -run 'TestVerifyRealArtifacts|TestRealESP32FirmwareArtifactsOTA' ./espslot ./espota); \
	done

# Instruction counts on an emulated Cortex-M3 (QEMU mps2-an385, -icount).
bench-qemu: probe/qemu-m3-big.json
	cd probe && tinygo build -target=qemu-m3-big.json -opt=2 -o p256bench.elf ./p256bench && ./qrun-icount.sh p256bench.elf

probe/qemu-m3-big.json:
	probe/setup-qemu.sh
