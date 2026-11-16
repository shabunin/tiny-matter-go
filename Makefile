PKGS := ./...  # this module only; firmware/ and probe/ are separate modules
QEMU_TARGET := probe/qemu-m3-big.json

.PHONY: test test32 tinygo-test fuzz cross bench-qemu all

all: test test32 tinygo-test cross

test:
	go vet $(PKGS)
	go test $(PKGS)

# 32-bit int: catches width assumptions that break on microcontrollers.
test32:
	GOARCH=386 go test $(PKGS)

tinygo-test:
	tinygo test ./tlv ./ota ./bdx ./crypto/p256 ./crypto/ccm ./crypto/spake2p ./message ./exchange ./securechannel ./securechannel/pase ./securechannel/casesession ./im ./credentials ./credentials/devcreds ./fabric ./device ./ip4 ./ip6 ./mdns ./storage ./onboarding ./thread

fuzz:
	go test ./tlv -run XXX -fuzz FuzzRoundTrip -fuzztime 60s
	go test ./message -run XXX -fuzz FuzzDecode -fuzztime 60s
	go test ./securechannel/pase -run XXX -fuzz FuzzDecode -fuzztime 60s
	go test ./im -run XXX -fuzz FuzzServer -fuzztime 60s -fuzzminimizetime 0s
	go test ./securechannel/casesession -run XXX -fuzz FuzzDecode -fuzztime 60s
	go test ./ip6 -run XXX -fuzz FuzzHandleFrame -fuzztime 60s
	go test ./ip4 -run XXX -fuzz FuzzHandleFrame -fuzztime 60s
	go test ./mdns -run XXX -fuzz FuzzHandlePacket -fuzztime 60s

# Cross-compile the P-256 benchmark for real boards and print flash/RAM use.
cross:
	@cd probe && for t in pico2-w pico-w xiao-ble esp32c3-generic esp32s3-generic; do \
		printf "%-16s " $$t; tinygo build -target=$$t -opt=z -size=short -o /dev/null ./p256bench | tail -1; done
	@echo "full device (on/off light):"
	@cd probe && for t in pico2-w pico-w esp32c3-generic; do \
		printf "%-16s " $$t; tinygo build -target=$$t -opt=z -size=short -o /dev/null ./devicesize | tail -1; done
	@echo "Wi-Fi light firmware:"
	@cd firmware && printf "%-16s " esp32s3-generic; tinygo build -target=esp32s3-generic -size=short -o /dev/null ./esp32s3-light | tail -1

# Instruction counts on an emulated Cortex-M3 (QEMU mps2-an385, -icount).
bench-qemu: probe/qemu-m3-big.json
	cd probe && tinygo build -target=qemu-m3-big.json -opt=2 -o p256bench.elf ./p256bench && ./qrun-icount.sh p256bench.elf

probe/qemu-m3-big.json:
	probe/setup-qemu.sh
