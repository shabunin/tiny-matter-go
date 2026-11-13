PKGS := ./tlv/... ./crypto/... ./message/... ./exchange/...
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
	tinygo test ./tlv ./crypto/p256 ./crypto/ccm ./crypto/spake2p ./message ./exchange ./securechannel ./securechannel/pase ./im

fuzz:
	go test ./tlv -run XXX -fuzz FuzzRoundTrip -fuzztime 60s
	go test ./message -run XXX -fuzz FuzzDecode -fuzztime 60s
	go test ./securechannel/pase -run XXX -fuzz FuzzDecode -fuzztime 60s
	go test ./im -run XXX -fuzz FuzzServer -fuzztime 60s -fuzzminimizetime 0s

# Cross-compile the P-256 benchmark for real boards and print flash/RAM use.
cross:
	@cd probe && for t in pico2-w pico-w xiao-ble esp32c3-generic esp32s3-generic; do \
		printf "%-16s " $$t; tinygo build -target=$$t -opt=z -size=short -o /dev/null ./p256bench | tail -1; done

# Instruction counts on an emulated Cortex-M3 (QEMU mps2-an385, -icount).
bench-qemu: probe/qemu-m3-big.json
	cd probe && tinygo build -target=qemu-m3-big.json -opt=2 -o p256bench.elf ./p256bench && ./qrun-icount.sh p256bench.elf

probe/qemu-m3-big.json:
	probe/setup-qemu.sh
