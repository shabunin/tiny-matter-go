#!/bin/sh
# Generates a TinyGo target for QEMU's mps2-an385 board (Cortex-M3, 4 MB
# flash, 512 KB RAM), large enough to run the crypto probes. The generated
# files contain absolute paths and are not committed.
set -e
cd "$(dirname "$0")"
R=$(tinygo env TINYGOROOT)
cat > mps2.ld <<LD
MEMORY
{
    FLASH_TEXT (rw) : ORIGIN = 0x00000000, LENGTH = 4M
    RAM (xrw)       : ORIGIN = 0x20000000, LENGTH = 512K
}
_stack_size = 16K;
INCLUDE "$R/targets/arm.ld"
LD
cat > qemu-m3-big.json <<JSON
{
	"inherits": ["cortex-m3"],
	"build-tags": ["qemu", "lm3s6965"],
	"linkerscript": "$PWD/mps2.ld",
	"default-stack-size": 16384,
	"extra-files": ["targets/cortex-m-qemu.s"],
	"emulator": "qemu-system-arm -machine mps2-an385 -semihosting -nographic -kernel {}"
}
JSON
echo "wrote probe/mps2.ld and probe/qemu-m3-big.json"
