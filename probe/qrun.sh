#!/bin/sh
# usage: qrun.sh <elf>  -- runs on mps2-an385 and decodes lm3s UART writes from qemu unimp log
timeout ${QTIMEOUT:-600} qemu-system-arm -machine mps2-an385 -semihosting -nographic -kernel "$1" -d unimp 2>&1 \
 | sed -n 's/.*offset 0xc000, value 0x\([0-9a-f]*\)).*/\1/p' | while read h; do printf "\\$(printf %o 0x$h)"; done
