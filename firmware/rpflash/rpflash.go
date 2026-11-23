//go:build rp2350

// Package rpflash is the RP2350's flash as a storage.BlockDevice, at
// absolute offsets from the start of the flash.
//
// TinyGo's machine.Flash counts offsets from the end of the program image
// (machine.FlashDataStart), which is not aligned to the 4 KB erase sector
// in most builds, so its EraseBlocks hits unaligned addresses (the boot
// ROM erases nothing there) and the same store sits at different block
// numbers in different builds. Its WriteAt also programs whole 256-byte
// pages from an unaligned offset. Here erases are by sector and writes by
// whole page, both aligned, through the same RAM-resident functions
// TinyGo's machine package uses.
package rpflash

import (
	"errors"
	"machine"
	"runtime/interrupt"
	"unsafe"
)

const (
	xipBase    = 0x10000000
	sectorSize = 4096
	pageSize   = 256
)

// The functions in TinyGo's machine package (machine_rp2350_rom.go) that
// leave XIP, call the boot ROM and flush the cache. Offsets are from the
// start of the flash.
//
//export flash_erase_blocks
func flashEraseBlocks(offset uint32, count uintptr)

//export flash_range_write
func flashRangeWrite(offset uint32, data *byte, count uintptr)

var (
	errRange = errors.New("rpflash: outside the free flash")
	errAlign = errors.New("rpflash: erase not aligned to sectors")
)

// Device is the flash after the program image.
type Device struct {
	page [pageSize]byte
}

// free returns the bounds of the flash the program does not use, as
// offsets from the start of the flash.
func free() (start, end int64) {
	return int64(machine.FlashDataStart() - xipBase), int64(machine.FlashDataEnd() - xipBase)
}

// Size is the size of the flash: offsets go up to it.
func (d *Device) Size() int64 {
	_, end := free()
	return end
}

func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if _, end := free(); off < 0 || off+int64(len(p)) > end {
		return 0, errRange
	}
	copy(p, unsafe.Slice((*byte)(unsafe.Pointer(uintptr(xipBase+off))), len(p)))
	return len(p), nil
}

// WriteAt programs p at off, which must be erased. It programs whole pages,
// keeping what the page already holds around p.
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	if start, end := free(); off < start || off+int64(len(p)) > end {
		return 0, errRange
	}
	n := 0
	for n < len(p) {
		at := off + int64(n)
		base := at &^ (pageSize - 1)
		d.ReadAt(d.page[:], base)
		k := copy(d.page[at-base:], p[n:])
		state := interrupt.Disable()
		flashRangeWrite(uint32(base), &d.page[0], pageSize)
		interrupt.Restore(state)
		n += k
	}
	return n, nil
}

func (d *Device) EraseBlockSize() int64 { return sectorSize }

// EraseBlocks erases length sectors from sector start.
func (d *Device) EraseBlocks(start, length int64) error {
	off := start * sectorSize
	if s, end := free(); off < s || off+length*sectorSize > end {
		return errRange
	}
	if off%sectorSize != 0 {
		return errAlign
	}
	state := interrupt.Disable()
	flashEraseBlocks(uint32(off), uintptr(length*sectorSize))
	interrupt.Restore(state)
	return nil
}
