//go:build rp2350

// Package rpflash is a range of the RP2350's flash as a storage.BlockDevice,
// at offsets from the start of the flash.
//
// TinyGo's machine.Flash counts offsets from the end of the program image
// (machine.FlashDataStart), which is not aligned to the 4 KB erase sector
// in most builds, so its EraseBlocks hits unaligned addresses and the same
// store sits at different block numbers in different builds; and once the
// boot ROM runs the image from a partition, 0x10000000 is that partition,
// not the flash. Here offsets are physical: reads go through the XIP
// window that bypasses address translation (and the cache), erases are by
// sector and writes by whole page, both aligned, through the RAM-resident
// functions TinyGo's machine package uses.
package rpflash

import (
	"errors"
	"runtime/interrupt"
	"unsafe"
)

const (
	// noTranslate is the uncached XIP window onto the flash as stored.
	noTranslate = 0x1c000000
	sectorSize  = 4096
	pageSize    = 256
)

// The functions in TinyGo's machine package (machine_rp2350_rom.go) that
// leave XIP, call the boot ROM and flush the cache. Offsets are from the
// start of the flash.
//
//export flash_erase_blocks
func flashEraseBlocks(offset uint32, count uintptr)

//export flash_range_write
func flashRangeWrite(offset uint32, data *byte, count uintptr)

var errRange = errors.New("rpflash: outside the device's range")

// Device is the flash from Start to End (bytes from the start of the flash,
// both sector-aligned). It refuses to touch anything outside.
type Device struct {
	Start, End int64
	page       [pageSize]byte
}

func (d *Device) in(off, n int64) bool { return off >= d.Start && off+n <= d.End }

// Size is where the device ends: offsets go up to it.
func (d *Device) Size() int64 { return d.End }

func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if !d.in(off, int64(len(p))) {
		return 0, errRange
	}
	copy(p, unsafe.Slice((*byte)(unsafe.Pointer(uintptr(noTranslate+off))), len(p)))
	return len(p), nil
}

// WriteAt programs p at off, which must be erased. It programs whole pages,
// keeping what the page already holds around p.
func (d *Device) WriteAt(p []byte, off int64) (int, error) {
	if !d.in(off, int64(len(p))) {
		return 0, errRange
	}
	n := 0
	for n < len(p) {
		at := off + int64(n)
		base := at &^ (pageSize - 1)
		copy(d.page[:], unsafe.Slice((*byte)(unsafe.Pointer(uintptr(noTranslate+base))), pageSize))
		k := copy(d.page[at-base:], p[n:])
		state := interrupt.Disable()
		flashRangeWrite(uint32(base), &d.page[0], pageSize)
		interrupt.Restore(state)
		n += k
	}
	return n, nil
}

func (d *Device) EraseBlockSize() int64 { return sectorSize }

// EraseBlocks erases length sectors from sector start (counted from the
// start of the flash).
func (d *Device) EraseBlocks(start, length int64) error {
	off := start * sectorSize
	if !d.in(off, length*sectorSize) {
		return errRange
	}
	state := interrupt.Disable()
	flashEraseBlocks(uint32(off), uintptr(length*sectorSize))
	interrupt.Restore(state)
	return nil
}
