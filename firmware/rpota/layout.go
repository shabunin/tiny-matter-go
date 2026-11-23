// Package rpota stores OTA software updates for the Raspberry Pi Pico 2 W in
// the RP2350 boot ROM's A/B partitions (RP2350 datasheet 5.1.7, 5.1.16 and
// 5.1.17).
//
// The flash holds a partition table in its first sector, partitions A and B
// for the firmware, and the device state in its last 32 KB, outside both.
// The boot ROM maps the partition it boots at 0x10000000, so one image runs
// from either. An update is written to the other partition with its
// IMAGE_DEF flagged "try before you buy" (TBYB), and started by a
// FLASH_UPDATE reboot: the ROM boots such an image only then, so if it hangs
// or resets before it confirms itself (explicit_buy), the next boot starts
// the previous image. Confirming erases the first sector of the other
// partition, which leaves the new image the only one.
//
// A UF2 dropped on the BOOTSEL drive goes to the partition not running and
// takes over the same way, without a trial.
//
// This file is the layout and the image format, shared with the rpslot host
// tool.
package rpota

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	// SectorSize is the flash erase sector, the partitions' unit.
	SectorSize = 4096
	// FlashSize is the Pico 2 W's flash.
	FlashSize = 4 << 20
	// StateStart is where the device state starts: the last 32 KB, which
	// no partition covers.
	StateStart = FlashSize - 32<<10

	// XIPBase is where the boot ROM maps the running partition, and the
	// base of flash addresses in UF2 files and reboot parameters.
	XIPBase = 0x10000000
)

// Partition is a range of flash sectors, both ends included.
type Partition struct{ First, Last uint32 }

// Start is the partition's offset in the flash.
func (p Partition) Start() uint32 { return p.First * SectorSize }

// Size is the partition's size in bytes.
func (p Partition) Size() uint32 { return (p.Last - p.First + 1) * SectorSize }

// Partitions are A and B. Sector 0 holds the partition table and sector 1
// (the boot ROM's slot 1) stays unused; the state follows B.
var Partitions = [2]Partition{
	{First: 2, Last: 508},
	{First: 509, Last: StateStart/SectorSize - 1},
}

// Block markers and items (datasheet 5.9; pico-sdk boot/picobin.h).
const (
	blockStart = 0xffffded3
	blockEnd   = 0xab123579

	itemImageType      = 0x42
	itemPartitionTable = 0x0a
	itemLast           = 0xff

	imageTypeBits = 0x000f
	imageTypeEXE  = 0x0001
	chipBits      = 0x7000
	chipRP2350    = 0x1000
	cpuBits       = 0x0700 // 0: Arm
	tbybFlag      = 0x8000

	// Partition permissions (all: secure, non-secure and boot loader, read
	// and write) and flags.
	permAll              = 0xfc000000
	flagLinkAPartition   = 1 << 1 // a B partition; its A is in the link value
	flagNotBootableRISCV = 0x00000400
	flagAcceptsAbsolute  = 0x00008000
	flagAcceptsArmS      = 0x00020000

	// UF2 family IDs.
	FamilyAbsolute = 0xe48bff57
	FamilyArmS     = 0xe48bff59
)

// PartitionTable returns the block to write at the start of the flash.
func PartitionTable() []byte {
	loc := func(p Partition) uint32 { return permAll | p.First | p.Last<<13 }
	items := []uint32{
		// The table: singleton (slot 1 is not searched), two partitions.
		itemPartitionTable | 6<<8 | 2<<24 | 1<<31,
		permAll | flagAcceptsAbsolute, // unpartitioned space
		loc(Partitions[0]), permAll | flagAcceptsArmS | flagNotBootableRISCV,
		loc(Partitions[1]), permAll | flagAcceptsArmS | flagNotBootableRISCV | flagLinkAPartition, // A is 0
	}
	words := []uint32{blockStart}
	words = append(words, items...)
	// The last item gives the items' size; the next word links the block
	// to itself, a loop of one.
	words = append(words, itemLast|uint32(len(items))<<8, 0, blockEnd)
	b := make([]byte, 4*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

var (
	errNoImageDef = errors.New("rpota: no RP2350 Arm executable IMAGE_DEF in the first 4 KB")
	errBlockLoop  = errors.New("rpota: the IMAGE_DEF's block loop is not one block")
)

// imageType finds the image's IMAGE_DEF: a block within the first 4 KB
// whose first item is an IMAGE_TYPE for an RP2350 Arm executable. It
// returns the offset of that item. TinyGo writes a loop of a single block
// (targets/rp2350_embedded_block.s); a longer loop, whose last IMAGE_DEF
// would count, is refused.
func imageType(img []byte) (int, error) {
	le := binary.LittleEndian
	end := min(len(img), SectorSize)
	for off := 0; off+20 <= end; off += 4 {
		if le.Uint32(img[off:]) != blockStart {
			continue
		}
		item := le.Uint32(img[off+4:])
		if item&0xff != itemImageType || item>>8&0xff != 1 {
			continue
		}
		flags := item >> 16
		if flags&imageTypeBits != imageTypeEXE || flags&chipBits != chipRP2350 || flags&cpuBits != 0 {
			continue
		}
		// Walk to the last item: its link must be 0 (to this block).
		p := off + 4
		for p+12 <= len(img) {
			h := le.Uint32(img[p:])
			if h&0xff == itemLast {
				if le.Uint32(img[p+4:]) != 0 || le.Uint32(img[p+8:]) != blockEnd {
					return 0, errBlockLoop
				}
				return off + 4, nil
			}
			size := int(h >> 8 & 0xff)
			if h&0x80 != 0 {
				size = int(h >> 8 & 0xffff)
			}
			if size == 0 {
				break
			}
			p += 4 * size
		}
		return 0, errBlockLoop
	}
	return 0, errNoImageDef
}

// SetTBYB flags an image "try before you buy" in place, for an update: the
// boot ROM then starts it only from the FLASH_UPDATE reboot that applies it,
// until it confirms itself.
func SetTBYB(img []byte) error {
	at, err := imageType(img)
	if err != nil {
		return err
	}
	le := binary.LittleEndian
	le.PutUint32(img[at:], le.Uint32(img[at:])|tbybFlag<<16)
	return nil
}

// CheckUpdate checks the start of an update payload: an image whose
// IMAGE_DEF is flagged TBYB.
func CheckUpdate(first []byte) error {
	at, err := imageType(first)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(first[at:])>>16&tbybFlag == 0 {
		return errors.New("rpota: the image is not flagged TBYB (use rpslot payload)")
	}
	return nil
}

// UF2 encodes regions of flash, each at a flash offset, as a UF2 file
// for the BOOTSEL drive.
func UF2(family uint32, regions ...Region) []byte {
	const payload = 256
	type block struct {
		addr uint32
		data []byte
	}
	var blocks []block
	for _, r := range regions {
		for off := 0; off < len(r.Data); off += payload {
			chunk := make([]byte, payload)
			n := copy(chunk, r.Data[off:])
			for i := n; i < payload; i++ {
				chunk[i] = 0xFF
			}
			blocks = append(blocks, block{XIPBase + r.Offset + uint32(off), chunk})
		}
	}
	le := binary.LittleEndian
	out := make([]byte, 512*len(blocks))
	for i, bl := range blocks {
		b := out[512*i:]
		le.PutUint32(b[0:], 0x0A324655)
		le.PutUint32(b[4:], 0x9E5D5157)
		le.PutUint32(b[8:], 0x00002000) // family ID present
		le.PutUint32(b[12:], bl.addr)
		le.PutUint32(b[16:], payload)
		le.PutUint32(b[20:], uint32(i))
		le.PutUint32(b[24:], uint32(len(blocks)))
		le.PutUint32(b[28:], family)
		copy(b[32:], bl.data)
		le.PutUint32(b[508:], 0x0AB16F30)
	}
	return out
}

// FirmwareUF2 encodes a flash image (as built, from 0x10000000) for the
// BOOTSEL drive, which writes it to the partition not running.
//
// It starts with the workaround for erratum RP2350-E10 (datasheet D.2.1):
// on A2 chips the boot ROM ignores a UF2 for a partition unless a block of
// the absolute family comes first, which sets up the flash. That block is
// written, so it targets slot 1, which nothing uses (picotool's default, the
// end of 16 MB, is the end of this 4 MB flash: the state). Later ROMs skip
// it by its extension tag.
func FirmwareUF2(img []byte) []byte {
	const flagExtensions, rp2IgnoreBlock = 0x8000, 0x9957e304
	e10 := UF2(FamilyAbsolute, Region{SectorSize, bytes.Repeat([]byte{0xef}, 256)})
	le := binary.LittleEndian
	le.PutUint32(e10[8:], le.Uint32(e10[8:])|flagExtensions)
	le.PutUint32(e10[24:], 2) // number of blocks, as picotool writes it
	le.PutUint32(e10[32+256:], rp2IgnoreBlock)
	return append(e10, UF2(FamilyArmS, Region{0, img})...)
}

// Region is data for a flash offset.
type Region struct {
	Offset uint32
	Data   []byte
}

// InstallUF2 is the one-time setup for the BOOTSEL drive: the partition
// table, with the first sectors of slot 1 and both partitions erased, so
// that no stale image or table there counts. The firmware UF2 then goes to
// a partition.
func InstallUF2() []byte {
	blank := make([]byte, SectorSize)
	for i := range blank {
		blank[i] = 0xFF
	}
	table := append(PartitionTable(), blank[len(PartitionTable()):]...)
	return UF2(FamilyAbsolute,
		Region{0, table},
		Region{SectorSize, blank},
		Region{Partitions[0].Start(), blank},
		Region{Partitions[1].Start(), blank},
	)
}
