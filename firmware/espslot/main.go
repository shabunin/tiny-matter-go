// Command espslot prepares TinyGo ESP32 and ESP32-S3 firmware for the
// two-slot layouts of esp32-loader and esp32s3-loader:
//
//	espslot record -elf app.elf -bin app.bin [-slot 0x10000|0x11000] -seq 1 -o rec.bin
//
// writes a boot record sector (4 KB) for the image app.bin, built from
// app.elf, placed at the slot's flash offset.
//
//	espslot payload -elf app.elf -bin app.bin -o app.payload
//
// writes the payload of an OTA update (see firmware/espota): the image with
// what its boot record needs. Wrap it with tmctl ota-image.
//
//	espslot verify -elf app.elf -bin app.bin [-loader-elf loader.elf]
//
// checks that a built ESP32 or ESP32-S3 image (and optionally its boot
// loader) obeys every memory-map, symbol, size and checksum invariant that
// the loader and espota require.
package main

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
)

// Common flash layout constants shared with esp32-loader, esp32s3-loader and espota.
const (
	recA     = 0xE000
	slotSize = 0x1F0000
	espMagic = 0xE9
	recMagic = 0x42474D54 // "TMGB"
	payMagic = 0x49474D54 // "TMGI"

	espChipESP32   = 0
	espChipESP32S3 = 9
)

type chipSpec struct {
	name        string
	chipID      uint16
	bootBase    uint32 // 0x0 on ESP32-S3, 0x1000 on classic ESP32
	defaultSlot uint32
	needIROM    bool
	appDRAMLo   uint32
	appDRAMHi   uint32
	appIRAMLo   uint32
	appIRAMHi   uint32
	ldrDRAMLo   uint32
	ldrDRAMHi   uint32
	ldrIRAMLo   uint32
	ldrIRAMHi   uint32
}

var (
	specESP32S3 = chipSpec{
		name: "esp32s3", chipID: espChipESP32S3, bootBase: 0, defaultSlot: 0x10000, needIROM: true,
		appDRAMLo: 0x3FC88000, appDRAMHi: 0x3FCD8000,
		appIRAMLo: 0x40378000, appIRAMHi: 0x403C8000,
		ldrDRAMLo: 0x3FCD8000, ldrDRAMHi: 0x3FCE0000,
		ldrIRAMLo: 0x403D0000, ldrIRAMHi: 0x403D8000,
	}
	specESP32 = chipSpec{
		name: "esp32", chipID: espChipESP32, bootBase: 0x1000, defaultSlot: 0x11000, needIROM: false,
		appDRAMLo: 0x3FFB0000, appDRAMHi: 0x3FFE0000,
		appIRAMLo: 0x40080000, appIRAMHi: 0x4009C000,
		ldrDRAMLo: 0x3FFF0000, ldrDRAMHi: 0x3FFF8000,
		ldrIRAMLo: 0x4009C000, ldrIRAMHi: 0x400A0000,
	}
)

func specForChip(chip uint16) (chipSpec, error) {
	switch chip {
	case espChipESP32S3:
		return specESP32S3, nil
	case espChipESP32:
		return specESP32, nil
	default:
		return chipSpec{}, fmt.Errorf("espslot: unsupported ESP chip ID %d (want 0=esp32 or 9=esp32s3)", chip)
	}
}

func detectChip(img []byte) (chipSpec, error) {
	if len(img) < 24 || img[0] != espMagic {
		return chipSpec{}, errors.New("espslot: not a valid ESP image")
	}
	return specForChip(binary.LittleEndian.Uint16(img[12:]))
}

// ImageReport summarises the layout and headroom of a verified ESP image.
type ImageReport struct {
	Chip         string
	Size         uint32
	Segments     uint32
	Entry        uint32
	IROMPtr      uint32
	DROMPtr      uint32
	MaxDRAM      uint32
	MaxIRAM      uint32
	DRAMHeadroom uint32
	IRAMHeadroom uint32
	SlotHeadroom uint32
}

// LoaderReport summarises a verified boot loader ELF binary.
type LoaderReport struct {
	Chip      string
	Entry     uint32
	TotalSize uint32
	DRAMSize  uint32
	IRAMSize  uint32
	MaxBefore uint32 // bytes available before REC_A
}

// symbols returns the RAM addresses of the words holding the image's IROM
// (ESP32-S3 only) and DROM flash offsets.
func symbols(path string, spec chipSpec) (irom, drom uint32, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return 0, 0, err
	}
	for _, s := range syms {
		switch s.Name {
		case "_irom_flash_addr":
			irom = uint32(s.Value)
		case "_drom_flash_addr":
			drom = uint32(s.Value)
		}
	}
	if drom == 0 || (spec.needIROM && irom == 0) {
		return 0, 0, fmt.Errorf("espslot: flash offset symbols not found in %s (irom=%#x drom=%#x)", path, irom, drom)
	}
	if !spec.needIROM {
		irom = 0
	}
	return irom, drom, nil
}

// Record returns a boot record sector.
func Record(seq, slot, length, irom, drom uint32) []byte {
	b := make([]byte, 4096)
	for i := range b {
		b[i] = 0xFF
	}
	le := binary.LittleEndian
	le.PutUint32(b[0:], recMagic)
	le.PutUint32(b[4:], seq)
	le.PutUint32(b[8:], slot)
	le.PutUint32(b[12:], length)
	le.PutUint32(b[16:], irom)
	le.PutUint32(b[20:], drom)
	le.PutUint32(b[24:], crc32.ChecksumIEEE(b[:24]))
	return b
}

// BuildPayload prefixes an ESP32 or ESP32-S3 image with the 16-byte TMGI header.
func BuildPayload(img []byte, irom, drom uint32) ([]byte, error) {
	if _, err := VerifyImage(img, irom, drom); err != nil {
		return nil, err
	}
	b := make([]byte, 16, 16+len(img))
	le := binary.LittleEndian
	le.PutUint32(b[0:], payMagic)
	le.PutUint32(b[4:], irom)
	le.PutUint32(b[8:], drom)
	le.PutUint32(b[12:], uint32(len(img)))
	return append(b, img...), nil
}

func inRange(addr, length, lo, hi uint32) bool {
	return addr >= lo && addr+length <= hi && addr+length >= addr
}

// VerifyImage checks that img and its flash-offset symbols satisfy every
// check performed by esp32-loader / esp32s3-loader and espota.
func VerifyImage(img []byte, irom, drom uint32) (ImageReport, error) {
	if len(img) < 24 {
		return ImageReport{}, errors.New("espslot: image shorter than 24-byte ESP header")
	}
	if uint64(len(img)) > slotSize {
		return ImageReport{}, fmt.Errorf("espslot: image %d bytes exceeds slot limit %d bytes", len(img), slotSize)
	}
	spec, err := detectChip(img)
	if err != nil {
		return ImageReport{}, err
	}
	le := binary.LittleEndian
	nseg := uint32(img[1])
	entry := le.Uint32(img[4:])
	if nseg == 0 || nseg > 16 {
		return ImageReport{}, fmt.Errorf("espslot: invalid segment count %d", nseg)
	}
	off := uint32(24)
	sum := byte(0xEF)
	patched := 0
	if !spec.needIROM {
		patched |= 1
	}
	var maxDRAM, maxIRAM uint32
	for i := uint32(0); i < nseg; i++ {
		if uint64(off)+8 > uint64(len(img)) {
			return ImageReport{}, fmt.Errorf("espslot: truncated header for segment %d", i)
		}
		addr := le.Uint32(img[off:])
		segLen := le.Uint32(img[off+4:])
		off += 8
		if addr&3 != 0 || segLen&3 != 0 {
			return ImageReport{}, fmt.Errorf("espslot: segment %d (%#x+%#x) is not 4-byte aligned", i, addr, segLen)
		}
		if uint64(off)+uint64(segLen) > uint64(len(img)) {
			return ImageReport{}, fmt.Errorf("espslot: truncated body for segment %d", i)
		}
		switch {
		case inRange(addr, segLen, spec.appDRAMLo, spec.appDRAMHi):
			if addr+segLen > maxDRAM {
				maxDRAM = addr + segLen
			}
			if spec.needIROM && irom >= addr && irom+4 <= addr+segLen {
				patched |= 1
			}
			if drom >= addr && drom+4 <= addr+segLen {
				patched |= 2
			}
		case inRange(addr, segLen, spec.appIRAMLo, spec.appIRAMHi):
			if addr+segLen > maxIRAM {
				maxIRAM = addr + segLen
			}
		default:
			return ImageReport{}, fmt.Errorf("espslot: %s segment %d (%#x+%#x) outside application SRAM (may overlap loader)", spec.name, i, addr, segLen)
		}
		for _, x := range img[off : off+segLen] {
			sum ^= x
		}
		off += segLen
	}
	end := off | 15
	if int(end) >= len(img) {
		return ImageReport{}, fmt.Errorf("espslot: missing checksum byte at %#x (image size %#x)", end, len(img))
	}
	if img[end] != sum {
		return ImageReport{}, fmt.Errorf("espslot: bad XOR checksum %#x, want %#x", img[end], sum)
	}
	if patched != 3 {
		return ImageReport{}, fmt.Errorf("espslot: flash offset words (irom=%#x drom=%#x) not inside any DRAM segment", irom, drom)
	}
	if !inRange(entry, 4, spec.appIRAMLo, spec.appIRAMHi) {
		return ImageReport{}, fmt.Errorf("espslot: entry point %#x outside %s application IRAM", entry, spec.name)
	}
	rep := ImageReport{
		Chip:         spec.name,
		Size:         uint32(len(img)),
		Segments:     nseg,
		Entry:        entry,
		IROMPtr:      irom,
		DROMPtr:      drom,
		MaxDRAM:      maxDRAM,
		MaxIRAM:      maxIRAM,
		SlotHeadroom: slotSize - uint32(len(img)),
	}
	if maxDRAM > 0 {
		rep.DRAMHeadroom = spec.appDRAMHi - maxDRAM
	}
	if maxIRAM > 0 {
		rep.IRAMHeadroom = spec.appIRAMHi - maxIRAM
	}
	return rep, nil
}

// VerifyLoader checks that a built esp32-loader or esp32s3-loader ELF uses
// loader_entry, stays strictly inside its reserved SRAM window, and fits
// before REC_A (0xE000).
func VerifyLoader(path string) (LoaderReport, error) {
	f, err := elf.Open(path)
	if err != nil {
		return LoaderReport{}, err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return LoaderReport{}, err
	}
	var entrySym uint64
	for _, s := range syms {
		if s.Name == "loader_entry" {
			entrySym = s.Value
			break
		}
	}
	if entrySym == 0 {
		return LoaderReport{}, errors.New("espslot: loader_entry symbol not found")
	}
	if f.Entry != entrySym {
		return LoaderReport{}, fmt.Errorf("espslot: loader ELF entry %#x != loader_entry %#x", f.Entry, entrySym)
	}
	entry := uint32(f.Entry)
	var spec chipSpec
	switch {
	case inRange(entry, 4, specESP32S3.ldrIRAMLo, specESP32S3.ldrIRAMHi):
		spec = specESP32S3
	case inRange(entry, 4, specESP32.ldrIRAMLo, specESP32.ldrIRAMHi):
		spec = specESP32
	default:
		return LoaderReport{}, fmt.Errorf("espslot: loader entry %#x outside reserved ESP32/ESP32-S3 loader IRAM", entry)
	}

	rep := LoaderReport{Chip: spec.name, Entry: entry, MaxBefore: recA - spec.bootBase}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || (p.Filesz == 0 && p.Memsz == 0) {
			continue
		}
		addr := uint32(p.Vaddr)
		memsz := uint32(p.Memsz)
		switch {
		case inRange(addr, memsz, spec.ldrDRAMLo, spec.ldrDRAMHi):
			rep.DRAMSize += memsz
		case inRange(addr, memsz, spec.ldrIRAMLo, spec.ldrIRAMHi):
			rep.IRAMSize += memsz
		default:
			return LoaderReport{}, fmt.Errorf("espslot: %s loader segment %#x+%#x outside reserved loader SRAM", spec.name, addr, memsz)
		}
		rep.TotalSize += uint32(p.Filesz)
	}
	if rep.TotalSize == 0 {
		return LoaderReport{}, errors.New("espslot: loader has no loadable segments")
	}
	if rep.TotalSize+256 >= rep.MaxBefore {
		return LoaderReport{}, fmt.Errorf("espslot: %s loader payload %d bytes approaches REC_A (%#x)", spec.name, rep.TotalSize, recA)
	}
	return rep, nil
}

func parseUint(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 0, 32)
	return uint32(v), err
}

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "payload":
			payload(os.Args[2:])
			return
		case "verify":
			verify(os.Args[2:])
			return
		case "record":
			recordCmd(os.Args[2:])
			return
		}
	}
	fmt.Fprintln(os.Stderr, "usage: espslot record -elf app.elf -bin app.bin [-slot 0x10000|0x11000] -seq 1 [-confirmed] -o rec.bin\n"+
		"       espslot payload -elf app.elf -bin app.bin -o app.payload\n"+
		"       espslot verify -elf app.elf -bin app.bin [-loader-elf loader.elf]")
	os.Exit(2)
}

func recordCmd(args []string) {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	elfPath := fs.String("elf", "", "the image's ELF file")
	binPath := fs.String("bin", "", "the image")
	slot := fs.String("slot", "", "flash offset of the slot (default 0x10000 on ESP32-S3, 0x11000 on ESP32)")
	seq := fs.Uint("seq", 1, "record sequence number")
	confirmed := fs.Bool("confirmed", true, "mark the record tried and confirmed")
	out := fs.String("o", "", "output file")
	fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	img, err := os.ReadFile(*binPath)
	if err != nil {
		fail(err)
	}
	spec, err := detectChip(img)
	if err != nil {
		fail(err)
	}
	irom, drom, err := symbols(*elfPath, spec)
	if err != nil {
		fail(err)
	}
	if _, err := VerifyImage(img, irom, drom); err != nil {
		fail(err)
	}
	base := spec.defaultSlot
	if *slot != "" {
		base, err = parseUint(*slot)
		if err != nil {
			fail(err)
		}
	}
	if base&0xFFFF != spec.bootBase || base < spec.defaultSlot {
		fail(fmt.Errorf("espslot: %s slot %#x must be >= %#x and aligned to 64 KB + %#x", spec.name, base, spec.defaultSlot, spec.bootBase))
	}
	rec := Record(uint32(*seq), base, uint32(len(img)), irom, drom)
	if *confirmed {
		clear(rec[0x100:0x108])
	}
	if err := os.WriteFile(*out, rec, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("record %d (%s): slot %#x, %d bytes, _irom_flash_addr at %#x, _drom_flash_addr at %#x\n", *seq, spec.name, base, len(img), irom, drom)
}

// payload writes an OTA payload: "TMGI", the two flash offset word
// addresses and the image length, then the image.
func payload(args []string) {
	fs := flag.NewFlagSet("payload", flag.ExitOnError)
	elfPath := fs.String("elf", "", "the image's ELF file")
	binPath := fs.String("bin", "", "the image")
	out := fs.String("o", "", "output file")
	fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	img, err := os.ReadFile(*binPath)
	if err != nil {
		fail(err)
	}
	spec, err := detectChip(img)
	if err != nil {
		fail(err)
	}
	irom, drom, err := symbols(*elfPath, spec)
	if err != nil {
		fail(err)
	}
	outBytes, err := BuildPayload(img, irom, drom)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, outBytes, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("payload (%s): %d byte image, _irom_flash_addr at %#x, _drom_flash_addr at %#x\n", spec.name, len(img), irom, drom)
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	elfPath := fs.String("elf", "", "the image's ELF file")
	binPath := fs.String("bin", "", "the image")
	loaderElf := fs.String("loader-elf", "", "optional boot loader ELF file")
	fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	img, err := os.ReadFile(*binPath)
	if err != nil {
		fail(err)
	}
	spec, err := detectChip(img)
	if err != nil {
		fail(err)
	}
	irom, drom, err := symbols(*elfPath, spec)
	if err != nil {
		fail(err)
	}
	rep, err := VerifyImage(img, irom, drom)
	if err != nil {
		fail(err)
	}
	fmt.Printf("image ok (%s): %d bytes (%d KB free in slot), %d segments, entry %#x\n",
		rep.Chip, rep.Size, rep.SlotHeadroom/1024, rep.Segments, rep.Entry)
	fmt.Printf("  DRAM max %#x (%d KB headroom), IRAM max %#x (%d KB headroom before loader)\n",
		rep.MaxDRAM, rep.DRAMHeadroom/1024, rep.MaxIRAM, rep.IRAMHeadroom/1024)
	fmt.Printf("  _irom_flash_addr=%#x _drom_flash_addr=%#x\n", rep.IROMPtr, rep.DROMPtr)
	if *loaderElf != "" {
		lrep, err := VerifyLoader(*loaderElf)
		if err != nil {
			fail(err)
		}
		if lrep.Chip != rep.Chip {
			fail(fmt.Errorf("espslot: loader chip %s does not match image chip %s", lrep.Chip, rep.Chip))
		}
		fmt.Printf("loader ok (%s): entry %#x, %d bytes (%d B DRAM, %d B IRAM, %d KB before REC_A)\n",
			lrep.Chip, lrep.Entry, lrep.TotalSize, lrep.DRAMSize, lrep.IRAMSize, (lrep.MaxBefore-lrep.TotalSize)/1024)
	}
}
