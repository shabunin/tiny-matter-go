// Command espslot prepares TinyGo ESP32-S3 firmware for the two-slot
// layout of esp32s3-loader (see its documentation):
//
//	espslot record -elf app.elf -bin app.bin -slot 0x10000 -seq 1 -o rec.bin
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
// checks that a built ESP32-S3 image (and optionally its boot loader) obeys
// every memory-map, symbol, size and checksum invariant that esp32s3-loader
// and espota require.
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

// Memory map and flash layout constants shared with esp32s3-loader and espota.
const (
	recA      = 0xE000
	slotSize  = 0x1F0000
	appDRAMLo = 0x3FC88000
	appDRAMHi = 0x3FCD8000
	appIRAMLo = 0x40378000
	appIRAMHi = 0x403C8000
	ldrDRAMLo = 0x3FCD8000
	ldrDRAMHi = 0x3FCE0000
	ldrIRAMLo = 0x403D0000
	ldrIRAMHi = 0x403D8000
	espMagic  = 0xE9
	espChipS3 = 9
	recMagic  = 0x42474D54 // "TMGB"
	payMagic  = 0x49474D54 // "TMGI"
)

// ImageReport summarises the layout and headroom of a verified ESP32-S3 image.
type ImageReport struct {
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

// LoaderReport summarises a verified esp32s3-loader ELF binary.
type LoaderReport struct {
	Entry     uint32
	TotalSize uint32
	DRAMSize  uint32
	IRAMSize  uint32
}

// Symbols returns the RAM addresses of the words holding the image's
// IROM and DROM flash offsets.
func symbols(path string) (irom, drom uint32, err error) {
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
	if irom == 0 || drom == 0 {
		return 0, 0, errors.New("espslot: _irom_flash_addr or _drom_flash_addr not found (not a TinyGo ESP32-S3 image?)")
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

// BuildPayload prefixes an ESP32-S3 image with the 16-byte TMGI header.
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

// VerifyImage checks that img and its _irom_flash_addr/_drom_flash_addr
// symbols satisfy every check performed by esp32s3-loader and espota.
func VerifyImage(img []byte, irom, drom uint32) (ImageReport, error) {
	if len(img) < 24 {
		return ImageReport{}, errors.New("espslot: image shorter than 24-byte ESP header")
	}
	if uint64(len(img)) > slotSize {
		return ImageReport{}, fmt.Errorf("espslot: image %d bytes exceeds slot limit %d bytes", len(img), slotSize)
	}
	le := binary.LittleEndian
	if img[0] != espMagic || le.Uint16(img[12:]) != espChipS3 {
		return ImageReport{}, errors.New("espslot: not an ESP32-S3 image")
	}
	nseg := uint32(img[1])
	entry := le.Uint32(img[4:])
	if nseg == 0 || nseg > 16 {
		return ImageReport{}, fmt.Errorf("espslot: invalid segment count %d", nseg)
	}
	off := uint32(24)
	sum := byte(0xEF)
	patched := 0
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
		case inRange(addr, segLen, appDRAMLo, appDRAMHi):
			if addr+segLen > maxDRAM {
				maxDRAM = addr + segLen
			}
			if irom >= addr && irom+4 <= addr+segLen {
				patched |= 1
			}
			if drom >= addr && drom+4 <= addr+segLen {
				patched |= 2
			}
		case inRange(addr, segLen, appIRAMLo, appIRAMHi):
			if addr+segLen > maxIRAM {
				maxIRAM = addr + segLen
			}
		default:
			return ImageReport{}, fmt.Errorf("espslot: segment %d (%#x+%#x) outside application SRAM (may overlap esp32s3-loader)", i, addr, segLen)
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
		return ImageReport{}, fmt.Errorf("espslot: _irom_flash_addr (%#x) or _drom_flash_addr (%#x) not inside any DRAM segment", irom, drom)
	}
	if !inRange(entry, 4, appIRAMLo, appIRAMHi) {
		return ImageReport{}, fmt.Errorf("espslot: entry point %#x outside application IRAM", entry)
	}
	rep := ImageReport{
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
		rep.DRAMHeadroom = appDRAMHi - maxDRAM
	}
	if maxIRAM > 0 {
		rep.IRAMHeadroom = appIRAMHi - maxIRAM
	}
	return rep, nil
}

// VerifyLoader checks that a built esp32s3-loader ELF uses loader_entry,
// stays strictly inside its reserved SRAM window above the application, and
// fits before REC_A (0xE000).
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
	var rep LoaderReport
	rep.Entry = uint32(f.Entry)
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || (p.Filesz == 0 && p.Memsz == 0) {
			continue
		}
		addr := uint32(p.Vaddr)
		memsz := uint32(p.Memsz)
		switch {
		case inRange(addr, memsz, ldrDRAMLo, ldrDRAMHi):
			rep.DRAMSize += memsz
		case inRange(addr, memsz, ldrIRAMLo, ldrIRAMHi):
			rep.IRAMSize += memsz
		default:
			return LoaderReport{}, fmt.Errorf("espslot: loader segment %#x+%#x outside reserved loader SRAM", addr, memsz)
		}
		rep.TotalSize += uint32(p.Filesz)
	}
	if rep.TotalSize == 0 {
		return LoaderReport{}, errors.New("espslot: loader has no loadable segments")
	}
	// Reserve room for the ESP image headers alongside loader segments before REC_A.
	if rep.TotalSize+256 >= recA {
		return LoaderReport{}, fmt.Errorf("espslot: loader payload %d bytes approaches REC_A (%#x)", rep.TotalSize, recA)
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
	fmt.Fprintln(os.Stderr, "usage: espslot record -elf app.elf -bin app.bin -slot 0x10000 -seq 1 [-confirmed] -o rec.bin\n"+
		"       espslot payload -elf app.elf -bin app.bin -o app.payload\n"+
		"       espslot verify -elf app.elf -bin app.bin [-loader-elf loader.elf]")
	os.Exit(2)
}

func recordCmd(args []string) {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	elfPath := fs.String("elf", "", "the image's ELF file")
	binPath := fs.String("bin", "", "the image")
	slot := fs.String("slot", "0x10000", "flash offset of the slot (64 KB aligned)")
	seq := fs.Uint("seq", 1, "record sequence number")
	confirmed := fs.Bool("confirmed", true, "mark the record tried and confirmed")
	out := fs.String("o", "", "output file")
	fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	irom, drom, err := symbols(*elfPath)
	if err != nil {
		fail(err)
	}
	img, err := os.ReadFile(*binPath)
	if err != nil {
		fail(err)
	}
	if _, err := VerifyImage(img, irom, drom); err != nil {
		fail(err)
	}
	base, err := parseUint(*slot)
	if err != nil || base&0xFFFF != 0 || base == 0 {
		fail(errors.New("espslot: the slot must be a non-zero multiple of 64 KB"))
	}
	rec := Record(uint32(*seq), base, uint32(len(img)), irom, drom)
	if *confirmed {
		clear(rec[0x100:0x108])
	}
	if err := os.WriteFile(*out, rec, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("record %d: slot %#x, %d bytes, _irom_flash_addr at %#x, _drom_flash_addr at %#x\n", *seq, base, len(img), irom, drom)
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
	irom, drom, err := symbols(*elfPath)
	if err != nil {
		fail(err)
	}
	img, err := os.ReadFile(*binPath)
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
	fmt.Printf("payload: %d byte image, _irom_flash_addr at %#x, _drom_flash_addr at %#x\n", len(img), irom, drom)
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	elfPath := fs.String("elf", "", "the image's ELF file")
	binPath := fs.String("bin", "", "the image")
	loaderElf := fs.String("loader-elf", "", "optional esp32s3-loader ELF file")
	fs.Parse(args)
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	irom, drom, err := symbols(*elfPath)
	if err != nil {
		fail(err)
	}
	img, err := os.ReadFile(*binPath)
	if err != nil {
		fail(err)
	}
	rep, err := VerifyImage(img, irom, drom)
	if err != nil {
		fail(err)
	}
	fmt.Printf("image ok: %d bytes (%d KB free in slot), %d segments, entry %#x\n",
		rep.Size, rep.SlotHeadroom/1024, rep.Segments, rep.Entry)
	fmt.Printf("  DRAM max %#x (%d KB headroom before loader), IRAM max %#x (%d KB headroom)\n",
		rep.MaxDRAM, rep.DRAMHeadroom/1024, rep.MaxIRAM, rep.IRAMHeadroom/1024)
	fmt.Printf("  _irom_flash_addr=%#x _drom_flash_addr=%#x\n", rep.IROMPtr, rep.DROMPtr)
	if *loaderElf != "" {
		lrep, err := VerifyLoader(*loaderElf)
		if err != nil {
			fail(err)
		}
		fmt.Printf("loader ok: entry %#x, %d bytes (%d B DRAM, %d B IRAM, %d KB before REC_A)\n",
			lrep.Entry, lrep.TotalSize, lrep.DRAMSize, lrep.IRAMSize, (recA-lrep.TotalSize)/1024)
	}
}
