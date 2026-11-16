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
	le.PutUint32(b[0:], 0x42474D54) // "TMGB"
	le.PutUint32(b[4:], seq)
	le.PutUint32(b[8:], slot)
	le.PutUint32(b[12:], length)
	le.PutUint32(b[16:], irom)
	le.PutUint32(b[20:], drom)
	le.PutUint32(b[24:], crc32.ChecksumIEEE(b[:24]))
	return b
}

func parseUint(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 0, 32)
	return uint32(v), err
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "payload" {
		payload(os.Args[2:])
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "record" {
		fmt.Fprintln(os.Stderr, "usage: espslot record -elf app.elf -bin app.bin -slot 0x10000 -seq 1 [-confirmed] -o rec.bin\n"+
			"       espslot payload -elf app.elf -bin app.bin -o app.payload")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	elfPath := fs.String("elf", "", "the image's ELF file")
	binPath := fs.String("bin", "", "the image")
	slot := fs.String("slot", "0x10000", "flash offset of the slot (64 KB aligned)")
	seq := fs.Uint("seq", 1, "record sequence number")
	confirmed := fs.Bool("confirmed", true, "mark the record tried and confirmed")
	out := fs.String("o", "", "output file")
	fs.Parse(os.Args[2:])
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	irom, drom, err := symbols(*elfPath)
	if err != nil {
		fail(err)
	}
	st, err := os.Stat(*binPath)
	if err != nil {
		fail(err)
	}
	base, err := parseUint(*slot)
	if err != nil || base&0xFFFF != 0 || base == 0 {
		fail(errors.New("espslot: the slot must be a non-zero multiple of 64 KB"))
	}
	rec := Record(uint32(*seq), base, uint32(st.Size()), irom, drom)
	if *confirmed {
		clear(rec[0x100:0x108])
	}
	if err := os.WriteFile(*out, rec, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("record %d: slot %#x, %d bytes, _irom_flash_addr at %#x, _drom_flash_addr at %#x\n", *seq, base, st.Size(), irom, drom)
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
	if len(img) < 24 || img[0] != 0xE9 || binary.LittleEndian.Uint16(img[12:]) != 9 {
		fail(errors.New("espslot: not an ESP32-S3 image"))
	}
	b := make([]byte, 16, 16+len(img))
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0x49474D54) // "TMGI"
	le.PutUint32(b[4:], irom)
	le.PutUint32(b[8:], drom)
	le.PutUint32(b[12:], uint32(len(img)))
	if err := os.WriteFile(*out, append(b, img...), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("payload: %d byte image, _irom_flash_addr at %#x, _drom_flash_addr at %#x\n", len(img), irom, drom)
}
