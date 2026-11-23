// Command rpslot prepares Raspberry Pi Pico 2 W firmware for the A/B
// partitions of firmware/rpota:
//
//	rpslot install -o install.uf2
//
// writes the one-time setup for the BOOTSEL drive: the partition table,
// with the first sectors of slot 1 and both partitions erased. It replaces
// whatever image is at the start of the flash; the device state, in the
// last 32 KB, stays. Copy it to the drive, then the firmware's UF2.
//
//	rpslot payload -elf app.elf -o app.payload
//
// writes the payload of an OTA update: the flash image of app.elf (tinygo
// build -o app.elf) flagged "try before you buy". Wrap it with tmctl
// ota-image. (TinyGo's .bin output for the RP2350 is a UF2 file.)
//
//	rpslot uf2 -elf app.elf -o app.uf2
//
// writes app.elf as a UF2 for the BOOTSEL drive once the partition table
// is installed: TinyGo's own UF2 lacks the RP2350-E10 workaround block, so
// the A2 chip's boot ROM ignores it.
package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"os"

	"firmware/rpota"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rpslot:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: rpslot install -o file.uf2 | payload|uf2 -elf app.elf -o file")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	out := fs.String("o", "", "output file")
	elfPath := fs.String("elf", "", "the firmware (tinygo build -o app.elf)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-o is required")
	}
	switch args[0] {
	case "install":
		return os.WriteFile(*out, rpota.InstallUF2(), 0o644)
	case "payload":
		img, err := flashImage(*elfPath)
		if err != nil {
			return err
		}
		if err := payload(img); err != nil {
			return err
		}
		return os.WriteFile(*out, img, 0o644)
	case "uf2":
		img, err := flashImage(*elfPath)
		if err != nil {
			return err
		}
		if size := rpota.Partitions[0].Size(); uint32(len(img)) > size {
			return fmt.Errorf("image of %d bytes does not fit a %d-byte partition", len(img), size)
		}
		return os.WriteFile(*out, rpota.FirmwareUF2(img), 0o644)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// flashImage lays out the ELF's loadable segments as they are stored in
// flash from 0x10000000 (their physical addresses: .data's initial values
// too), with gaps filled with 0xFF.
func flashImage(path string) ([]byte, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var img []byte
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Filesz == 0 {
			continue
		}
		if p.Paddr < rpota.XIPBase || p.Paddr+p.Filesz > rpota.XIPBase+rpota.FlashSize {
			return nil, fmt.Errorf("segment at %#x is not in flash", p.Paddr)
		}
		off := int(p.Paddr - rpota.XIPBase)
		for len(img) < off+int(p.Filesz) {
			img = append(img, 0xFF)
		}
		if _, err := p.ReadAt(img[off:off+int(p.Filesz)], 0); err != nil {
			return nil, err
		}
	}
	if len(img) == 0 {
		return nil, errors.New("no loadable segments in flash")
	}
	return img, nil
}

// payload checks that img fits a partition and flags it TBYB in place.
func payload(img []byte) error {
	if size := rpota.Partitions[0].Size(); uint32(len(img)) > size {
		return fmt.Errorf("image of %d bytes does not fit a %d-byte partition", len(img), size)
	}
	if len(img) < rpota.SectorSize {
		return errors.New("image shorter than a sector")
	}
	return rpota.SetTBYB(img)
}
