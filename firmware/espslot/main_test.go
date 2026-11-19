package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"testing"
)

func syntheticImage(spec chipSpec) (img []byte, irom, drom uint32) {
	dramAddr := spec.appDRAMLo + 0x200
	dram := make([]byte, 64)
	if spec.needIROM {
		irom = dramAddr + 9
		drom = dramAddr + 13
		binary.LittleEndian.PutUint32(dram[irom-dramAddr:], 0x10000)
	} else {
		irom = 0
		drom = dramAddr + 12
	}
	binary.LittleEndian.PutUint32(dram[drom-dramAddr:], 0x20000)

	iramAddr := spec.appIRAMLo + 0x400
	iram := make([]byte, 128)
	for i := range iram {
		iram[i] = byte(i * 7)
	}

	var b bytes.Buffer
	var hdr [24]byte
	hdr[0] = espMagic
	hdr[1] = 2
	binary.LittleEndian.PutUint32(hdr[4:], iramAddr)
	binary.LittleEndian.PutUint16(hdr[12:], spec.chipID)
	b.Write(hdr[:])

	writeSeg := func(addr uint32, data []byte) {
		var sh [8]byte
		binary.LittleEndian.PutUint32(sh[0:], addr)
		binary.LittleEndian.PutUint32(sh[4:], uint32(len(data)))
		b.Write(sh[:])
		b.Write(data)
	}
	writeSeg(dramAddr, dram)
	writeSeg(iramAddr, iram)

	sum := byte(0xEF)
	for _, x := range dram {
		sum ^= x
	}
	for _, x := range iram {
		sum ^= x
	}
	end := b.Len() | 15
	for b.Len() < end {
		b.WriteByte(0)
	}
	b.WriteByte(sum)
	return b.Bytes(), irom, drom
}

func TestRecordFormat(t *testing.T) {
	rec := Record(7, 0x10000, 123456, 0x3fc95f89, 0x3fc95f8d)
	if len(rec) != 4096 {
		t.Fatalf("len = %d, want 4096", len(rec))
	}
	le := binary.LittleEndian
	if le.Uint32(rec[0:]) != recMagic || le.Uint32(rec[4:]) != 7 ||
		le.Uint32(rec[8:]) != 0x10000 || le.Uint32(rec[12:]) != 123456 ||
		le.Uint32(rec[16:]) != 0x3fc95f89 || le.Uint32(rec[20:]) != 0x3fc95f8d {
		t.Fatalf("record header mismatch: %x", rec[:28])
	}
	if got, want := le.Uint32(rec[24:]), crc32.ChecksumIEEE(rec[:24]); got != want {
		t.Fatalf("record CRC = %#x, want %#x", got, want)
	}
	for i := 28; i < len(rec); i++ {
		if rec[i] != 0xFF {
			t.Fatalf("byte %d = %#x, want 0xFF", i, rec[i])
		}
	}
}

func TestBuildPayloadAndVerifyImage(t *testing.T) {
	for _, spec := range []chipSpec{specESP32S3, specESP32} {
		t.Run(spec.name, func(t *testing.T) {
			img, irom, drom := syntheticImage(spec)
			rep, err := VerifyImage(img, irom, drom)
			if err != nil {
				t.Fatalf("VerifyImage: %v", err)
			}
			if rep.Chip != spec.name || rep.Size != uint32(len(img)) || rep.Segments != 2 || rep.DRAMHeadroom == 0 || rep.IRAMHeadroom == 0 {
				t.Fatalf("unexpected report: %+v", rep)
			}
			p, err := BuildPayload(img, irom, drom)
			if err != nil {
				t.Fatalf("BuildPayload: %v", err)
			}
			le := binary.LittleEndian
			if le.Uint32(p[0:]) != payMagic || le.Uint32(p[4:]) != irom ||
				le.Uint32(p[8:]) != drom || le.Uint32(p[12:]) != uint32(len(img)) {
				t.Fatalf("bad TMGI header: %x", p[:16])
			}
			if !bytes.Equal(p[16:], img) {
				t.Fatal("payload image body mismatch")
			}
		})
	}
}

func TestVerifyImageRejectsInvalid(t *testing.T) {
	for _, spec := range []chipSpec{specESP32S3, specESP32} {
		t.Run(spec.name, func(t *testing.T) {
			baseImg, baseIROM, baseDROM := syntheticImage(spec)
			cases := []struct {
				name   string
				mutate func([]byte, *uint32, *uint32) []byte
			}{
				{"too short", func(b []byte, _, _ *uint32) []byte { return b[:10] }},
				{"wrong magic", func(b []byte, _, _ *uint32) []byte { b[0] = 0x00; return b }},
				{"unsupported chip id", func(b []byte, _, _ *uint32) []byte { binary.LittleEndian.PutUint16(b[12:], 5); return b }},
				{"zero segments", func(b []byte, _, _ *uint32) []byte { b[1] = 0; return b }},
				{"bad XOR checksum", func(b []byte, _, _ *uint32) []byte { b[len(b)-1] ^= 0x80; return b }},
				{"segment overlaps loader SRAM", func(b []byte, _, _ *uint32) []byte {
					binary.LittleEndian.PutUint32(b[24:], spec.appDRAMHi-4)
					return b
				}},
				{"unaligned segment address", func(b []byte, _, _ *uint32) []byte {
					binary.LittleEndian.PutUint32(b[24:], spec.appDRAMLo+1)
					return b
				}},
				{"drom outside DRAM", func(b []byte, _, drom *uint32) []byte {
					*drom = spec.appDRAMHi - 8
					return b
				}},
				{"entry outside IRAM", func(b []byte, _, _ *uint32) []byte {
					binary.LittleEndian.PutUint32(b[4:], spec.ldrIRAMLo)
					return b
				}},
				{"exceeds slot size", func(b []byte, _, _ *uint32) []byte {
					big := make([]byte, slotSize+1)
					copy(big, b)
					return big
				}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					img := bytes.Clone(baseImg)
					irom, drom := baseIROM, baseDROM
					img = tc.mutate(img, &irom, &drom)
					if _, err := VerifyImage(img, irom, drom); err == nil {
						t.Fatalf("VerifyImage unexpectedly accepted %s", tc.name)
					}
				})
			}
		})
	}
}

func TestVerifyRealArtifacts(t *testing.T) {
	check := func(name, elfEnv, binEnv, loaderEnv string) {
		elfPath, binPath, loaderPath := os.Getenv(elfEnv), os.Getenv(binEnv), os.Getenv(loaderEnv)
		if elfPath == "" || binPath == "" {
			return
		}
		t.Run(name, func(t *testing.T) {
			img, err := os.ReadFile(binPath)
			if err != nil {
				t.Fatalf("read bin: %v", err)
			}
			spec, err := detectChip(img)
			if err != nil {
				t.Fatalf("detectChip: %v", err)
			}
			irom, drom, err := symbols(elfPath, spec)
			if err != nil {
				t.Fatalf("symbols: %v", err)
			}
			rep, err := VerifyImage(img, irom, drom)
			if err != nil {
				t.Fatalf("VerifyImage: %v", err)
			}
			t.Logf("verified image: %+v", rep)
			if loaderPath != "" {
				lrep, err := VerifyLoader(loaderPath)
				if err != nil {
					t.Fatalf("VerifyLoader: %v", err)
				}
				if lrep.Chip != rep.Chip {
					t.Fatalf("loader chip %s != image chip %s", lrep.Chip, rep.Chip)
				}
				t.Logf("verified loader: %+v", lrep)
			}
		})
	}
	if os.Getenv("TMG_ESP32S3_ELF") == "" && os.Getenv("TMG_ESP32_ELF") == "" {
		t.Skip("set TMG_ESP32S3_ELF/BIN or TMG_ESP32_ELF/BIN to verify real firmware artifacts")
	}
	check("esp32s3", "TMG_ESP32S3_ELF", "TMG_ESP32S3_BIN", "TMG_ESP32S3_LOADER_ELF")
	check("esp32", "TMG_ESP32_ELF", "TMG_ESP32_BIN", "TMG_ESP32_LOADER_ELF")
}
