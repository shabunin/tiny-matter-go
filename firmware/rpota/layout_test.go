package rpota

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// tinygoImage returns the start of an image as TinyGo builds it: a vector
// table, then the minimal Arm IMAGE_DEF of targets/rp2350_embedded_block.s.
func tinygoImage() []byte {
	img := make([]byte, 0x200)
	for i, w := range []uint32{0xffffded3, 0x10210142, 0x000001ff, 0, 0xab123579} {
		binary.LittleEndian.PutUint32(img[0x110+4*i:], w)
	}
	return img
}

func TestSetTBYB(t *testing.T) {
	img := tinygoImage()
	if err := CheckUpdate(img); err == nil {
		t.Fatal("an image without TBYB passed as an update")
	}
	if err := SetTBYB(img); err != nil {
		t.Fatal(err)
	}
	if w := binary.LittleEndian.Uint32(img[0x114:]); w != 0x90210142 {
		t.Fatalf("image type item %#x, want 0x90210142", w)
	}
	if err := CheckUpdate(img); err != nil {
		t.Fatal(err)
	}
}

func TestImageDefRefused(t *testing.T) {
	for name, edit := range map[string]func(img []byte){
		"no block":    func(img []byte) { img[0x110] = 0 },
		"RP2040":      func(img []byte) { binary.LittleEndian.PutUint32(img[0x114:], 0x00210142) },
		"RISC-V":      func(img []byte) { binary.LittleEndian.PutUint32(img[0x114:], 0x11210142) },
		"longer loop": func(img []byte) { binary.LittleEndian.PutUint32(img[0x11c:], 0x40) },
		"no end":      func(img []byte) { img[0x120] = 0 },
	} {
		img := tinygoImage()
		edit(img)
		if err := SetTBYB(img); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPartitionTable(t *testing.T) {
	want := []uint32{
		0xffffded3,
		0x8200060a, // partition table: 6 words, 2 partitions, singleton
		0xfc008000,
		0xfc000000 | 2 | 508<<13, 0xfc020400,
		0xfc000000 | 509 | 1015<<13, 0xfc020402,
		0x000006ff, 0, 0xab123579,
	}
	b := PartitionTable()
	if len(b) != 4*len(want) {
		t.Fatalf("%d bytes", len(b))
	}
	for i, w := range want {
		if got := binary.LittleEndian.Uint32(b[4*i:]); got != w {
			t.Errorf("word %d: %#08x, want %#08x", i, got, w)
		}
	}
	a, bp := Partitions[0], Partitions[1]
	if a.Start() != 0x2000 || bp.Start() != a.Start()+a.Size() || bp.Start()+bp.Size() != StateStart {
		t.Fatalf("layout A %#x+%#x B %#x+%#x state %#x", a.Start(), a.Size(), bp.Start(), bp.Size(), StateStart)
	}
}

func TestInstallUF2(t *testing.T) {
	u := InstallUF2()
	if len(u)%512 != 0 || len(u)/512 != 4*16 {
		t.Fatalf("%d bytes", len(u))
	}
	le := binary.LittleEndian
	addrs := map[uint32]bool{}
	for i := 0; i < len(u); i += 512 {
		b := u[i : i+512]
		if le.Uint32(b) != 0x0A324655 || le.Uint32(b[508:]) != 0x0AB16F30 || le.Uint32(b[28:]) != FamilyAbsolute ||
			int(le.Uint32(b[20:])) != i/512 || le.Uint32(b[24:]) != 64 {
			t.Fatalf("block %d header", i/512)
		}
		addrs[le.Uint32(b[12:])] = true
	}
	for _, a := range []uint32{0x10000000, 0x10001000, 0x10002000, 0x10002f00, 0x101fd000} {
		if !addrs[a] {
			t.Errorf("no block at %#x", a)
		}
	}
	if !bytes.Equal(u[32:32+len(PartitionTable())], PartitionTable()) {
		t.Error("first block does not hold the table")
	}
}

func TestFirmwareUF2(t *testing.T) {
	img := bytes.Repeat([]byte{1}, 600)
	u := FirmwareUF2(img)
	if len(u) != 512*4 {
		t.Fatalf("%d blocks", len(u)/512)
	}
	le := binary.LittleEndian
	e := u[:512]
	if le.Uint32(e[8:]) != 0xa000 || le.Uint32(e[12:]) != 0x10001000 || le.Uint32(e[16:]) != 256 ||
		le.Uint32(e[20:]) != 0 || le.Uint32(e[24:]) != 2 || le.Uint32(e[28:]) != FamilyAbsolute ||
		le.Uint32(e[32+256:]) != 0x9957e304 || !bytes.Equal(e[32:32+256], bytes.Repeat([]byte{0xef}, 256)) {
		t.Fatalf("E10 block header % x", e[:32])
	}
	for i := 1; i < 4; i++ {
		b := u[512*i:]
		if le.Uint32(b[8:]) != 0x2000 || le.Uint32(b[12:]) != uint32(0x10000000+256*(i-1)) ||
			le.Uint32(b[20:]) != uint32(i-1) || le.Uint32(b[24:]) != 3 || le.Uint32(b[28:]) != FamilyArmS {
			t.Fatalf("block %d header % x", i, b[:32])
		}
	}
	if !bytes.Equal(u[512*3+32:512*3+32+88], img[512:]) || u[512*3+32+88] != 0xFF {
		t.Error("last block's data")
	}
}
