package envsensor

import (
	"errors"
	"testing"
)

func TestCRC8(t *testing.T) {
	// The SHT3x datasheet's example (section 4.12).
	if c := crc8([]byte{0xBE, 0xEF}); c != 0x92 {
		t.Fatalf("crc8(BEEF) = %#x, want 0x92", c)
	}
}

func TestSHT3xConvert(t *testing.T) {
	for _, c := range []struct {
		t, h  uint16
		wantT int32
		wantH int32
	}{
		{0, 0, -4500, 0},
		{0xFFFF, 0xFFFF, 13000, 10000},
		{0x62C0, 0xBA5B, 2251, 7280}, // read on the Cardputer: 22.51 °C, 72.80 %
	} {
		gt, gh := SHT3xConvert(c.t, c.h)
		if gt != c.wantT || gh != c.wantH {
			t.Errorf("SHT3xConvert(%#x, %#x) = %d, %d; want %d, %d", c.t, c.h, gt, gh, c.wantT, c.wantH)
		}
	}
}

// bus answers like one sensor: a register pointer then reads from it, and
// records writes.
type bus struct {
	addr   uint16
	regs   [256]byte
	reads  [][]byte // canned reads without a register (SHT3x)
	writes [][]byte
}

func (b *bus) Tx(addr uint16, w, r []byte) error {
	if addr != b.addr {
		return errors.New("NACK")
	}
	switch {
	case len(w) == 1 && len(r) > 0:
		copy(r, b.regs[w[0]:])
	case len(w) == 0 && len(r) > 0:
		if len(b.reads) == 0 {
			return errors.New("NACK")
		}
		copy(r, b.reads[0])
		b.reads = b.reads[1:]
	default:
		b.writes = append(b.writes, append([]byte(nil), w...))
	}
	return nil
}

func TestSHT3xRead(t *testing.T) {
	// Bytes an SHT30 on the Cardputer sent, CRCs and all.
	b := &bus{addr: 0x44, reads: [][]byte{{0x62, 0xC0, 0x4A, 0xBA, 0x5B, 0x6A}}}
	s := &SHT3x{Bus: b, Addr: 0x44}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if tt, h, err := s.Read(); err != nil || tt != 2251 || h != 7280 {
		t.Fatalf("Read: %d %d %v", tt, h, err)
	}
	b.reads = [][]byte{{0x62, 0xC0, 0x4A, 0xBA, 0x5B, 0x00}}
	if _, _, err := s.Read(); err != errCRC {
		t.Errorf("bad CRC: %v", err)
	}
	if (&SHT3x{Bus: b, Addr: 0x45}).Start() == nil {
		t.Error("absent sensor started")
	}
}

// The datasheet's worked example (BMP280 datasheet section 3.12).
var example = BMP280Calibration{
	T1: 27504, T2: 26435, T3: -1000,
	P1: 36477, P2: -10685, P3: 3024, P4: 2855, P5: 140, P6: -7, P7: 15500, P8: -14600, P9: 6000,
}

func TestBMP280Compensate(t *testing.T) {
	temp, p := example.Compensate(519888, 415148)
	if temp != 2508 || p != 100653 {
		t.Fatalf("Compensate = %d (0.01 °C), %d Pa; want 2508, 100653", temp, p)
	}
}

func TestBMP280(t *testing.T) {
	b := &bus{addr: 0x76}
	b.regs[bmpChipID] = bmp280ID
	le := func(i int, v uint16) { b.regs[bmpCalib+i], b.regs[bmpCalib+i+1] = byte(v), byte(v>>8) }
	c := example
	for i, v := range []uint16{c.T1, uint16(c.T2), uint16(c.T3), c.P1, uint16(c.P2), uint16(c.P3),
		uint16(c.P4), uint16(c.P5), uint16(c.P6), uint16(c.P7), uint16(c.P8), uint16(c.P9)} {
		le(2*i, v)
	}
	s := &BMP280{Bus: b, Addr: 0x76}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	if s.cal != example {
		t.Fatalf("calibration %+v", s.cal)
	}
	if len(b.writes) != 2 || b.writes[0][0] != bmpConfig || b.writes[1][0] != bmpCtrlMeas || b.writes[1][1]&3 != 3 {
		t.Errorf("setup writes %x", b.writes)
	}
	// Before the first measurement the data registers read 0x80000.
	copy(b.regs[bmpData:], []byte{0x80, 0, 0, 0x80, 0, 0})
	if _, _, err := s.Read(); err == nil {
		t.Error("reading before a measurement")
	}
	// adc_P 415148 = 0x655AC, adc_T 519888 = 0x7EED0.
	copy(b.regs[bmpData:], []byte{0x65, 0x5A, 0xC0, 0x7E, 0xED, 0x00})
	if tt, p, err := s.Read(); err != nil || tt != 2508 || p != 100653 {
		t.Fatalf("Read = %d, %d, %v", tt, p, err)
	}
	b.regs[bmpChipID] = 0x60 // a BME280
	if (&BMP280{Bus: b, Addr: 0x76}).Init() != errNotBMP280 {
		t.Error("BME280 taken for a BMP280")
	}
}
