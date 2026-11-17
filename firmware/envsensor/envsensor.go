// Package envsensor drives the climate sensors of M5Stack ENV units over
// I2C: the Sensirion SHT3x (temperature and humidity; ENV II and III) and
// the Bosch BMP280 (pressure; ENV II and IV). Readings come in the units
// Matter uses: temperature in 0.01 °C, humidity in 0.01 % and pressure in
// Pa.
package envsensor

import (
	"encoding/binary"
	"errors"
)

// Bus is an I2C bus (machine.I2C satisfies it).
type Bus interface {
	Tx(addr uint16, w, r []byte) error
}

var errCRC = errors.New("envsensor: bad CRC")

// ---- SHT3x ----

// SHT3x is a Sensirion SHT30/31/35 at Addr (0x44, or 0x45 with ADDR high).
// A reading is in two steps, so the caller need not wait: Start a
// measurement, then Read it at least 16 ms later.
type SHT3x struct {
	Bus  Bus
	Addr uint16
}

// Start starts a single high-repeatability measurement (without clock
// stretching); it also tells whether the sensor is there.
func (s *SHT3x) Start() error { return s.Bus.Tx(s.Addr, []byte{0x24, 0x00}, nil) }

// Read returns the measurement Start started: temperature in 0.01 °C and
// relative humidity in 0.01 %.
func (s *SHT3x) Read() (temp, humidity int32, err error) {
	var b [6]byte
	if err := s.Bus.Tx(s.Addr, nil, b[:]); err != nil {
		return 0, 0, err
	}
	if crc8(b[0:2]) != b[2] || crc8(b[3:5]) != b[5] {
		return 0, 0, errCRC
	}
	t, h := binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[3:5])
	temp, humidity = SHT3xConvert(t, h)
	return temp, humidity, nil
}

// SHT3xConvert converts raw SHT3x readings (datasheet section 4.13).
func SHT3xConvert(rawT, rawH uint16) (temp, humidity int32) {
	temp = int32((17500*int64(rawT)+32767)/65535) - 4500
	humidity = int32((10000*int64(rawH) + 32767) / 65535)
	return temp, humidity
}

// crc8 is the Sensirion CRC (polynomial 0x31, initial value 0xFF).
func crc8(b []byte) byte {
	c := byte(0xFF)
	for _, x := range b {
		c ^= x
		for range 8 {
			if c&0x80 != 0 {
				c = c<<1 ^ 0x31
			} else {
				c <<= 1
			}
		}
	}
	return c
}

// ---- BMP280 ----

// BMP280 is a Bosch BMP280 at Addr (0x76, or 0x77 with SDO high), run in
// normal mode so a fresh reading is always there to read.
type BMP280 struct {
	Bus  Bus
	Addr uint16
	cal  BMP280Calibration
}

// BMP280Calibration is the BMP280's trimming parameters (dig_T1 to dig_P9).
type BMP280Calibration struct {
	T1         uint16
	T2, T3     int16
	P1         uint16
	P2, P3, P4 int16
	P5, P6, P7 int16
	P8, P9     int16
}

const (
	bmpChipID   = 0xD0
	bmpCalib    = 0x88
	bmpConfig   = 0xF5
	bmpCtrlMeas = 0xF4
	bmpData     = 0xF7
	bmp280ID    = 0x58
)

var errNotBMP280 = errors.New("envsensor: not a BMP280")

// Init checks the chip ID, reads the calibration and starts measuring:
// pressure ×16 and temperature ×2 oversampling, IIR filter 4, a reading a
// second.
func (s *BMP280) Init() error {
	var id [1]byte
	if err := s.Bus.Tx(s.Addr, []byte{bmpChipID}, id[:]); err != nil {
		return err
	}
	if id[0] != bmp280ID {
		return errNotBMP280
	}
	var c [24]byte
	if err := s.Bus.Tx(s.Addr, []byte{bmpCalib}, c[:]); err != nil {
		return err
	}
	s.cal = ParseBMP280Calibration(c[:])
	// config (standby 1 s, filter 4) before ctrl_meas: in normal mode
	// writes to config may be ignored.
	if err := s.Bus.Tx(s.Addr, []byte{bmpConfig, 0b101_010_00}, nil); err != nil {
		return err
	}
	return s.Bus.Tx(s.Addr, []byte{bmpCtrlMeas, 0b010_101_11}, nil)
}

// ParseBMP280Calibration decodes the 24 calibration bytes from 0x88.
func ParseBMP280Calibration(b []byte) BMP280Calibration {
	u := func(i int) uint16 { return binary.LittleEndian.Uint16(b[i:]) }
	s := func(i int) int16 { return int16(u(i)) }
	return BMP280Calibration{
		T1: u(0), T2: s(2), T3: s(4),
		P1: u(6), P2: s(8), P3: s(10), P4: s(12), P5: s(14), P6: s(16), P7: s(18), P8: s(20), P9: s(22),
	}
}

// Read returns the latest temperature (0.01 °C) and pressure (Pa).
func (s *BMP280) Read() (temp, pressure int32, err error) {
	var b [6]byte
	if err := s.Bus.Tx(s.Addr, []byte{bmpData}, b[:]); err != nil {
		return 0, 0, err
	}
	adcP := int32(b[0])<<12 | int32(b[1])<<4 | int32(b[2])>>4
	adcT := int32(b[3])<<12 | int32(b[4])<<4 | int32(b[5])>>4
	if adcT == 0x80000 || adcP == 0x80000 { // skipped or not yet measured
		return 0, 0, errors.New("envsensor: no BMP280 reading yet")
	}
	temp, pressure = s.cal.Compensate(adcT, adcP)
	return temp, pressure, nil
}

// Compensate converts raw readings to temperature (0.01 °C) and pressure
// (Pa), with the datasheet's integer formulas (section 3.11.3, the 64-bit
// pressure one).
func (c *BMP280Calibration) Compensate(adcT, adcP int32) (temp, pressure int32) {
	t1, t2, t3 := int32(c.T1), int32(c.T2), int32(c.T3)
	v1 := ((adcT>>3 - t1<<1) * t2) >> 11
	v2 := (((adcT>>4 - t1) * (adcT>>4 - t1)) >> 12 * t3) >> 14
	tFine := v1 + v2
	temp = (tFine*5 + 128) >> 8

	var1 := int64(tFine) - 128000
	var2 := var1 * var1 * int64(c.P6)
	var2 += (var1 * int64(c.P5)) << 17
	var2 += int64(c.P4) << 35
	var1 = (var1*var1*int64(c.P3))>>8 + (var1*int64(c.P2))<<12
	var1 = ((int64(1)<<47 + var1) * int64(c.P1)) >> 33
	if var1 == 0 {
		return temp, 0
	}
	p := 1048576 - int64(adcP)
	p = ((p<<31 - var2) * 3125) / var1
	var1 = (int64(c.P9) * (p >> 13) * (p >> 13)) >> 25
	var2 = (int64(c.P8) * p) >> 19
	p = (p+var1+var2)>>8 + int64(c.P7)<<4 // Pa in Q24.8
	return temp, int32((p + 128) >> 8)
}
