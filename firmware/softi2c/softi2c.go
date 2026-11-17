// Package softi2c is a bit-banged I2C controller on two GPIOs, for buses
// the hardware controller cannot drive: TinyGo's on the classic ESP32 gets
// no answer from the M5StickC's HAT header (G0, G26), whose chips answer
// this one. Both lines need pull-ups (the units have them; the internal
// ones are enabled too). It runs at about 25 kHz and honours clock
// stretching.
package softi2c

import (
	"errors"
	"machine"
	"time"
)

var (
	errNack    = errors.New("softi2c: no acknowledge")
	errStretch = errors.New("softi2c: clock held low")
)

// Bus is an I2C bus on SDA and SCL.
type Bus struct {
	SDA, SCL machine.Pin
}

// Configure releases both lines.
func (b *Bus) Configure() {
	b.release(b.SDA)
	b.release(b.SCL)
}

func (b *Bus) release(p machine.Pin) { p.Configure(machine.PinConfig{Mode: machine.PinInputPullup}) }

func (b *Bus) pull(p machine.Pin) {
	p.Configure(machine.PinConfig{Mode: machine.PinOutput})
	p.Low()
}

func delay() { time.Sleep(20 * time.Microsecond) }

// sclHigh releases SCL and waits for it to rise: a target may hold it low
// (clock stretching) while it works.
func (b *Bus) sclHigh() error {
	b.release(b.SCL)
	for i := 0; !b.SCL.Get(); i++ {
		if i > 5000 { // about 100 ms
			return errStretch
		}
		delay()
	}
	delay()
	return nil
}

func (b *Bus) start() error {
	b.release(b.SDA)
	if err := b.sclHigh(); err != nil {
		return err
	}
	b.pull(b.SDA)
	delay()
	b.pull(b.SCL)
	delay()
	return nil
}

func (b *Bus) stop() {
	b.pull(b.SDA)
	delay()
	b.sclHigh()
	b.release(b.SDA)
	delay()
}

// write sends a byte and reports whether the target acknowledged it.
func (b *Bus) write(v byte) (bool, error) {
	for i := 0; i < 8; i++ {
		if v&0x80 != 0 {
			b.release(b.SDA)
		} else {
			b.pull(b.SDA)
		}
		v <<= 1
		delay()
		if err := b.sclHigh(); err != nil {
			return false, err
		}
		b.pull(b.SCL)
	}
	b.release(b.SDA)
	delay()
	if err := b.sclHigh(); err != nil {
		return false, err
	}
	ack := !b.SDA.Get()
	b.pull(b.SCL)
	delay()
	return ack, nil
}

// read receives a byte, acknowledging it if more are wanted.
func (b *Bus) read(more bool) (byte, error) {
	var v byte
	b.release(b.SDA)
	for i := 0; i < 8; i++ {
		delay()
		if err := b.sclHigh(); err != nil {
			return 0, err
		}
		v <<= 1
		if b.SDA.Get() {
			v |= 1
		}
		b.pull(b.SCL)
	}
	if more {
		b.pull(b.SDA)
	}
	delay()
	if err := b.sclHigh(); err != nil {
		return 0, err
	}
	b.pull(b.SCL)
	b.release(b.SDA)
	return v, nil
}

// Tx writes w to the target at addr and then reads len(r) bytes, with a
// repeated start between (machine.I2C's Tx).
func (b *Bus) Tx(addr uint16, w, r []byte) error {
	err := b.tx(byte(addr), w, r)
	b.stop()
	return err
}

func (b *Bus) tx(addr byte, w, r []byte) error {
	if len(w) > 0 || len(r) == 0 {
		if err := b.start(); err != nil {
			return err
		}
		if err := b.send(addr<<1, w); err != nil {
			return err
		}
	}
	if len(r) == 0 {
		return nil
	}
	if err := b.start(); err != nil {
		return err
	}
	if err := b.send(addr<<1|1, nil); err != nil {
		return err
	}
	for i := range r {
		v, err := b.read(i < len(r)-1)
		if err != nil {
			return err
		}
		r[i] = v
	}
	return nil
}

// send writes the address byte and then w, each acknowledged.
func (b *Bus) send(first byte, w []byte) error {
	for i := -1; i < len(w); i++ {
		v := first
		if i >= 0 {
			v = w[i]
		}
		ack, err := b.write(v)
		if err != nil {
			return err
		}
		if !ack {
			return errNack
		}
	}
	return nil
}
