//go:build rp2350

// Package rptrng reads the RP2350's true random number generator (RP2350
// datasheet 12.12). TinyGo's machine.GetRNG and crypto/rand on the RP2040
// and RP2350 sample the ring oscillator and are not meant for keys.
//
// The TRNG runs with its health tests on (autocorrelation, repetition and
// the von Neumann corrector); a block that fails one is thrown away and
// the source restarted. Its raw output is not guaranteed to carry a full
// bit of entropy per bit, so every 32 bytes returned are the SHA-256 of
// 72 bytes from it.
package rptrng

import (
	"crypto/sha256"
	"device/rp"
	"errors"
	"time"
)

const (
	// sampleCount is how many system clock cycles the TRNG waits between
	// samples of its ring oscillator: more is slower and less correlated.
	sampleCount = 256
	errorBits   = rp.TRNG_RNG_ISR_AUTOCORR_ERR_Msk | rp.TRNG_RNG_ISR_CRNGT_ERR_Msk | rp.TRNG_RNG_ISR_VN_ERR_Msk
	blockSize   = 24 // the six EHR_DATA registers
)

// ErrTimeout is returned when the TRNG produces nothing for a while.
var ErrTimeout = errors.New("rptrng: no data from the TRNG")

// Reader reads random bytes. It is not safe for concurrent use.
type Reader struct {
	started bool
	// Restarts counts blocks thrown away after a failed health test.
	Restarts int
}

func (r *Reader) start() {
	rp.RESETS.RESET.ClearBits(rp.RESETS_RESET_TRNG)
	for !rp.RESETS.RESET_DONE.HasBits(rp.RESETS_RESET_DONE_TRNG_Msk) {
	}
	t := rp.TRNG
	t.RND_SOURCE_ENABLE.Set(0)
	t.TRNG_SW_RESET.Set(1)
	for t.TRNG_BUSY.Get() != 0 {
	}
	t.RNG_IMR.Set(0xF) // no interrupts: polled
	t.TRNG_CONFIG.Set(0)
	t.SAMPLE_CNT1.Set(sampleCount)
	t.TRNG_DEBUG_CONTROL.Set(0) // all health tests and the corrector on
	t.RNG_ICR.Set(0xFFFFFFFF)
	t.RND_SOURCE_ENABLE.Set(1)
	r.started = true
}

// block reads one 192-bit block from the TRNG into b.
func (r *Reader) block(b *[blockSize]byte) error {
	t := rp.TRNG
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		if !r.started {
			r.start()
		}
		isr := t.RNG_ISR.Get()
		if isr&errorBits != 0 {
			r.Restarts++
			r.started = false // a failed test stops the source
			continue
		}
		if t.TRNG_VALID.Get()&rp.TRNG_TRNG_VALID_EHR_VALID_Msk != 0 {
			regs := [...]uint32{t.EHR_DATA0.Get(), t.EHR_DATA1.Get(), t.EHR_DATA2.Get(),
				t.EHR_DATA3.Get(), t.EHR_DATA4.Get(), t.EHR_DATA5.Get()}
			t.RNG_ICR.Set(rp.TRNG_RNG_ISR_EHR_VALID_Msk)
			for i, v := range regs {
				b[4*i], b[4*i+1], b[4*i+2], b[4*i+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
			}
			return nil
		}
		if time.Now().After(deadline) {
			r.started = false
			return ErrTimeout
		}
	}
}

// Read fills p with random bytes.
func (r *Reader) Read(p []byte) (int, error) {
	n := 0
	var raw [3 * blockSize]byte
	for n < len(p) {
		for i := 0; i < 3; i++ {
			if err := r.block((*[blockSize]byte)(raw[i*blockSize:])); err != nil {
				return n, err
			}
		}
		sum := sha256.Sum256(raw[:])
		n += copy(p[n:], sum[:])
	}
	clear(raw[:])
	return n, nil
}
