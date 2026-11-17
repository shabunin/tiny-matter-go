package tlv

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

// sample writes many kinds of elements, with payloads around and well
// beyond small buffer sizes, nested containers and every tag form.
func sample(w *Writer, rnd *rand.Rand) {
	tags := []Tag{Anonymous, ContextTag(1), ContextTag(255), {Kind: TagCommonProfile, Number: 0x1234}, {Kind: TagImplicitProfile, Number: 0x12345678}}
	w.StartStruct(Anonymous)
	for i := 0; i < 200; i++ {
		tag := tags[rnd.IntN(len(tags))]
		switch rnd.IntN(9) {
		case 0:
			w.PutUint(tag, rnd.Uint64()>>uint(rnd.IntN(64)))
		case 1:
			w.PutInt(tag, int64(rnd.Uint64())>>uint(rnd.IntN(64)))
		case 2:
			b := make([]byte, []int{0, 1, 31, 32, 33, 255, 256, 300, 1000, 70000}[rnd.IntN(10)])
			for j := range b {
				b[j] = byte(rnd.Uint32())
			}
			w.PutBytes(tag, b)
		case 3:
			w.PutString(tag, strings.Repeat("x", rnd.IntN(600)))
		case 4:
			w.StartList(tag)
			w.PutBool(ContextTag(1), true)
			w.PutNull(ContextTag(2))
			w.PutFloat64(ContextTag(3), 1.5)
			w.PutFloat32(ContextTag(4), -2)
			w.EndContainer()
		case 5:
			w.StartArray(tag)
		case 6:
			if w.Depth() > 1 {
				w.EndContainer()
			}
		case 7:
			w.PutRaw([]byte{0x24, 0x07, 0x2A}) // context tag 7, uint8 42
		case 8:
			w.PutRaw(bytes.Repeat([]byte{0x15, 0x18}, rnd.IntN(100)))
		}
	}
	for w.Depth() > 0 {
		w.EndContainer()
	}
}

func TestStreamWriter(t *testing.T) {
	for seed := uint64(0); seed < 20; seed++ {
		want := NewWriter(nil)
		sample(want, rand.New(rand.NewPCG(seed, 1)))
		if want.Err() != nil {
			t.Fatal(want.Err())
		}
		for _, size := range []int{0, 1, 31, 32, 33, 64, 100, 256, 4096} {
			var got []byte
			buf := make([]byte, 0, size)
			limit := max(size, minStreamBuf)
			w := NewStreamWriter(buf, func(p []byte) error {
				if len(p) == 0 || len(p) > limit {
					t.Fatalf("seed %d size %d: sink got %d bytes", seed, size, len(p))
				}
				got = append(got, p...)
				return nil
			})
			sample(w, rand.New(rand.NewPCG(seed, 1)))
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want.Bytes()) {
				t.Fatalf("seed %d size %d: streamed %d bytes differ from %d", seed, size, len(got), want.Len())
			}
			if cap(w.buf) != limit {
				t.Fatalf("seed %d size %d: buffer grew to %d", seed, size, cap(w.buf))
			}
			if w.Err() != nil || w.Len() != 0 {
				t.Fatalf("after Flush: err %v, %d bytes held", w.Err(), w.Len())
			}
			// What a streamed encoding decodes to is the same.
			if size == 64 {
				r := NewReader(got)
				if err := r.Next(); err != nil || r.Type() != TypeStruct {
					t.Fatalf("decode: %v", err)
				}
				if _, err := r.RawElement(); err != nil {
					t.Fatalf("decode: %v", err)
				}
			}
		}
	}
}

func TestStreamWriterSinkError(t *testing.T) {
	errFull := errors.New("full")
	calls := 0
	w := NewStreamWriter(make([]byte, 0, 32), func(p []byte) error {
		calls++
		if calls == 2 {
			return errFull
		}
		return nil
	})
	for i := 0; i < 100; i++ {
		w.PutBytes(ContextTag(1), make([]byte, 20))
	}
	if err := w.Flush(); err != errFull {
		t.Fatalf("Flush: %v", err)
	}
	if calls != 2 {
		t.Fatalf("sink called %d times; output after its error should be dropped", calls)
	}
	// A plain Writer is unaffected.
	if err := NewWriter(nil).Flush(); err != nil {
		t.Fatal(err)
	}
}
