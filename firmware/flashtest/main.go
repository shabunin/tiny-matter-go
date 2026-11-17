//go:build esp32

// Command flashtest checks esp32flash with storage.Flash: each boot loads
// a counter, saves it plus one, then runs 20 save/load rounds. Run it
// twice to see the counter survive a restart.
package main

import (
	"time"

	"firmware/esp32flash"

	"github.com/shabunin/tiny-matter-go/storage"
)

func main() {
	time.Sleep(2 * time.Second)
	size := esp32flash.FlashSize()
	println("flashtest: flash size", size)
	dev := &esp32flash.Device{Offset: size - 32<<10, Length: 32 << 10}
	st := &storage.Flash{Dev: dev, SlotSize: 16 << 10}
	b, _ := st.Load()
	n := 0
	if len(b) >= 1 {
		n = int(b[0])
	}
	println("flashtest: loaded", len(b), "bytes, counter", n)
	payload := make([]byte, 3000)
	payload[0] = byte(n + 1)
	if err := st.Save(payload); err != nil {
		println("flashtest: save:", err.Error())
	}
	bad := 0
	start := time.Now()
	for i := 0; i < 20; i++ {
		payload[1], payload[2999] = byte(i), byte(i*7)
		if st.Save(payload) != nil {
			bad++
			continue
		}
		b, _ := (&storage.Flash{Dev: dev, SlotSize: 16 << 10}).Load()
		if len(b) != 3000 || b[0] != byte(n+1) || b[1] != byte(i) || b[2999] != byte(i*7) {
			bad++
		}
	}
	println("flashtest: 20 save/load rounds, failures", bad, "in", time.Since(start).String())
	for {
		time.Sleep(time.Second)
	}
}
