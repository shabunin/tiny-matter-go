package controller

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWaitTimeoutRespectsLongerContext(t *testing.T) {
	if got := waitTimeout(context.Background()); got != responseTimeout {
		t.Fatalf("background waitTimeout = %v, want %v", got, responseTimeout)
	}
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShort()
	if got := waitTimeout(shortCtx); got != responseTimeout {
		t.Fatalf("short deadline waitTimeout = %v, want %v", got, responseTimeout)
	}
	longCtx, cancelLong := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancelLong()
	if got := waitTimeout(longCtx); got <= responseTimeout || got > 75*time.Second {
		t.Fatalf("long deadline waitTimeout = %v, want in (%v, 75s]", got, responseTimeout)
	}
}

func TestReserveNodeIDConcurrent(t *testing.T) {
	c := &Controller{st: &state{NextNodeID: 1}}

	// Explicit reservation blocks concurrent reuse until released.
	id, err := c.reserveNodeID(42)
	if err != nil || id != 42 {
		t.Fatalf("reserveNodeID(42) = %d, %v", id, err)
	}
	if _, err := c.reserveNodeID(42); err == nil {
		t.Fatal("duplicate explicit reserveNodeID(42) succeeded")
	}
	c.releaseNodeID(42)
	if id, err := c.reserveNodeID(42); err != nil || id != 42 {
		t.Fatalf("re-reserve after release: %d, %v", id, err)
	}
	c.releaseNodeID(42)

	// Concurrent automatic allocation assigns unique IDs.
	const n = 16
	ids := make([]uint64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := c.reserveNodeID(0)
			if err != nil {
				t.Errorf("reserve(0) %d: %v", i, err)
				return
			}
			ids[i] = got
		}(i)
	}
	wg.Wait()
	seen := map[uint64]bool{}
	for _, got := range ids {
		if got == 0 || seen[got] {
			t.Fatalf("duplicate or zero reserved ID %d in %v", got, ids)
		}
		seen[got] = true
		c.releaseNodeID(got)
	}
}
