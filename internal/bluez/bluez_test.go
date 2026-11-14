package bluez

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestLiveScan scans the real adapter for Matter devices for a few seconds.
// It runs only with TMG_BLE_LIVE=1.
func TestLiveScan(t *testing.T) {
	if os.Getenv("TMG_BLE_LIVE") == "" {
		t.Skip("set TMG_BLE_LIVE=1 to scan with the real adapter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Log("adapter", c.Adapter)
	n := 0
	err = c.Scan(ctx, func(d Device) bool {
		n++
		t.Logf("%s %q rssi %d service data % x", d.Address, d.Name, d.RSSI, d.ServiceData)
		return false
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	t.Logf("%d Matter devices advertising", n)
}
