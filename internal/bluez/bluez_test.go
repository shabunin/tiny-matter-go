package bluez

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/internal/dbus"
)

func TestLinkSignalActiveGate(t *testing.T) {
	dev := dbus.ObjectPath("/org/bluez/hci0/dev_11_22_33_44_55_66")
	l := &Link{
		dev:      dev,
		resolved: make(chan struct{}, 1),
		events:   newQueue[[]byte](),
	}
	// Disconnect during pre-connect retry must not inject EOF (nil).
	l.signal(&dbus.Message{
		Member: "PropertiesChanged",
		Path:   dev,
		Body: []any{
			ifaceDevice,
			map[string]any{"Connected": dbus.Variant{Sig: "b", Value: false}},
			[]any{},
		},
	})
	if items := l.events.take(); len(items) != 0 {
		t.Fatalf("unexpected events before active: %v", items)
	}

	// ServicesResolved=true signals resolution readiness.
	l.signal(&dbus.Message{
		Member: "PropertiesChanged",
		Path:   dev,
		Body: []any{
			ifaceDevice,
			map[string]any{"ServicesResolved": dbus.Variant{Sig: "b", Value: true}},
			[]any{},
		},
	})
	select {
	case <-l.resolved:
	default:
		t.Fatal("expected ServicesResolved signal")
	}

	// Connected=false after connect loop succeeded injects nil EOF.
	l.active.Store(true)
	l.signal(&dbus.Message{
		Member: "PropertiesChanged",
		Path:   dev,
		Body: []any{
			ifaceDevice,
			map[string]any{"Connected": dbus.Variant{Sig: "b", Value: false}},
			[]any{},
		},
	})
	items := l.events.take()
	if len(items) != 1 || items[0] != nil {
		t.Fatalf("events after active disconnect = %v, want [nil]", items)
	}
}

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
