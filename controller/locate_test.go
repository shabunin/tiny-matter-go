package controller

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

var (
	testAddrs = []netip.AddrPort{netip.MustParseAddrPort("[fe80::1]:5540")}
	testBLE   = BLEDevice{ID: "dev0", Address: "02:00:00:00:00:01"}
	errAdapt  = errors.New("bluez: adapter is off")
)

// ipAfter answers with testAddrs, or err if set, after d.
func ipAfter(d time.Duration, err error) func(context.Context) ([]netip.AddrPort, error) {
	return func(ctx context.Context) ([]netip.AddrPort, error) {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		return testAddrs, nil
	}
}

func bleAfter(d time.Duration, err error) func(context.Context) (BLEDevice, error) {
	return func(ctx context.Context) (BLEDevice, error) {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return BLEDevice{}, ctx.Err()
		}
		return testBLE, err
	}
}

func TestRace(t *testing.T) {
	nf := notFound{"not found"}
	const never = time.Hour
	for _, tc := range []struct {
		name    string
		f       finders
		grace   time.Duration
		wantIP  bool
		wantBLE bool
		wantErr error // matched with errors.Is, or by isNotFound for nf
	}{
		{"IP within the grace period", finders{ipAfter(20*time.Millisecond, nil), bleAfter(0, nil)}, 5 * time.Second, true, false, nil},
		{"IP first", finders{ipAfter(0, nil), bleAfter(20*time.Millisecond, nil)}, 5 * time.Second, true, false, nil},
		{"BLE after the grace period", finders{ipAfter(never, nil), bleAfter(0, nil)}, 20 * time.Millisecond, false, true, nil},
		{"BLE once IP fails", finders{ipAfter(0, nf), bleAfter(20*time.Millisecond, nil)}, 5 * time.Second, false, true, nil},
		{"BLE, then IP fails", finders{ipAfter(20*time.Millisecond, nf), bleAfter(0, nil)}, 5 * time.Second, false, true, nil},
		{"IP once BLE fails", finders{ipAfter(20*time.Millisecond, nil), bleAfter(0, errAdapt)}, 5 * time.Second, true, false, nil},
		{"neither found", finders{ipAfter(0, nf), bleAfter(10*time.Millisecond, nf)}, 5 * time.Second, false, false, nf},
		{"a failure wins", finders{ipAfter(0, nf), bleAfter(10*time.Millisecond, errAdapt)}, 5 * time.Second, false, false, errAdapt},
		{"a failure wins, first", finders{ipAfter(10*time.Millisecond, nf), bleAfter(0, errAdapt)}, 5 * time.Second, false, false, errAdapt},
		{"IP only", finders{ip: ipAfter(0, nil)}, 5 * time.Second, true, false, nil},
		{"IP only, not found", finders{ip: ipAfter(0, nf)}, 5 * time.Second, false, false, nf},
		{"BLE only", finders{ble: bleAfter(0, nil)}, 5 * time.Second, false, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			l, err := race(context.Background(), tc.f, tc.grace)
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("took %v", took)
			}
			switch {
			case tc.wantErr == nf:
				if !isNotFound(err) {
					t.Fatalf("err = %v, want not found", err)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case err != nil:
				t.Fatal(err)
			}
			if gotIP := len(l.addrs) > 0; gotIP != tc.wantIP {
				t.Errorf("addrs %v", l.addrs)
			}
			if gotBLE := l.ble != nil; gotBLE != tc.wantBLE || gotBLE && l.ble.ID != testBLE.ID {
				t.Errorf("ble %v", l.ble)
			}
		})
	}
	if _, err := race(context.Background(), finders{}, time.Second); err == nil {
		t.Error("no finders: no error")
	}
}

// TestRaceCancels: the losing search is stopped.
func TestRaceCancels(t *testing.T) {
	stopped := make(chan struct{})
	ip := func(ctx context.Context) ([]netip.AddrPort, error) {
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}
	l, err := race(context.Background(), finders{ip, bleAfter(0, nil)}, 10*time.Millisecond)
	if err != nil || l.ble == nil {
		t.Fatalf("race = %v, %v", l, err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the mDNS search goes on")
	}

	// The caller giving up ends both.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = race(ctx, finders{ipAfter(time.Hour, nil), bleAfter(time.Hour, nil)}, time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}
