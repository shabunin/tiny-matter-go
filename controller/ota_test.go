package controller_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/onboarding"
	"github.com/shabunin/tiny-matter-go/ota"
)

// memImages is an ImageStore in memory.
type memImages struct {
	data    []byte
	done    bool
	applied bool
}

func (m *memImages) Begin(h *ota.Header) error { m.data = nil; return nil }
func (m *memImages) Write(p []byte) error      { m.data = append(m.data, p...); return nil }
func (m *memImages) Finish() error             { m.done = true; return nil }
func (m *memImages) Abort()                    {}
func (m *memImages) Apply() error              { m.applied = true; return nil }

func TestOTAProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	images := &memImages{}
	d := startDeviceConfig(t, noNetwork, nil, func(cfg *device.Config) {
		cfg.Updates = images
		cfg.Basic.SoftwareVersion = 1
	})
	c := openController(t, t.TempDir())
	defer c.Close()
	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 20000)
	rand.Read(payload)
	img, err := ota.Create(ota.Header{VendorID: devcreds.VendorID, ProductID: devcreds.ProductID,
		SoftwareVersion: 2, SoftwareVersionString: "2.0"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	applied := make(chan uint32, 1)
	var sent int64
	transfers := make(chan error, 1)
	err = c.ServeOTA(&controller.OTAProvider{
		Image:      img,
		OnProgress: func(node uint64, s, total int64) { sent = s },
		OnTransfer: func(node uint64, err error) { transfers <- err },
		OnApply:    func(node uint64, version uint32) { applied <- version },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AnnounceOTA(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-transfers:
		if err != nil {
			t.Fatalf("transfer: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("no transfer")
	}
	select {
	case v := <-applied:
		if v != 2 {
			t.Fatalf("apply request for version %d", v)
		}
	case <-ctx.Done():
		t.Fatal("no apply request")
	}
	if sent != int64(len(img)) {
		t.Fatalf("progress ended at %d of %d", sent, len(img))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var ok bool
		var st uint8
		d.do(func() {
			ok = images.applied && images.done && bytes.Equal(images.data, payload)
			st = d.dev.OTA.State()
		})
		if ok && st == clusters.OTAStateApplying {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device did not apply the image (state %d)", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
