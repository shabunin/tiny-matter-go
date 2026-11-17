package device_test

import (
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// TestBindingUnreachable keeps sending to a bound node that never answers:
// the device's memory must stay flat (a sensor bound to a light that is
// switched off must not run out).
func TestBindingUnreachable(t *testing.T) {
	const ghost = 0x99
	ghostAddr := netip.MustParseAddrPort("[fe80::99]:5540")
	var h *harness
	fails := 0
	h = newHarnessConfig(t, &storage.Memory{}, false, func(cfg *device.Config) {
		cfg.Log = func(m string) {
			if strings.Contains(m, "binding:") {
				fails++
			}
		}
		cfg.Resolve = func(now time.Time, cfid [8]byte, node uint64) (exchange.Addr, bool) {
			return ghostAddr, node == ghost
		}
	})
	ep := h.dev.Node.AddEndpoint(sensorEndpoint, clusters.DeviceTypeOccupancySensor)
	ep.Clients = []uint32{clusters.IDOnOff}
	h.dev.Node.AddCluster(ep, clusters.Descriptor{}, h.dev.NewBinding())
	_, s := h.commission()
	path := im.AttributePath{Endpoint: sensorEndpoint, Cluster: clusters.IDBinding, Attribute: 0}
	if st := h.write(s, path, bindingList(func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(1), ghost)
		w.PutUint(tlv.ContextTag(3), 1)
	})); st != im.Success {
		t.Fatalf("write binding: %#x", st)
	}
	run := func(d time.Duration) {
		for end := h.w.Now.Add(d); h.w.Now.Before(end); {
			h.dev.SendBound(h.w.Now, sensorEndpoint, clusters.IDOnOff, clusters.CmdOn, nil)
			for i := 0; i < 20; i++ {
				h.w.Advance(time.Second)
			}
		}
	}
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	run(10 * time.Minute)
	before, sessions := heap(), len(h.dev.M.Sessions())
	run(2 * time.Hour)
	after := heap()
	t.Logf("heap %d -> %d bytes, sessions %d -> %d, %d failures logged", before, after, sessions, len(h.dev.M.Sessions()), fails)
	if fails < 100 {
		t.Fatalf("only %d failures: the node was not retried", fails)
	}
	if after > before+64<<10 {
		t.Errorf("heap grew by %d bytes over 2 hours of failed sends", after-before)
	}
}
