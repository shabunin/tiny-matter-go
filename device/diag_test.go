package device_test

import (
	"bytes"
	"testing"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func TestSoftwareDiagnostics(t *testing.T) {
	h := newHarness(t)
	_, caseS := h.commission()
	// Free may be 0 under Go, which returns idle heap to the OS; TinyGo's
	// heap is fixed.
	if _, err := h.attr(caseS, 0, clusters.IDSoftwareDiagnostics, 1).Uint(); err != nil {
		t.Fatal(err)
	}
	used, err := h.attr(caseS, 0, clusters.IDSoftwareDiagnostics, 2).Uint()
	if err != nil || used == 0 {
		t.Fatalf("CurrentHeapUsed %d, %v", used, err)
	}
	// Only the heap attributes and no features (no watermark).
	if fm, _ := h.attr(caseS, 0, clusters.IDSoftwareDiagnostics, 0xFFFC).Uint(); fm != 0 {
		t.Fatalf("FeatureMap %#x", fm)
	}
	if h.dev.WiFiDiagnostics != nil {
		t.Fatal("Wi-Fi Network Diagnostics on a device without Wi-Fi")
	}
	rds := h.readQ(caseS, im.Request{Attributes: []im.AttributePath{{Endpoint: 0, Cluster: clusters.IDWiFiDiagnostics, Attribute: 4}}})
	if len(rds) != 1 || len(rds[0].Reports) != 1 || rds[0].Reports[0].Status != im.UnsupportedCluster {
		t.Fatalf("Wi-Fi diagnostics read on a non-Wi-Fi device: %+v", rds)
	}
}

func TestWiFiNetworkDiagnostics(t *testing.T) {
	h := newHarnessWith(t, nil, true)
	_, caseS := h.commission()
	nulls := func(what string) {
		t.Helper()
		for a := uint32(0); a <= 4; a++ {
			if !h.attr(caseS, 0, clusters.IDWiFiDiagnostics, a).IsNull() {
				t.Fatalf("%s: attribute %d is not null", what, a)
			}
		}
	}
	nulls("no Status")

	st := clusters.WiFiStatus{}
	h.dev.WiFiDiagnostics.Status = func() clusters.WiFiStatus { return st }
	st.RSSI, st.HasRSSI = -60, true
	nulls("not connected")

	// Connected, but only the RSSI known (as espradio reports today).
	st.Connected = true
	if v, _ := h.attr(caseS, 0, clusters.IDWiFiDiagnostics, 4).Int(); v != -60 {
		t.Fatalf("RSSI %d", v)
	}
	if v, _ := h.attr(caseS, 0, clusters.IDWiFiDiagnostics, 1).Uint(); v != clusters.WiFiSecurityUnspecified {
		t.Fatalf("SecurityType %d", v)
	}
	for _, a := range []uint32{0, 2, 3} {
		if !h.attr(caseS, 0, clusters.IDWiFiDiagnostics, a).IsNull() {
			t.Fatalf("unknown attribute %d is not null", a)
		}
	}

	// Everything known.
	st = clusters.WiFiStatus{Connected: true, BSSID: [6]byte{1, 2, 3, 4, 5, 6}, Security: clusters.WiFiSecurityWPA2,
		Version: 3, HasVersion: true, Channel: 6, RSSI: -45, HasRSSI: true}
	if b, _ := h.attr(caseS, 0, clusters.IDWiFiDiagnostics, 0).Bytes(); !bytes.Equal(b, st.BSSID[:]) {
		t.Fatalf("BSSID %x", b)
	}
	for a, want := range map[uint32]uint64{1: clusters.WiFiSecurityWPA2, 2: 3, 3: 6} {
		if v, _ := h.attr(caseS, 0, clusters.IDWiFiDiagnostics, a).Uint(); v != want {
			t.Fatalf("attribute %d = %d, want %d", a, v, want)
		}
	}
	if v, _ := h.attr(caseS, 0, clusters.IDWiFiDiagnostics, 4).Int(); v != -45 {
		t.Fatalf("RSSI %d", v)
	}
	// The root endpoint lists it.
	ids := h.attr(caseS, 0, clusters.IDDescriptor, 1)
	if !listHas(t, ids, clusters.IDWiFiDiagnostics) {
		t.Fatal("Descriptor ServerList lacks Wi-Fi Network Diagnostics")
	}
}

// listHas reports whether the list r is positioned on holds the integer v.
func listHas(t *testing.T, r *tlv.Reader, v uint64) bool {
	t.Helper()
	if err := r.EnterContainer(); err != nil {
		t.Fatal(err)
	}
	for r.Next() == nil {
		if x, err := r.Uint(); err == nil && x == v {
			return true
		}
	}
	return false
}
