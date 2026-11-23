package wifinode

import (
	"testing"

	"github.com/shabunin/tiny-matter-go/clusters"
)

func TestScanResults(t *testing.T) {
	aps := []AccessPoint{
		{SSID: "far", RSSI: -80, Security: clusters.WiFiWPA2 | clusters.WiFiWPA3, Channel: 1, BSSID: [6]byte{1}},
		{SSID: "near", RSSI: -40}, // a radio that reports no details
		{SSID: "far", RSSI: -60, Security: clusters.WiFiWPA2, Channel: 11, BSSID: [6]byte{2}},
		{SSID: "", RSSI: -30},
		{SSID: "cafe", RSSI: -70, Security: clusters.WiFiUnencrypted, Channel: 6},
	}
	res := ScanResults(aps, nil)
	if len(res) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(res), res)
	}
	want := []struct {
		ssid     string
		rssi     int8
		security uint8
		channel  uint16
	}{
		{"near", -40, clusters.WiFiWPA2, 0},
		{"far", -60, clusters.WiFiWPA2, 11}, // the strongest of the two
		{"cafe", -70, clusters.WiFiUnencrypted, 6},
	}
	for i, w := range want {
		r := res[i]
		if string(r.SSID) != w.ssid || r.RSSI != w.rssi || r.Security != w.security || r.Channel != w.channel || r.Band != clusters.WiFiBand2G4 {
			t.Errorf("result %d: %+v, want %+v", i, r, w)
		}
	}
	if r := ScanResults(aps, []byte("far")); len(r) != 1 || r[0].BSSID != [6]byte{2} {
		t.Errorf("filtered: %+v", r)
	}
}
