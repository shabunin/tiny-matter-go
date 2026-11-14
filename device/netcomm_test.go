package device_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/securechannel/pase"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func nc(cmd uint32) im.CommandPath {
	return im.CommandPath{Endpoint: 0, Cluster: clusters.IDNetworkCommissioning, Command: cmd}
}

func addWiFi(ssid, creds string) func(w *tlv.Writer) {
	return func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), []byte(ssid))
		w.PutBytes(tlv.ContextTag(1), []byte(creds))
		w.PutUint(tlv.ContextTag(2), 7)
	}
}

func networkStatus(t *testing.T, res im.InvokeResult) uint64 {
	t.Helper()
	if res.Status != im.Success || res.Fields == nil {
		t.Fatalf("status %#x", res.Status)
	}
	v, _ := field(t, res.Fields, 0).Uint()
	return v
}

func TestNetworkCommissioning(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessWith(t, store, true)
	var joined []clusters.WiFiNetwork
	h.dev.Net.Connect = func(now time.Time, n clusters.WiFiNetwork) { joined = append(joined, n) }
	if h.dev.General.SupportsConcurrentConnection {
		t.Fatal("Wi-Fi device claims concurrent connection")
	}

	h.afterArm = func(s *exchange.Session) {
		// Constraint checks.
		if res := h.invoke(s, nc(2), addWiFi("", "password")); res.Status != im.ConstraintError {
			t.Fatalf("empty SSID: %#x", res.Status)
		}
		if res := h.invoke(s, nc(2), addWiFi("home", "short")); res.Status != im.Success {
			t.Fatalf("WEP-64 length rejected: %#x", res.Status) // 5 bytes is valid
		}
		if res := h.invoke(s, nc(2), addWiFi("home", "1234567")); res.Status != im.ConstraintError {
			t.Fatalf("7-byte credentials: %#x", res.Status)
		}
		// Update the network, then a second one exceeds MaxNetworks.
		res := h.invoke(s, nc(2), addWiFi("home", "correct horse"))
		if st := networkStatus(t, res); st != 0 {
			t.Fatalf("AddOrUpdateWiFiNetwork: %d", st)
		}
		if i, _ := field(t, res.Fields, 2).Uint(); i != 0 {
			t.Fatalf("network index %d", i)
		}
		if st := networkStatus(t, h.invoke(s, nc(2), addWiFi("other", "password"))); st != uint64(clusters.NetworkBoundsExceeded) {
			t.Fatalf("second network: %d", st)
		}
		if h.dev.General.Breadcrumb != 7 {
			t.Fatalf("breadcrumb %d", h.dev.General.Breadcrumb)
		}
		// Connect to an unknown network, then the configured one.
		res = h.invoke(s, nc(6), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), []byte("nope")) })
		if st := networkStatus(t, res); st != uint64(clusters.NetworkIDNotFound) || len(joined) != 0 {
			t.Fatalf("ConnectNetwork unknown: %d", st)
		}
		res = h.invoke(s, nc(6), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), []byte("home")) })
		if st := networkStatus(t, res); st != 0 {
			t.Fatalf("ConnectNetwork: %d", st)
		}
		if r := field(t, res.Fields, 2); !r.IsNull() {
			t.Fatal("ErrorValue not null")
		}
		if len(joined) != 1 || string(joined[0].SSID) != "home" || string(joined[0].Credentials) != "correct horse" {
			t.Fatalf("joined %+v", joined)
		}
		h.dev.Net.SetConnected(h.dev.Node, []byte("home"))
	}
	h.commission()
	if n := h.dev.Net.Committed(); len(n) != 1 || string(n[0].SSID) != "home" {
		t.Fatalf("committed %+v", n)
	}

	// The network survives a restart.
	h2 := newHarnessWith(t, store, true)
	if n := h2.dev.Net.Networks; len(n) != 1 || string(n[0].Credentials) != "correct horse" {
		t.Fatalf("restored %+v", n)
	}
}

func TestNetworkCommissioningRollback(t *testing.T) {
	h := newHarnessWith(t, nil, true)
	h.dev.Net.Restore([]clusters.WiFiNetwork{{SSID: []byte("old"), Credentials: []byte("password1")}})

	var paseS *exchange.Session
	pase.Pair(h.w.Now, h.ctl.M, h.devN.Addr, pase.InitiatorConfig{Passcode: passcode, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) { paseS = s }})
	h.w.Advance(time.Second)

	// Without the fail-safe, changes are refused.
	if res := h.invoke(paseS, nc(2), addWiFi("new", "password2")); res.Status != im.FailsafeRequired {
		t.Fatalf("without fail-safe: %#x", res.Status)
	}
	h.invoke(paseS, im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: 0},
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 30); w.PutUint(tlv.ContextTag(1), 1) })
	rm := func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), []byte("old")) }
	if st := networkStatus(t, h.invoke(paseS, nc(4), rm)); st != 0 {
		t.Fatalf("RemoveNetwork: %d", st)
	}
	if st := networkStatus(t, h.invoke(paseS, nc(4), rm)); st != uint64(clusters.NetworkIDNotFound) {
		t.Fatalf("RemoveNetwork again: %d", st)
	}
	if st := networkStatus(t, h.invoke(paseS, nc(2), addWiFi("new", "password2"))); st != 0 {
		t.Fatalf("add: %d", st)
	}
	if n := h.dev.Net.Networks; len(n) != 1 || string(n[0].SSID) != "new" {
		t.Fatalf("networks %+v", n)
	}
	h.w.Advance(time.Minute) // the fail-safe expires
	if n := h.dev.Net.Networks; len(n) != 1 || !bytes.Equal(n[0].SSID, []byte("old")) {
		t.Fatalf("not rolled back: %+v", n)
	}
}

func TestNetworkCommissioningRead(t *testing.T) {
	h := newHarnessWith(t, nil, true)
	h.dev.Net.Restore([]clusters.WiFiNetwork{{SSID: []byte("home"), Credentials: []byte("password1")}})
	h.dev.Net.SetConnected(h.dev.Node, []byte("home"))
	n := h.dev.Net
	buf := tlv.NewWriter(nil)
	ctx := &im.Context{Node: h.dev.Node}
	buf.StartStruct(tlv.Anonymous)
	for a := uint32(0); a <= 8; a++ {
		if st := n.ReadAttribute(ctx, a, buf, tlv.ContextTag(uint8(a))); st != im.Success {
			t.Fatalf("attribute %d: %#x", a, st)
		}
	}
	buf.EndContainer()
	raw := buf.Bytes()
	r := field(t, raw, 1)
	r.EnterContainer()
	r.Next()
	item, _ := r.RawElement()
	item = append([]byte{0x15}, item[1:]...) // re-tag as an anonymous struct
	if id, _ := field(t, item, 0).Bytes(); string(id) != "home" {
		t.Fatalf("network ID %q", id)
	}
	if c, _ := field(t, item, 1).Bool(); !c {
		t.Fatal("not connected")
	}
	if !field(t, raw, 5).IsNull() || !field(t, raw, 6).IsNull() || !field(t, raw, 7).IsNull() {
		t.Fatal("last-connect attributes not null")
	}
	if p := n.ReadPrivilege(1); p != im.Administer {
		t.Fatal("Networks readable without Administer")
	}
}

func TestNetworkCommissioningScan(t *testing.T) {
	h := newHarnessWith(t, nil, true)
	h.dev.Net.Scan = func(ctx *im.Context, ssid []byte) ([]clusters.WiFiScanResult, clusters.NetworkingStatus) {
		if ssid != nil {
			return nil, clusters.NetworkOK
		}
		return []clusters.WiFiScanResult{{Security: clusters.WiFiWPA2, SSID: []byte("home"), Channel: 6, RSSI: -40}}, clusters.NetworkOK
	}
	var paseS *exchange.Session
	pase.Pair(h.w.Now, h.ctl.M, h.devN.Addr, pase.InitiatorConfig{Passcode: passcode, Rand: rand.Reader,
		Done: func(now time.Time, s *exchange.Session, err error) { paseS = s }})
	h.w.Advance(time.Second)

	res := h.invoke(paseS, nc(0), func(w *tlv.Writer) { w.PutNull(tlv.ContextTag(0)) })
	if st := networkStatus(t, res); st != 0 {
		t.Fatalf("scan: %d", st)
	}
	r := field(t, res.Fields, 2)
	r.EnterContainer()
	if r.Next() != nil {
		t.Fatal("no scan results")
	}
	item, _ := r.RawElement()
	item = append([]byte{0x15}, item[1:]...)
	if ssid, _ := field(t, item, 1).Bytes(); string(ssid) != "home" {
		t.Fatalf("SSID %q", ssid)
	}
	if rssi, _ := field(t, item, 5).Int(); rssi != -40 {
		t.Fatalf("RSSI %d", rssi)
	}
	// A directed scan that finds nothing reports NetworkNotFound.
	res = h.invoke(paseS, nc(0), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), []byte("gone")) })
	if st := networkStatus(t, res); st != uint64(clusters.NetworkNotFound) {
		t.Fatalf("directed scan: %d", st)
	}
}
