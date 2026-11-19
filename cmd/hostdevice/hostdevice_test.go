package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/dnssd"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/ota"
)

type discardTransport struct{}

func (discardTransport) Send(exchange.Addr, []byte) error { return nil }

func newTestApp(t *testing.T, typ string, withUnitTesting bool) *app {
	t.Helper()
	k, ok := kinds[typ]
	if !ok {
		t.Fatalf("unknown kind %q", typ)
	}
	salt := []byte("SPAKE2P Key Salt")
	v, err := spake2p.NewVerifier(20202021, salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	dacKey, err := p256.NewPrivateKey(devcreds.DACPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err := device.New(device.Config{
		Transport:     discardTransport{},
		Rand:          rand.Reader,
		Verifier:      v,
		Salt:          salt,
		Iterations:    1000,
		Discriminator: 3840,
		Attestation: &clusters.Attestation{
			DACKey:                   dacKey,
			DACCert:                  devcreds.DACCert,
			PAICert:                  devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration,
		},
		Basic: &clusters.BasicInformation{
			VendorName: "tiny-matter-go", VendorID: devcreds.VendorID,
			ProductName: k.product, ProductID: devcreds.ProductID,
			SoftwareVersion: 1, SoftwareVersionString: "0.1",
		},
		DeviceType: k.deviceType.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &app{d: d, cmds: make(chan string, 4)}
	k.build(a)
	a.utilities()
	if withUnitTesting {
		a.unitTesting()
	}
	return a
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.state")
	fs := fileStore(path)

	got, err := fs.Load()
	if err != nil || got != nil {
		t.Fatalf("missing Load = (%v, %v), want (nil, nil)", got, err)
	}
	want := []byte("state-v1")
	if err := fs.Save(want); err != nil {
		t.Fatalf("Save v1: %v", err)
	}
	got, err = fs.Load()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Load v1 = (%q, %v), want %q", got, err, want)
	}
	want2 := []byte("state-v2-longer")
	if err := fs.Save(want2); err != nil {
		t.Fatalf("Save v2: %v", err)
	}
	got, err = fs.Load()
	if err != nil || !bytes.Equal(got, want2) {
		t.Fatalf("Load v2 = (%q, %v), want %q", got, err, want2)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("leftover temp file: %v", err)
	}
}

func TestBinaryUpdates(t *testing.T) {
	dir := t.TempDir()
	bu := &binaryUpdates{dir: dir}

	if err := bu.Write([]byte("nope")); err == nil {
		t.Fatal("Write succeeded before Begin")
	}
	if err := bu.Apply(); err == nil {
		t.Fatal("Apply succeeded before Finish")
	}

	payload := []byte("#!/bin/sh\necho ok\n")
	if err := bu.Begin(&ota.Header{SoftwareVersion: 2, PayloadSize: uint64(len(payload))}); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := bu.Write(payload[:5]); err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	if err := bu.Write(payload[5:]); err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	if err := bu.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	wantPath := filepath.Join(dir, "hostdevice-v2")
	got, err := os.ReadFile(wantPath)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ready binary = (%q, %v), want %q", got, err, payload)
	}
	st, err := os.Stat(wantPath)
	if err != nil || st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("ready binary not executable: mode=%v err=%v", st.Mode(), err)
	}

	bu.Abort()
	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		t.Fatalf("Abort did not remove ready binary: %v", err)
	}
}

func TestAllKindsBuildAndPoll(t *testing.T) {
	now := time.Unix(1000, 0)
	for name := range kinds {
		t.Run(name, func(t *testing.T) {
			a := newTestApp(t, name, name == "light")
			a.d.Poll(now)
			a.poll(now)
		})
	}
}

func TestCommands(t *testing.T) {
	now := time.Unix(2000, 0)

	cases := []struct {
		kind string
		cmds []string
	}{
		{"light", []string{"click", "long", "press", "release"}},
		{"temperature", []string{"temp 21.5"}},
		{"humidity", []string{"humidity 45.2"}},
		{"pressure", []string{"pressure 1013"}},
		{"lightsensor", []string{"lux 250"}},
		{"contact", []string{"contact open", "contact closed"}},
		{"occupancy", []string{"occupancy on", "occupancy off"}},
		{"bridge", []string{"add light Lamp", "reach 3 off", "reach 3 on", "remove 3"}},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			a := newTestApp(t, tc.kind, false)
			for _, cmd := range tc.cmds {
				if err := a.command(now, cmd); err != nil {
					t.Fatalf("command %q: %v", cmd, err)
				}
				a.poll(now.Add(2 * time.Second))
			}
			if err := a.command(now, "nonexistent"); err == nil {
				t.Fatal("expected error for unknown command")
			}
			if err := a.command(now, "@bad click"); err == nil {
				t.Fatal("expected error for malformed endpoint prefix")
			}
		})
	}
}

func TestSanitizeHostLabel(t *testing.T) {
	cases := map[string]string{
		"my-host.local":      "my-host",
		"macbook_pro.lan":    "macbookpro",
		"192.168.1.50":       "hostdevice",
		"---":                "hostdevice",
		"":                   "hostdevice",
		"Host123":            "Host123",
		"-leading-trailing-": "leading-trailing",
	}
	for in, want := range cases {
		if got := sanitizeHostLabel(in); got != want {
			t.Errorf("sanitizeHostLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSelectMDNSBackend(t *testing.T) {
	if got, err := selectMDNSBackend("builtin"); err != nil || got != "builtin" {
		t.Fatalf("builtin: (%q, %v)", got, err)
	}
	if got, err := selectMDNSBackend("avahi"); err != nil || got != "avahi" {
		t.Fatalf("avahi: (%q, %v)", got, err)
	}
	if got, err := selectMDNSBackend("auto"); err != nil || (got != "avahi" && got != "builtin") {
		t.Fatalf("auto: (%q, %v)", got, err)
	}
	if _, err := selectMDNSBackend("bogus"); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestBuiltinMDNSLifecycle(t *testing.T) {
	h, err := startHostMDNS("builtin")
	if err != nil {
		t.Fatalf("startHostMDNS(builtin): %v", err)
	}
	defer h.close()

	h.advertiser.Advertise([]dnssd.Service{{
		Instance: "TEST1234",
		Type:     "_matterc._udp",
		Subtypes: []string{"_L3840", "_S15"},
		Port:     5540,
		TXT:      []string{"D=3840", "CM=1"},
	}})
	now := time.Now()
	if next := h.poll(now); next.IsZero() {
		t.Fatal("expected follow-up announcement schedule")
	}
	// Idempotent close (sends goodbyes and stops reader goroutines).
	h.close()
	h.close()
}
