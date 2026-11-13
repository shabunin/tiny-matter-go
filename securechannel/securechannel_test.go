package securechannel

import (
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func TestStatusReport(t *testing.T) {
	s := SecureChannelStatus(GeneralBusy, CodeBusy)
	s.Data = []byte{0xe8, 0x03}
	b := s.AppendTo(nil)
	want := []byte{8, 0, 0, 0, 0, 0, 4, 0, 0xe8, 3}
	if string(b) != string(want) {
		t.Fatalf("encoded % x, want % x", b, want)
	}
	got, err := ParseStatusReport(b)
	if err != nil || got.GeneralCode != GeneralBusy || got.ProtocolCode != CodeBusy || string(got.Data) != string(s.Data) {
		t.Fatalf("got %+v, %v", got, err)
	}
	ok := SecureChannelStatus(GeneralSuccess, CodeSessionEstablishmentSuccess)
	if !ok.IsSuccess() || got.IsSuccess() {
		t.Fatal("IsSuccess")
	}
	if _, err := ParseStatusReport(b[:7]); err == nil {
		t.Fatal("short report accepted")
	}
}

func TestSessionParams(t *testing.T) {
	p := DefaultSessionParams
	p.MRP.IdleInterval = 5 * time.Second
	w := tlv.NewWriter(nil)
	p.Encode(w, tlv.Anonymous)
	r := tlv.NewReader(w.Bytes())
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSessionParams(r)
	if err != nil || got != p {
		t.Fatalf("got %+v, %v", got, err)
	}

	// An empty structure yields spec defaults.
	w = tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.EndContainer()
	r = tlv.NewReader(w.Bytes())
	r.Next()
	got, err = DecodeSessionParams(r)
	if err != nil || got.MRP != exchange.DefaultMRPConfig || got.MaxPathsPerInvoke != 1 {
		t.Fatalf("defaults: %+v, %v", got, err)
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	k1, _ := DeriveSessionKeys([]byte("secret"), nil, "SessionKeys")
	k2, _ := DeriveSessionKeys([]byte("secret"), nil, "SessionResumptionKeys")
	if k1.I2R == k1.R2I || k1 == k2 {
		t.Fatal("keys not distinct")
	}
}
