package onboarding

import (
	"bytes"
	"testing"
)

// Vectors generated and parsed by chip-tool's payload commands (SDK
// v1.5.1).
var qrVectors = []struct {
	code string
	p    Payload
}{
	{"MT:Y.K9042C00KA0648G00", Payload{VendorID: 0xFFF1, ProductID: 0x8000, Discovery: DiscoveryBLE, Discriminator: 3840, Passcode: 20202021}},
	{"MT:-24J0IRV01KA0648G00", Payload{VendorID: 0xFFF1, ProductID: 0x8001, Discovery: DiscoveryOnNetwork, Discriminator: 3841, Passcode: 20202021}},
	{"MT:-24J0AFN00KA0648G00", Payload{VendorID: 0xFFF1, ProductID: 0x8001, Discovery: DiscoveryOnNetwork, Discriminator: 3840, Passcode: 20202021}},
	{"MT:K6KT1SJF12MGVH7SR00", Payload{VendorID: 4442, ProductID: 71, Flow: FlowCustom, Discovery: DiscoveryBLE | DiscoveryOnNetwork, Discriminator: 1234, Passcode: 34567890}},
}

var manualVectors = []struct {
	code string
	p    Payload
}{
	{"34970112332", Payload{Discriminator: 15 << 8, ShortOnly: true, Passcode: 20202021}},
	{"34915300005", Payload{Discriminator: 3841 &^ 0xFF, ShortOnly: true, Passcode: 1}},
	{"35759861036", Payload{Discriminator: 4095 &^ 0xFF, ShortOnly: true, Passcode: 99999998}},
	{"514034210904442000711", Payload{VendorID: 4442, ProductID: 71, Flow: FlowCustom, Discriminator: 1234 &^ 0xFF, ShortOnly: true, Passcode: 34567890}},
}

func same(a, b *Payload) bool {
	return a.Version == b.Version && a.VendorID == b.VendorID && a.ProductID == b.ProductID &&
		a.Flow == b.Flow && a.Discovery == b.Discovery && a.Discriminator == b.Discriminator &&
		a.ShortOnly == b.ShortOnly && a.Passcode == b.Passcode && bytes.Equal(a.Extra, b.Extra)
}

func TestQRCode(t *testing.T) {
	for _, v := range qrVectors {
		p, err := Parse(v.code)
		if err != nil || !same(p, &v.p) {
			t.Fatalf("parse %s: %+v %v", v.code, p, err)
		}
		got, err := v.p.QRCode()
		if err != nil || got != v.code {
			t.Fatalf("encode %+v: %s %v, want %s", v.p, got, err, v.code)
		}
	}
	// Optional TLV data follows the fixed fields.
	p := qrVectors[0].p
	p.Extra = []byte{0x15, 0x2C, 0x00, 0x01, 0x41, 0x18}
	code, err := p.QRCode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseQR(code)
	if err != nil || !same(back, &p) {
		t.Fatalf("extra data: %+v %v", back, err)
	}
}

func TestManualCode(t *testing.T) {
	for _, v := range manualVectors {
		p, err := Parse(v.code)
		if err != nil || !same(p, &v.p) {
			t.Fatalf("parse %s: %+v %v", v.code, p, err)
		}
		got, err := v.p.ManualCode()
		if err != nil || got != v.code {
			t.Fatalf("encode %+v: %s %v, want %s", v.p, got, err, v.code)
		}
	}
	// A QR payload gives the same manual code, from the short
	// discriminator.
	p := qrVectors[0].p
	if code, _ := p.ManualCode(); code != "34970112332" {
		t.Fatalf("manual code of a QR payload: %s", code)
	}
	if p, err := Parse("3497-011-2332"); err != nil || p.Passcode != 20202021 {
		t.Fatalf("dashes: %+v %v", p, err)
	}
}

func TestInvalid(t *testing.T) {
	for _, code := range []string{
		"34970112333",            // check digit
		"3497011233",             // length
		"349701123322",           // length
		"74970112332",            // chunk 1 out of range
		"x4970112332",            // not a digit
		"MT:Y.K9042C00KA0648G0",  // base-38 length
		"MT:Y.K9042C00KA0648G0a", // base-38 character
		"MT:Y.K9042C00",          // too short
		"MT:..........",          // base-38 overflow
	} {
		if _, err := Parse(code); err == nil {
			t.Errorf("%s accepted", code)
		}
	}
	for _, pin := range []uint32{0, 11111111, 12345678, 99999999, 1 << 27} {
		p := Payload{Discriminator: 3840, Passcode: pin}
		if _, err := p.QRCode(); err == nil {
			t.Errorf("passcode %d accepted", pin)
		}
	}
	short := Payload{Discriminator: 15 << 8, ShortOnly: true, Passcode: 20202021}
	if _, err := short.QRCode(); err == nil {
		t.Error("QR code from a short discriminator")
	}
}

func FuzzParse(f *testing.F) {
	for _, v := range qrVectors {
		f.Add(v.code)
	}
	for _, v := range manualVectors {
		f.Add(v.code)
	}
	f.Fuzz(func(t *testing.T, code string) {
		p, err := Parse(code)
		if err != nil {
			return
		}
		var again string
		if p.ShortOnly {
			again, err = p.ManualCode()
		} else {
			again, err = p.QRCode()
		}
		if err != nil {
			t.Fatalf("%q parsed to %+v, which does not encode: %v", code, p, err)
		}
		if q, err := Parse(again); err != nil || !same(p, q) {
			t.Fatalf("%q: %+v re-encoded as %q: %+v %v", code, p, again, q, err)
		}
	})
}
