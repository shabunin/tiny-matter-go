package thread

import (
	"encoding/hex"
	"errors"
	"testing"
)

// otbrDataset is an active dataset as `ot-ctl dataset active -x` prints it
// (the OpenThread example network: channel 15, PAN ID 0x1234, network
// "OpenThread-1234").
const otbrDataset = "0e080000000000010000" + // active timestamp 1
	"000300000f" + // channel 15
	"35060004001fffe0" + // channel mask
	"0208dead00beef00cafe" + // extended PAN ID
	"0708fd000db800a00000" + // mesh-local prefix fd00:db8:a0::/64
	"051000112233445566778899aabbccddeeff" + // network key
	"030f4f70656e5468726561642d31323334" + // network name
	"010212 34" + // PAN ID
	"041004a1af8b3e0b5b0b8a2e4a8e8b0d5f6c" + // PSKc
	"0c0402a0f7f8" // security policy

func dataset(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(stripSpaces(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func TestParseDataset(t *testing.T) {
	b := dataset(t, otbrDataset)
	d, err := ParseDataset(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Channel != 15 || d.PANID != 0x1234 || d.NetworkName != "OpenThread-1234" ||
		hex.EncodeToString(d.ExtendedPANID[:]) != "dead00beef00cafe" ||
		hex.EncodeToString(d.MeshLocalPrefix[:]) != "fd000db800a00000" ||
		hex.EncodeToString(d.NetworkKey[:]) != "00112233445566778899aabbccddeeff" ||
		d.ActiveTimestamp != 0x10000 || !d.Has(TypeChannelMask) || !d.Has(TypeSecurityPolicy) || d.Has(TypeDelayTimer) {
		t.Errorf("parsed %+v", d)
	}
	if &d.Raw[0] != &b[0] || len(d.Raw) != len(b) {
		t.Error("Raw is not the input")
	}
}

func TestParseDatasetErrors(t *testing.T) {
	full := dataset(t, otbrDataset)
	for name, b := range map[string][]byte{
		"truncated header": full[:len(full)-len("0c0402a0f7f8")/2+1],
		"truncated value":  full[:len(full)-1],
		"extended length":  append(append([]byte{}, full...), 0x10, 0xFF, 0, 1, 0),
		"channel page 1":   dataset(t, "000301000f"+otbrDataset[len("0e080000000000010000000300000f"):]),
		"short PAN ID":     append(append([]byte{}, full...), TypePANID, 1, 0x12),
		"too long":         make([]byte, MaxDatasetLen+1),
	} {
		if _, err := ParseDataset(b); !errors.Is(err, ErrDataset) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// No network key: a device could not join.
	noKey := dataset(t, "000300000f"+"0208dead00beef00cafe"+"01021234")
	if _, err := ParseDataset(noKey); !errors.Is(err, ErrIncomplete) {
		t.Errorf("no network key: err = %v", err)
	}
	if _, err := ParseDataset(nil); !errors.Is(err, ErrIncomplete) {
		t.Errorf("empty: err = %v", err)
	}
}
