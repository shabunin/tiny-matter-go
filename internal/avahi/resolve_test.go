package avahi

import (
	"testing"
	"time"
)

func TestParseBrowse(t *testing.T) {
	out := []byte(`+;wlp4s0;IPv6;8899A705A50F2D2C-0000000000000002;_matter._tcp;local
=;wlp4s0;IPv6;8899A705A50F2D2C-0000000000000002;_matter._tcp;local;a.local;fe80::96b9:7eff:fe8c:6b84;5540;"T=0"
=;wlp4s0;IPv4;8899A705A50F2D2C-0000000000000002;_matter._tcp;local;a.local;192.168.2.40;5540;"T=0"
=;wlp4s0;IPv6;38B77A29F07553EA-0000000000000001;_matter._tcp;local;b.local;fe80::32ed:a0ff:fec8:8734;5541;"T=0"
`)
	found := parseBrowse(out, time.Unix(0, 0))
	if a := found["8899A705A50F2D2C-0000000000000002"].addr.String(); a != "192.168.2.40:5540" {
		t.Errorf("node 2 at %s, want its IPv4 address", a)
	}
	if a := found["38B77A29F07553EA-0000000000000001"].addr.String(); a != "[fe80::32ed:a0ff:fec8:8734%wlp4s0]:5541" {
		t.Errorf("node 1 at %s, want a zoned link-local address", a)
	}
}
