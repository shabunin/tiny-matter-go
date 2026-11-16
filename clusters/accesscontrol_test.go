package clusters

import "testing"

func TestValidCASESubject(t *testing.T) {
	for _, c := range []struct {
		id   uint64
		want bool
	}{
		{1, true},
		{0x1B669, true},
		{0xFFFF_FFEF_FFFF_FFFF, true},
		{0, false},
		{0xFFFF_FFF0_0000_0000, false}, // reserved
		{0xFFFF_FFFF_FFFF_0000, false}, // group node IDs
		{0xFFFF_FFFF_FFFF_FFFF, false},
		{0xFFFF_FFFD_0001_0001, true},  // CAT 1, version 1
		{0xFFFF_FFFD_0000_0000, false}, // CAT version 0
		{0xFFFF_FFFB_0000_0001, false}, // PAKE key IDs
	} {
		if got := validCASESubject(c.id); got != c.want {
			t.Errorf("validCASESubject(%#x) = %v", c.id, got)
		}
	}
}

func TestValidACLTarget(t *testing.T) {
	u32 := func(v uint32) *uint32 { return &v }
	u16 := func(v uint16) *uint16 { return &v }
	for _, c := range []struct {
		name string
		t    ACLTarget
		want bool
	}{
		{"empty", ACLTarget{}, false},
		{"cluster", ACLTarget{Cluster: u32(6)}, true},
		{"endpoint", ACLTarget{Endpoint: u16(1)}, true},
		{"device type", ACLTarget{DeviceType: u32(0x010D)}, true},
		{"cluster and endpoint", ACLTarget{Cluster: u32(6), Endpoint: u16(1)}, true},
		{"endpoint and device type", ACLTarget{Endpoint: u16(22), DeviceType: u32(33)}, false},
		{"manufacturer cluster", ACLTarget{Cluster: u32(0xFFF1_FC00)}, true},
		{"cluster suffix gap", ACLTarget{Cluster: u32(0x8000)}, false},
		{"cluster vendor 0xFFFF", ACLTarget{Cluster: u32(0xFFFF_0006)}, false},
		{"device type suffix", ACLTarget{DeviceType: u32(0xC000)}, false},
	} {
		if got := validACLTarget(c.t); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
