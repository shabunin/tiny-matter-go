package datamodel

import (
	"strings"
	"testing"

	"github.com/shabunin/tiny-matter-go/tlv"
)

func TestModel(t *testing.T) {
	m := Default()
	if len(m.Clusters) < 100 {
		t.Fatalf("%d clusters", len(m.Clusters))
	}
	onoff := m.Cluster("onoff")
	if onoff == nil || onoff.ID != 6 || m.Cluster("0x0006") != onoff || m.Cluster("6") != onoff || m.Cluster("On/Off") != onoff {
		t.Fatal("OnOff lookup")
	}
	a := onoff.Attribute("OnOff")
	if a == nil || a.ID != 0 || a.Type.Kind != KindBool || a.Writable {
		t.Errorf("onOff attribute %+v", a)
	}
	if a := onoff.Attribute("startUpOnOff"); a == nil || !a.Writable || !a.Nullable || a.Type.Kind != KindEnum {
		t.Errorf("startUpOnOff %+v", a)
	}
	if c := onoff.Command("toggle"); c == nil || c.ID != 2 || c.Request != nil || c.Response != nil {
		t.Errorf("Toggle %+v", c)
	}
	lvl := m.Cluster("LevelControl").Command("MoveToLevel")
	if lvl == nil || len(lvl.Request.Fields) != 4 || lvl.Request.Fields[0].Name != "level" {
		t.Fatalf("MoveToLevel %+v", lvl)
	}
	oc := m.Cluster("OperationalCredentials")
	csr := oc.Command("CSRRequest")
	if csr == nil || csr.Response == nil || csr.ResponseID != 5 || oc.Response(5) != csr {
		t.Errorf("CSRRequest %+v", csr)
	}
	ac := m.Cluster("AdministratorCommissioning").Command("OpenCommissioningWindow")
	if ac == nil || !ac.Timed {
		t.Errorf("OpenCommissioningWindow %+v", ac)
	}
	if e := m.Cluster("Switch").Event("InitialPress"); e == nil || e.ID != 1 || e.Priority != "info" || len(e.Fields) != 1 {
		t.Errorf("InitialPress %+v", e)
	}
	acl := m.Cluster("AccessControl").Attribute("acl")
	if acl == nil || !acl.List || acl.Type.Kind != KindStruct || !acl.Type.FabricScoped {
		t.Errorf("ACL %+v", acl)
	}
	// Every field has a type.
	for _, c := range m.Clusters {
		for _, a := range c.Attributes {
			if a.Type == nil || a.Type.Kind == KindUnknown {
				t.Errorf("%s.%s: type %v", c.Name, a.Name, a.Type)
			}
		}
	}
}

func encode(t *testing.T, f *Field, s string) []byte {
	t.Helper()
	w := tlv.NewWriter(nil)
	if err := Encode(w, tlv.Anonymous, f, s); err != nil {
		t.Fatalf("Encode %q: %v", s, err)
	}
	return w.Bytes()
}

func TestRoundTrip(t *testing.T) {
	m := Default()
	for _, tc := range []struct{ cluster, attr, in, out string }{
		{"OnOff", "onOff", "on", "true"},
		{"OnOff", "startUpOnOff", "Toggle", "2 (Toggle)"},
		{"OnOff", "startUpOnOff", "null", "null"},
		{"OnOff", "featureMap", "5", "0x5"},
		{"BasicInformation", "nodeLabel", "kitchen light", `"kitchen light"`},
		{"BasicInformation", "vendorID", "0xFFF1", "0xfff1"},
		{"LevelControl", "options", "ExecuteIfOff|CoupleColorTempToLevel", "0x3 (ExecuteIfOff|CoupleColorTempToLevel)"},
		{"TemperatureMeasurement", "measuredValue", "-150", "-150"},
		{"AccessControl", "acl", `[{"privilege":"Administer","authMode":2,"subjects":[112233],"targets":null,"fabricIndex":1}]`,
			"[{privilege: 5 (Administer), authMode: 2 (CASE), subjects: [112233], targets: null, fabricIndex: 1}]"},
		{"GeneralDiagnostics", "networkInterfaces", `[{"name":"wlan0","isOperational":true,"offPremiseServicesReachableIPv4":null,"offPremiseServicesReachableIPv6":null,"hardwareAddress":"30eda0c88734","IPv4Addresses":["c0a8021a"],"IPv6Addresses":[],"type":"WiFi"}]`,
			`[{name: "wlan0", isOperational: true, offPremiseServicesReachableIPv4: null, offPremiseServicesReachableIPv6: null, hardwareAddress: hex:30eda0c88734, IPv4Addresses: [hex:c0a8021a], IPv6Addresses: [], type: 1 (WiFi)}]`},
	} {
		c := m.Cluster(tc.cluster)
		a := c.Attribute(tc.attr)
		if a == nil {
			t.Fatalf("%s.%s missing", tc.cluster, tc.attr)
		}
		if got := Format(encode(t, &a.Field, tc.in), &a.Field); got != tc.out {
			t.Errorf("%s.%s %s: got %s, want %s", tc.cluster, tc.attr, tc.in, got, tc.out)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	m := Default()
	for _, tc := range []struct{ cluster, attr, in, err string }{
		{"OnOff", "onOff", "maybe", "not a boolean"},
		{"OnOff", "startUpOnOff", "Sideways", "one of Off, On, Toggle"},
		{"OnOff", "onTime", "-1", "not a number"},
		{"AccessControl", "acl", `[{"bogus":1}]`, `no field "bogus"`},
		{"AccessControl", "acl", `{`, "want JSON"},
	} {
		a := m.Cluster(tc.cluster).Attribute(tc.attr)
		err := Encode(tlv.NewWriter(nil), tlv.Anonymous, &a.Field, tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s.%s %q: %v, want %q", tc.cluster, tc.attr, tc.in, err, tc.err)
		}
	}
}

func TestEncodeFields(t *testing.T) {
	cmd := Default().Cluster("LevelControl").Command("MoveToLevel")
	fields := func(args ...string) (string, error) {
		w := tlv.NewWriter(nil)
		w.StartStruct(tlv.Anonymous)
		if err := EncodeFields(w, cmd.Request, args); err != nil {
			return "", err
		}
		w.EndContainer()
		return FormatFields(w.Bytes(), cmd.Request.Fields), nil
	}
	want := "{level: 128, transitionTime: 10, optionsMask: 0x0, optionsOverride: 0x0}"
	for _, args := range [][]string{
		{"128", "10", "0", "0"},
		{"optionsOverride=0", "level=128", "TransitionTime=10", "optionsMask=0"},
		{"128", "transitionTime=10", "optionsmask=0", "optionsoverride=0"},
	} {
		got, err := fields(args...)
		if err != nil || got != want {
			t.Errorf("%q: %s, %v", args, got, err)
		}
	}
	if _, err := fields("128"); err == nil || !strings.Contains(err.Error(), "missing transitionTime, optionsMask, optionsOverride") {
		t.Errorf("missing fields: %v", err)
	}
	if _, err := fields("128", "1", "0", "0", "9"); err == nil {
		t.Error("too many values accepted")
	}
	// Without a model: numbered fields, guessed types.
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	if err := EncodeFields(w, nil, []string{"0=5", "1=hex:0102", "2=text", "3=-2", "4=[1,2]", `5={"0":true}`}); err != nil {
		t.Fatal(err)
	}
	w.EndContainer()
	if got, want := Format(w.Bytes(), nil), `{0: 5, 1: hex:0102, 2: "text", 3: -2, 4: [1, 2], 5: {0: true}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func FuzzFormat(f *testing.F) {
	m := Default()
	acl := &m.Cluster("AccessControl").Attribute("acl").Field
	f.Add([]byte{0x15, 0x24, 0x01, 0x05, 0x18})
	f.Fuzz(func(t *testing.T, b []byte) {
		Format(b, acl)
		Format(b, nil)
	})
}

func TestPrefixLookup(t *testing.T) {
	m := Default()
	if c := m.Cluster("basic"); c == nil || c.Name != "BasicInformation" {
		t.Errorf("basic: %v", c)
	}
	if c := m.Cluster("opcred"); c != nil {
		t.Errorf("opcred matched %s", c.Name)
	}
	if c := m.Cluster("operationalcred"); c == nil || c.ID != 0x3E {
		t.Errorf("operationalcred: %v", c)
	}
	lc := m.Cluster("LevelControl")
	if c := lc.Command("move"); c == nil || c.Name != "Move" {
		t.Errorf("move: %v", c) // exact beats prefix
	}
	if c := lc.Command("movetolevelw"); c == nil || c.Name != "MoveToLevelWithOnOff" {
		t.Errorf("movetolevelw: %v", c)
	}
	if a := m.Cluster("onoff").Attribute("on"); a != nil {
		t.Errorf("on matched %s", a.Name) // ambiguous: onOff, onTime
	}
}
