package clusters

import (
	"strings"
	"testing"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// write writes the value put encodes to attr of c on endpoint 1 of n.
func write(t *testing.T, n *im.Node, c im.Cluster, attr uint32, put func(w *tlv.Writer)) im.Status {
	t.Helper()
	w := tlv.NewWriter(nil)
	put(w)
	r := tlv.NewReader(w.Bytes())
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	return c.WriteAttribute(&im.Context{Node: n, Endpoint: 1}, attr, false, r)
}

func labels(ls ...string) func(w *tlv.Writer) {
	return func(w *tlv.Writer) {
		w.StartArray(tlv.Anonymous)
		for i := 0; i+1 < len(ls); i += 2 {
			w.StartStruct(tlv.Anonymous)
			w.PutString(tlv.ContextTag(0), ls[i])
			w.PutString(tlv.ContextTag(1), ls[i+1])
			w.EndContainer()
		}
		w.EndContainer()
	}
}

func TestUserLabel(t *testing.T) {
	n := im.NewNode(1)
	u := &UserLabel{}
	n.AddCluster(n.AddEndpoint(1), u)
	if u.WritePrivilege(0) != im.Manage {
		t.Error("labels written without Manage")
	}
	if st := write(t, n, u, 0, labels("room", "kitchen", "floor", "1")); st != im.Success {
		t.Fatalf("write: %#x", st)
	}
	long := strings.Repeat("x", 17)
	for _, bad := range [][]string{{long, "v"}, {"l", long}} {
		if st := write(t, n, u, 0, labels(bad...)); st != im.ConstraintError {
			t.Errorf("label %q: %#x", bad, st)
		}
	}
	var many []string
	for range MaxUserLabels + 1 {
		many = append(many, "l", "v")
	}
	if st := write(t, n, u, 0, labels(many...)); st != im.ResourceExhausted {
		t.Errorf("%d labels: %#x", MaxUserLabels+1, st)
	}
	if len(u.Labels) != 2 || u.Labels[1] != (Label{"floor", "1"}) {
		t.Fatalf("labels after failed writes: %v", u.Labels)
	}

	w := tlv.NewWriter(nil)
	u.EncodeState(w, tlv.Anonymous)
	r := tlv.NewReader(w.Bytes())
	r.Next()
	u2 := &UserLabel{}
	if err := u2.DecodeState(r); err != nil || len(u2.Labels) != 2 || u2.Labels[0] != (Label{"room", "kitchen"}) {
		t.Fatalf("restored %v, %v", u2.Labels, err)
	}
}

func TestLocalization(t *testing.T) {
	n := im.NewNode(1)
	lc := &LocalizationConfiguration{ActiveLocale: "en-US", SupportedLocales: []string{"en-US", "de-DE"}}
	tf := &TimeFormatLocalization{HourFormat: Hour24, CalendarTypes: []uint8{4, 7}, ActiveCalendar: 4}
	ul := &UnitLocalization{TemperatureUnit: Celsius, SupportedUnits: []uint8{Celsius, Fahrenheit}}
	n.AddCluster(n.AddEndpoint(1), lc, tf, ul)
	str := func(s string) func(w *tlv.Writer) { return func(w *tlv.Writer) { w.PutString(tlv.Anonymous, s) } }
	num := func(v uint64) func(w *tlv.Writer) { return func(w *tlv.Writer) { w.PutUint(tlv.Anonymous, v) } }

	for _, c := range []struct {
		name    string
		c       im.Cluster
		attr    uint32
		put     func(w *tlv.Writer)
		want    im.Status
		applied func() bool
	}{
		{"supported locale", lc, 0, str("de-DE"), im.Success, func() bool { return lc.ActiveLocale == "de-DE" }},
		{"unsupported locale", lc, 0, str("fr-FR"), im.ConstraintError, func() bool { return lc.ActiveLocale == "de-DE" }},
		{"SupportedLocales", lc, 1, str("x"), im.UnsupportedWrite, nil},
		{"12-hour clock", tf, 0, num(Hour12), im.Success, func() bool { return tf.HourFormat == Hour12 }},
		{"bad hour format", tf, 0, num(7), im.ConstraintError, func() bool { return tf.HourFormat == Hour12 }},
		{"supported calendar", tf, 1, num(7), im.Success, func() bool { return tf.ActiveCalendar == 7 }},
		{"unsupported calendar", tf, 1, num(1), im.ConstraintError, func() bool { return tf.ActiveCalendar == 7 }},
		{"Fahrenheit", ul, 0, num(Fahrenheit), im.Success, func() bool { return ul.TemperatureUnit == Fahrenheit }},
		{"Kelvin unsupported", ul, 0, num(Kelvin), im.ConstraintError, func() bool { return ul.TemperatureUnit == Fahrenheit }},
	} {
		if st := write(t, n, c.c, c.attr, c.put); st != c.want {
			t.Errorf("%s: %#x, want %#x", c.name, st, c.want)
		}
		if c.applied != nil && !c.applied() {
			t.Errorf("%s: not applied as expected", c.name)
		}
	}
	if tf.FeatureMap() != 1 || (&TimeFormatLocalization{}).FeatureMap() != 0 {
		t.Error("CALFMT feature")
	}
	if len((&TimeFormatLocalization{}).Attributes()) != 1 {
		t.Error("calendar attributes without CALFMT")
	}
}

func TestPowerSource(t *testing.T) {
	bat := &PowerSource{Rechargeable: true, State: func() PowerState {
		return PowerState{Status: PowerActive, BatVoltage: 3900, BatPercent: 0xFF, BatChargeState: BatCharging}
	}}
	if bat.FeatureMap() != 6 {
		t.Errorf("FeatureMap %#x", bat.FeatureMap())
	}
	if v, _ := readInt(t, bat, psBatVoltage); v != 3900 {
		t.Errorf("BatVoltage %d", v)
	}
	if _, null := readInt(t, bat, psBatPercentRemaining); !null {
		t.Error("unknown BatPercentRemaining not null")
	}
	if v, _ := readInt(t, bat, psBatChargeState); v != BatCharging {
		t.Errorf("BatChargeState %d", v)
	}
	if _, st := read(t, bat, psWiredCurrentType); st != im.UnsupportedAttribute {
		t.Errorf("a battery reads WiredCurrentType: %#x", st)
	}
	mains := &PowerSource{Wired: true}
	if mains.FeatureMap() != 1 {
		t.Errorf("FeatureMap %#x", mains.FeatureMap())
	}
	if _, st := read(t, mains, psBatChargeLevel); st != im.UnsupportedAttribute {
		t.Errorf("mains reads BatChargeLevel: %#x", st)
	}
}
