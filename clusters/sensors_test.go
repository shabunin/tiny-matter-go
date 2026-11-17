package clusters

import (
	"slices"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// read returns the value of attr, or the status.
func read(t *testing.T, c im.Cluster, attr uint32) (*tlv.Reader, im.Status) {
	t.Helper()
	w := tlv.NewWriter(nil)
	if st := c.ReadAttribute(&im.Context{}, attr, w, tlv.Anonymous); st != im.Success {
		return nil, st
	}
	r := tlv.NewReader(w.Bytes())
	if err := r.Next(); err != nil {
		t.Fatal(err)
	}
	return r, im.Success
}

func readInt(t *testing.T, c im.Cluster, attr uint32) (v int64, null bool) {
	t.Helper()
	r, st := read(t, c, attr)
	if st != im.Success {
		t.Fatalf("read %#x: %#x", attr, st)
	}
	if r.IsNull() {
		return 0, true
	}
	if r.Type() == tlv.TypeInt {
		v, _ = r.Int()
		return v, false
	}
	u, err := r.Uint()
	if err != nil {
		t.Fatal(err)
	}
	return int64(u), false
}

func TestMeasurement(t *testing.T) {
	n := im.NewNode(1)
	m := NewTemperatureMeasurement(Value(-4000), Value(8500))
	n.AddCluster(n.AddEndpoint(1, DeviceTypeTemperatureSensor), m)
	changes := 0
	n.OnChange = func(p im.ConcretePath) { changes++ }

	if _, null := readInt(t, m, 0); !null {
		t.Error("MeasuredValue not null before a reading")
	}
	m.Set(n, 1, Value(-1250))
	if v, _ := readInt(t, m, 0); v != -1250 {
		t.Errorf("MeasuredValue %d", v)
	}
	if v, _ := readInt(t, m, 1); v != -4000 {
		t.Errorf("MinMeasuredValue %d", v)
	}
	m.Set(n, 1, Value(-1250)) // unchanged: no report
	m.Set(n, 1, Value(99999)) // clamped to the range
	if v, _ := readInt(t, m, 0); v != 8500 || changes != 2 {
		t.Errorf("clamped %d, %d changes", v, changes)
	}
	if _, st := read(t, m, 3); st != im.UnsupportedAttribute || slices.Contains(m.Attributes(), 3) {
		t.Error("Tolerance without one")
	}
	m.Tolerance = 50
	if v, _ := readInt(t, m, 3); v != 50 || !slices.Contains(m.Attributes(), 3) {
		t.Error("Tolerance")
	}

	// Unsigned clusters encode unsigned; null ranges read null.
	h := NewHumidityMeasurement(Null, Value(10000))
	n.AddCluster(n.AddEndpoint(2, DeviceTypeHumiditySensor), h)
	h.Set(n, 2, Value(4550))
	if r, _ := read(t, h, 0); r.Type() != tlv.TypeUint {
		t.Errorf("humidity encoded as %v", r.Type())
	}
	if _, null := readInt(t, h, 1); !null {
		t.Error("MinMeasuredValue not null")
	}
	p := NewPressureMeasurement(Value(300), Value(1100))
	p.Set(n, 1, Value(1013))
	if r, _ := read(t, p, 0); r.Type() != tlv.TypeInt || p.Revision() != 3 {
		t.Errorf("pressure encoded as %v, revision %d", r.Type(), p.Revision())
	}
	if h.ID() != IDRelativeHumidityMeasurement || NewIlluminanceMeasurement(Null, Null).ID() != IDIlluminanceMeasurement {
		t.Error("cluster IDs")
	}
}

func TestBooleanStateAndOccupancy(t *testing.T) {
	n := im.NewNode(1)
	now := time.Unix(1000, 0)
	b := &BooleanState{}
	o := &OccupancySensing{Sensors: OccupancyPassiveInfrared}
	n.AddCluster(n.AddEndpoint(1, DeviceTypeContactSensor), b)
	n.AddCluster(n.AddEndpoint(2, DeviceTypeOccupancySensor), o)
	var events []im.ConcreteEventPath
	n.OnEvent = func(p im.ConcreteEventPath) { events = append(events, p) }

	b.Set(n, 1, now, true)
	b.Set(n, 1, now, true) // no change, no event
	if r, _ := read(t, b, 0); r == nil {
		t.Fatal("StateValue")
	} else if v, _ := r.Bool(); !v {
		t.Error("StateValue false")
	}
	o.Set(n, 2, now, true)
	if v, _ := readInt(t, o, 0); v != 1 {
		t.Errorf("Occupancy %d", v)
	}
	if len(events) != 2 || events[0].Cluster != IDBooleanState || events[1].Cluster != IDOccupancySensing {
		t.Errorf("events %+v", events)
	}

	// The deprecated sensor type attributes follow the features.
	for _, c := range []struct {
		sensors      uint32
		enum, bitmap int64
	}{
		{OccupancyPassiveInfrared, 0, 1},
		{OccupancyUltrasonic, 1, 2},
		{OccupancyPassiveInfrared | OccupancyUltrasonic, 2, 3},
		{OccupancyPhysicalContact, 3, 4},
		{OccupancyRadar, 0, 1},
		{OccupancyRadar | OccupancyUltrasonic, 2, 3},
	} {
		o := &OccupancySensing{Sensors: c.sensors}
		e, _ := readInt(t, o, 1)
		bm, _ := readInt(t, o, 2)
		if e != c.enum || bm != c.bitmap || o.FeatureMap() != c.sensors {
			t.Errorf("sensors %#x: type %d bitmap %d", c.sensors, e, bm)
		}
	}
}

func TestBridgedDeviceBasicInformation(t *testing.T) {
	b := &BridgedDeviceBasicInformation{ProductName: "Door", UniqueID: "u1", SoftwareVersionString: "1.2"}
	want := []uint32{biProductName, biNodeLabel, biSoftwareVersion, biSoftwareVersionString, bbiReachable, bbiUniqueID}
	if got := b.Attributes(); !slices.Equal(got, want) {
		t.Fatalf("attributes %#x, want %#x", got, want)
	}
	if _, st := read(t, b, biVendorName); st != im.UnsupportedAttribute {
		t.Errorf("VendorName: %#x", st)
	}
	if v, _ := readInt(t, b, biSoftwareVersion); v != 0 {
		t.Errorf("SoftwareVersion %d", v)
	}
	write := func(attr uint32, s string) im.Status {
		w := tlv.NewWriter(nil)
		w.PutString(tlv.Anonymous, s)
		r := tlv.NewReader(w.Bytes())
		r.Next()
		return b.WriteAttribute(&im.Context{}, attr, false, r)
	}
	if st := write(biNodeLabel, "Back door"); st != im.Success || b.NodeLabel != "Back door" {
		t.Errorf("NodeLabel write %#x", st)
	}
	if st := write(biNodeLabel, "a label that is longer than thirty-two bytes"); st != im.ConstraintError {
		t.Errorf("long NodeLabel %#x", st)
	}
	if st := write(bbiUniqueID, "x"); st != im.UnsupportedWrite {
		t.Errorf("UniqueID write %#x", st)
	}
	if st := write(biVendorName, "x"); st != im.UnsupportedAttribute {
		t.Errorf("VendorName write %#x", st)
	}
	if b.WritePrivilege(biNodeLabel) != im.Manage {
		t.Error("NodeLabel needs Manage")
	}
}

func TestForgetEndpoint(t *testing.T) {
	n := im.NewNode(1)
	g := &GroupData{Groups: []GroupInfo{
		{FabricIndex: 1, GroupID: 1, Endpoints: []uint16{3, 4}},
		{FabricIndex: 1, GroupID: 2, Endpoints: []uint16{4}},
		{FabricIndex: 2, GroupID: 1, Endpoints: []uint16{4, 5}},
	}}
	changes := 0
	g.OnChange = func() { changes++ }
	if !g.ForgetEndpoint(n, 4) || changes != 1 {
		t.Fatalf("ForgetEndpoint: %d changes", changes)
	}
	if len(g.Groups) != 2 || !slices.Equal(g.Groups[0].Endpoints, []uint16{3}) || !slices.Equal(g.Groups[1].Endpoints, []uint16{5}) {
		t.Fatalf("groups %+v", g.Groups)
	}
	if g.ForgetEndpoint(n, 9) || changes != 1 {
		t.Error("ForgetEndpoint of a non-member")
	}
}
