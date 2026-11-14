package dbus

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestEncodeDict(t *testing.T) {
	var e encoder
	if err := e.value("a{sv}", map[string]Variant{"Transport": {"s", "le"}}, 0); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		27, 0, 0, 0, // array length, from the first entry
		0, 0, 0, 0, // padding to the 8-aligned entry, not counted
		9, 0, 0, 0, 'T', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', 0,
		1, 's', 0, // variant signature
		0, 0, 0, // padding to the string
		2, 0, 0, 0, 'l', 'e', 0,
	}
	if !bytes.Equal(e.b, want) {
		t.Errorf("got  % x\nwant % x", e.b, want)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	m := &Message{
		Type: TypeSignal, Path: "/org/bluez/hci0/dev_32_ED_A0_C8_87_36",
		Interface: "org.freedesktop.DBus.Properties", Member: "PropertiesChanged",
		Sender: "", Signature: "sa{sv}asya(yt)a{qv}xd",
		Body: []any{
			"org.bluez.Device1",
			map[string]Variant{
				"RSSI":        {"n", int16(-60)},
				"ServiceData": {"a{sv}", map[string]Variant{"0000fff6-0000-1000-8000-00805f9b34fb": {"ay", []byte{0, 0, 15, 0xF1, 0xFF, 0, 0x80, 0}}}},
				"UUIDs":       {"as", []string{"a", "b"}},
				"Connected":   {"b", true},
				"Path":        {"o", ObjectPath("/x")},
			},
			[]string{"Name"},
			byte(7),
			[]any{[]any{byte(1), uint64(1 << 40)}, []any{byte(2), uint64(3)}},
			map[uint16]Variant{0x0123: {"ay", []byte{1, 2}}},
			int64(-5),
			2.5,
		},
	}
	b, err := m.encode(42)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != 42 || got.Path != m.Path || got.Member != m.Member || got.Signature != m.Signature {
		t.Fatalf("header: %+v", got)
	}
	props := got.Body[1].(map[string]any)
	if v := props["RSSI"].(Variant); v.Value != int16(-60) {
		t.Errorf("RSSI = %v", v)
	}
	sd := props["ServiceData"].(Variant).Value.(map[string]any)
	if v := sd["0000fff6-0000-1000-8000-00805f9b34fb"].(Variant).Value; !bytes.Equal(v.([]byte), []byte{0, 0, 15, 0xF1, 0xFF, 0, 0x80, 0}) {
		t.Errorf("service data = %v", v)
	}
	if v := props["UUIDs"].(Variant).Value; !reflect.DeepEqual(v, []any{"a", "b"}) {
		t.Errorf("UUIDs = %v", v)
	}
	if v := props["Path"].(Variant).Value; v != ObjectPath("/x") {
		t.Errorf("Path = %v", v)
	}
	if !reflect.DeepEqual(got.Body[2], []any{"Name"}) || got.Body[3] != byte(7) {
		t.Errorf("body = %v", got.Body)
	}
	if !reflect.DeepEqual(got.Body[4], []any{[]any{byte(1), uint64(1 << 40)}, []any{byte(2), uint64(3)}}) {
		t.Errorf("structs = %v", got.Body[4])
	}
	if v := got.Body[5].(map[any]any)[uint16(0x0123)].(Variant).Value; !bytes.Equal(v.([]byte), []byte{1, 2}) {
		t.Errorf("a{qv} = %v", got.Body[5])
	}
	if got.Body[6] != int64(-5) || got.Body[7] != 2.5 {
		t.Errorf("x, d = %v, %v", got.Body[6], got.Body[7])
	}
}

func TestEncodeErrors(t *testing.T) {
	var e encoder
	for _, c := range []struct {
		sig  string
		vals []any
	}{
		{"s", []any{1}},
		{"y", []any{300}},
		{"u", []any{-1}},
		{"(is)", []any{[]any{int32(1)}}},
		{"ss", []any{"one"}},
		{"a{", []any{nil}},
	} {
		if err := e.args(c.sig, c.vals); err == nil {
			t.Errorf("%s %v: no error", c.sig, c.vals)
		}
	}
}

func TestTruncated(t *testing.T) {
	m := &Message{Type: TypeMethodReturn, ReplySerial: 3, Signature: "as", Body: []any{[]string{"x", "y"}}}
	b, err := m.encode(1)
	if err != nil {
		t.Fatal(err)
	}
	for n := range len(b) {
		if _, err := readMessage(bytes.NewReader(b[:n])); err == nil {
			t.Fatalf("%d of %d bytes: no error", n, len(b))
		}
	}
}

// TestSystemBus talks to the real system bus, if there is one.
func TestSystemBus(t *testing.T) {
	c, err := SystemBus()
	if err != nil {
		t.Skip("no system bus:", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c.Name() == "" {
		t.Error("no unique name")
	}
	body, err := c.Call(ctx, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range body[0].([]any) {
		found = found || n == "org.freedesktop.DBus"
	}
	if !found {
		t.Errorf("ListNames = %v", body)
	}
	var de *Error
	_, err = c.Call(ctx, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NoSuchMethod", "")
	if !errors.As(err, &de) || de.Name != "org.freedesktop.DBus.Error.UnknownMethod" {
		t.Errorf("unknown method: %v", err)
	}

	// A second connection makes the bus announce its name.
	if err := c.AddMatch(ctx, "type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'"); err != nil {
		t.Fatal(err)
	}
	c2, err := SystemBus()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for {
		select {
		case m := <-c.Signals():
			if m.Member == "NameOwnerChanged" && len(m.Body) == 3 && m.Body[0] == c2.Name() {
				return
			}
		case <-ctx.Done():
			t.Fatal("no NameOwnerChanged for the second connection")
		}
	}
}
