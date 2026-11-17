package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/im"
)

// kind is a device the host device can be (the -type flag).
type kind struct {
	deviceType im.DeviceType // advertised in DNS-SD
	product    string
	build      func(a *app)
}

var kinds = map[string]kind{
	"light":       {clusters.DeviceTypeExtendedColorLight, "Host Light", buildLight},
	"ctlight":     {clusters.DeviceTypeColorTemperatureLight, "Host CT Light", func(a *app) { a.light(1, 0, clusters.DeviceTypeColorTemperatureLight, clusters.ColorTemperature) }},
	"dimlight":    {clusters.DeviceTypeDimmableLight, "Host Dimmable Light", func(a *app) { a.light(1, 0, clusters.DeviceTypeDimmableLight, 0) }},
	"onofflight":  {clusters.DeviceTypeOnOffLight, "Host On/Off Light", func(a *app) { a.light(1, 0, clusters.DeviceTypeOnOffLight, 0) }},
	"plug":        {clusters.DeviceTypeOnOffPlugInUnit, "Host Plug", func(a *app) { a.plug(1, 0, false) }},
	"dimplug":     {clusters.DeviceTypeDimmablePlugIn, "Host Dimmable Plug", func(a *app) { a.plug(1, 0, true) }},
	"contact":     {clusters.DeviceTypeContactSensor, "Host Contact Sensor", func(a *app) { a.contact(1, 0) }},
	"occupancy":   {clusters.DeviceTypeOccupancySensor, "Host Occupancy Sensor", func(a *app) { a.occupancy(1, 0) }},
	"temperature": {clusters.DeviceTypeTemperatureSensor, "Host Temperature Sensor", func(a *app) { a.temperature(1, 0) }},
	"humidity":    {clusters.DeviceTypeHumiditySensor, "Host Humidity Sensor", func(a *app) { a.humidity(1, 0) }},
	"lightsensor": {clusters.DeviceTypeLightSensor, "Host Light Sensor", func(a *app) { a.lightSensor(1, 0) }},
	"pressure":    {clusters.DeviceTypePressureSensor, "Host Pressure Sensor", func(a *app) { a.pressure(1, 0) }},
	"bridge":      {clusters.DeviceTypeAggregator, "Host Bridge", buildBridge},
}

func kindNames() string {
	var names []string
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// app is the device's application: its endpoints and the standard input
// commands that work them.
type app struct {
	d       *device.Device
	cmds    chan<- string
	targets []target
	tickers []ticker
}

// target is a command an endpoint takes: the first word of a line on
// standard input, optionally after "@<endpoint>".
type target struct {
	ep   uint16
	name string
	help string
	run  func(now time.Time, args []string) error
}

type ticker struct {
	ep   uint16
	tick func(now time.Time) time.Time
}

func (a *app) handle(ep uint16, name, help string, run func(now time.Time, args []string) error) {
	a.targets = append(a.targets, target{ep, name, help, run})
}

// command runs one line of input.
func (a *app) command(now time.Time, line string) error {
	f := strings.Fields(line)
	var ep uint16
	if len(f) > 0 && strings.HasPrefix(f[0], "@") {
		v, err := strconv.ParseUint(f[0][1:], 10, 16)
		if err != nil {
			return fmt.Errorf("bad endpoint %q", f[0])
		}
		ep, f = uint16(v), f[1:]
	}
	if len(f) == 0 {
		return nil
	}
	switch f[0] {
	case "press", "release", "click", "long":
		f = append([]string{"button"}, f...)
	}
	for _, t := range a.targets {
		if t.name == f[0] && (ep == 0 || t.ep == ep) {
			return t.run(now, f[1:])
		}
	}
	var help []string
	for _, t := range a.targets {
		help = append(help, fmt.Sprintf("@%d %s %s", t.ep, t.name, t.help))
	}
	return fmt.Errorf("unknown command %q; commands:\n  %s", strings.Join(f, " "), strings.Join(help, "\n  "))
}

// poll runs the tickers, returning when they next need to run.
func (a *app) poll(now time.Time) time.Time {
	var next time.Time
	for _, t := range a.tickers {
		if at := t.tick(now); !at.IsZero() {
			next = earliest(next, at)
		}
	}
	return next
}

// forget drops the commands and tickers of removed endpoints.
func (a *app) forget(gone func(ep uint16) bool) {
	var ts []target
	for _, t := range a.targets {
		if !gone(t.ep) {
			ts = append(ts, t)
		}
	}
	var tk []ticker
	for _, t := range a.tickers {
		if !gone(t.ep) {
			tk = append(tk, t)
		}
	}
	a.targets, a.tickers = ts, tk
}

// endpoint adds an endpoint of one device type under parent (0: none); a
// bridged device's endpoint also gets the Bridged Node device type and
// its Bridged Device Basic Information.
func (a *app) endpoint(ep, parent uint16, dt im.DeviceType, cs ...im.Cluster) *im.Endpoint {
	types := []im.DeviceType{dt}
	if parent != 0 {
		types = append(types, clusters.DeviceTypeBridgedNode)
	}
	e := a.d.Node.AddEndpoint(ep, types...)
	e.Parent = parent
	a.d.Node.AddCluster(e, clusters.Descriptor{})
	a.d.Node.AddCluster(e, cs...)
	return e
}

func buildLight(a *app) {
	a.light(1, 0, clusters.DeviceTypeExtendedColorLight, clusters.ColorAllFeatures)
	a.button(2)
}

// light adds a light (On/Off, Dimmable, Color Temperature or Extended
// Color, by dt and the Color Control features); it logs its output at
// most every 250 ms.
func (a *app) light(ep, parent uint16, dt im.DeviceType, colorFeatures uint32) {
	id := &clusters.Identify{Type: clusters.IdentifyLightOutput, Effects: true}
	id.OnIdentify = func(on bool) { log.Printf("@%d identify=%v effect=%#x", ep, on, id.Effect()) }
	changed := false
	onOff := &clusters.OnOff{Lighting: true, OnChange: func(bool) { changed = true }}
	scenes := a.d.NewScenes()
	onOff.Scenes = scenes
	groups := a.d.NewGroups(id)
	groups.Scenes = scenes
	cs := []im.Cluster{id, groups, scenes, onOff}
	var level *clusters.LevelControl
	var color *clusters.ColorControl
	if dt != clusters.DeviceTypeOnOffLight {
		level = clusters.NewLevelControl(onOff, true)
		level.OnChange = func(uint8) { changed = true }
		cs = append(cs, level)
	}
	if colorFeatures != 0 {
		color = clusters.NewColorControl(colorFeatures, onOff, level)
		color.OnChange = func() { changed = true }
		cs = append(cs, color)
	}
	var last time.Time
	a.tickers = append(a.tickers, ticker{ep, func(now time.Time) time.Time {
		if !changed {
			return time.Time{}
		}
		if next := last.Add(250 * time.Millisecond); now.Before(next) {
			return next
		}
		changed, last = false, now
		msg := fmt.Sprintf("@%d light on=%v", ep, onOff.On)
		if level != nil {
			msg += fmt.Sprintf(" level=%d", level.Level())
		}
		if color != nil {
			r, g, b := color.RGB(level.Brightness())
			msg += fmt.Sprintf(" mode=%d rgb=#%02x%02x%02x", color.Mode(), r, g, b)
		}
		log.Print(msg)
		return time.Time{}
	}})
	a.endpoint(ep, parent, dt, cs...)
}

// plug adds an On/Off or Dimmable Plug-in Unit.
func (a *app) plug(ep, parent uint16, dimmable bool) {
	id := &clusters.Identify{Type: clusters.IdentifyActuator, Effects: true}
	onOff := &clusters.OnOff{Lighting: true, OnChange: func(on bool) { log.Printf("@%d plug on=%v", ep, on) }}
	scenes := a.d.NewScenes()
	onOff.Scenes = scenes
	groups := a.d.NewGroups(id)
	groups.Scenes = scenes
	cs := []im.Cluster{id, groups, scenes, onOff}
	dt := clusters.DeviceTypeOnOffPlugInUnit
	if dimmable {
		dt = clusters.DeviceTypeDimmablePlugIn
		level := clusters.NewLevelControl(onOff, true)
		level.OnChange = func(l uint8) { log.Printf("@%d plug level=%d", ep, l) }
		cs = append(cs, level)
	}
	a.endpoint(ep, parent, dt, cs...)
}

// button adds a push button (Generic Switch).
func (a *app) button(ep uint16) {
	sw := &clusters.Switch{}
	a.endpoint(ep, 0, clusters.DeviceTypeGenericSwitch,
		&clusters.Identify{Type: clusters.IdentifyVisibleIndicator, OnIdentify: func(on bool) { log.Printf("@%d identify=%v", ep, on) }},
		sw)
	a.handle(ep, "button", "press|release|click|long", func(now time.Time, args []string) error {
		if len(args) != 1 {
			return errors.New("button press|release|click|long")
		}
		switch args[0] {
		case "press":
			sw.Press(a.d.Node, ep, now)
		case "release":
			sw.Release(a.d.Node, ep, now)
		case "click":
			sw.Press(a.d.Node, ep, now)
			time.AfterFunc(150*time.Millisecond, func() { a.cmds <- fmt.Sprintf("@%d button release", ep) })
		case "long":
			sw.Press(a.d.Node, ep, now)
			time.AfterFunc(1500*time.Millisecond, func() { a.cmds <- fmt.Sprintf("@%d button release", ep) })
		default:
			return errors.New("button press|release|click|long")
		}
		log.Printf("@%d button: %s", ep, args[0])
		return nil
	})
}

func sensorIdentify(ep uint16) *clusters.Identify {
	return &clusters.Identify{Type: clusters.IdentifyVisibleIndicator, OnIdentify: func(on bool) { log.Printf("@%d identify=%v", ep, on) }}
}

// contact adds a Contact Sensor ("contact open|closed").
func (a *app) contact(ep, parent uint16) {
	st := &clusters.BooleanState{}
	a.endpoint(ep, parent, clusters.DeviceTypeContactSensor, sensorIdentify(ep), st)
	a.handle(ep, "contact", "open|closed", func(now time.Time, args []string) error {
		if len(args) != 1 || args[0] != "open" && args[0] != "closed" {
			return errors.New("contact open|closed")
		}
		st.Set(a.d.Node, ep, now, args[0] == "closed") // true: contact
		return nil
	})
}

// occupancy adds a PIR Occupancy Sensor ("occupancy on|off").
func (a *app) occupancy(ep, parent uint16) {
	occ := &clusters.OccupancySensing{Sensors: clusters.OccupancyPassiveInfrared}
	a.endpoint(ep, parent, clusters.DeviceTypeOccupancySensor, sensorIdentify(ep), occ)
	a.handle(ep, "occupancy", "on|off", func(now time.Time, args []string) error {
		if len(args) != 1 || args[0] != "on" && args[0] != "off" {
			return errors.New("occupancy on|off")
		}
		occ.Set(a.d.Node, ep, now, args[0] == "on")
		return nil
	})
}

// measurement adds a sensor with a measurement cluster, reading initial at
// first and then what the command name sets: a value in the given unit (or
// "null"), converted by conv.
func (a *app) measurement(ep, parent uint16, dt im.DeviceType, m *clusters.Measurement, name, unit string, initial float64, conv func(float64) int32) {
	a.endpoint(ep, parent, dt, sensorIdentify(ep), m)
	m.Set(a.d.Node, ep, clusters.Value(conv(initial)))
	a.handle(ep, name, "<"+unit+">|null", func(now time.Time, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("%s <%s>|null", name, unit)
		}
		if args[0] == "null" {
			m.Set(a.d.Node, ep, clusters.Null)
			return nil
		}
		v, err := strconv.ParseFloat(args[0], 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("%s <%s>|null", name, unit)
		}
		m.Set(a.d.Node, ep, clusters.Value(conv(v)))
		return nil
	})
}

func hundredths(v float64) int32 { return int32(math.Round(v * 100)) }

// temperature adds a Temperature Sensor (-40 to 85 °C; "temp <°C>").
func (a *app) temperature(ep, parent uint16) {
	a.measurement(ep, parent, clusters.DeviceTypeTemperatureSensor,
		clusters.NewTemperatureMeasurement(clusters.Value(-4000), clusters.Value(8500)), "temp", "°C", 21, hundredths)
}

// humidity adds a Humidity Sensor ("humidity <%>").
func (a *app) humidity(ep, parent uint16) {
	a.measurement(ep, parent, clusters.DeviceTypeHumiditySensor,
		clusters.NewHumidityMeasurement(clusters.Value(0), clusters.Value(10000)), "humidity", "%", 45, hundredths)
}

// pressure adds a Pressure Sensor (300 to 1100 hPa; "pressure <hPa>").
func (a *app) pressure(ep, parent uint16) {
	a.measurement(ep, parent, clusters.DeviceTypePressureSensor,
		clusters.NewPressureMeasurement(clusters.Value(300), clusters.Value(1100)), "pressure", "hPa", 1013,
		func(v float64) int32 { return int32(math.Round(v)) })
}

// lightSensor adds a Light Sensor ("lux <lux>").
func (a *app) lightSensor(ep, parent uint16) {
	a.measurement(ep, parent, clusters.DeviceTypeLightSensor,
		clusters.NewIlluminanceMeasurement(clusters.Value(1), clusters.Value(0xFFFE)), "lux", "lux", 300,
		func(lux float64) int32 {
			if lux < 1 {
				return 1
			}
			return int32(math.Min(10000*math.Log10(lux)+1, 0xFFFE))
		})
}

// bridged are the device kinds a bridge can expose.
var bridged = map[string]func(a *app, ep uint16){
	"light":       func(a *app, ep uint16) { a.light(ep, 1, clusters.DeviceTypeOnOffLight, 0) },
	"dimlight":    func(a *app, ep uint16) { a.light(ep, 1, clusters.DeviceTypeDimmableLight, 0) },
	"plug":        func(a *app, ep uint16) { a.plug(ep, 1, false) },
	"contact":     func(a *app, ep uint16) { a.contact(ep, 1) },
	"occupancy":   func(a *app, ep uint16) { a.occupancy(ep, 1) },
	"temperature": func(a *app, ep uint16) { a.temperature(ep, 1) },
	"humidity":    func(a *app, ep uint16) { a.humidity(ep, 1) },
}

// buildBridge makes an Aggregator (endpoint 1) with three bridged devices
// (endpoints 3 to 5); "add <kind> [label]" bridges another, "remove <ep>"
// drops one and "reach <ep> on|off" sets whether it is reachable.
func buildBridge(a *app) {
	a.d.Node.AddCluster(a.d.Node.AddEndpoint(1, clusters.DeviceTypeAggregator), clusters.Descriptor{})
	infos := map[uint16]*clusters.BridgedDeviceBasicInformation{}
	add := func(kindName string, ep uint16, label string) error {
		build := bridged[kindName]
		if build == nil {
			var names []string
			for k := range bridged {
				names = append(names, k)
			}
			sort.Strings(names)
			return fmt.Errorf("bridged kinds: %s", strings.Join(names, ", "))
		}
		build(a, ep)
		info := &clusters.BridgedDeviceBasicInformation{
			VendorName: "tiny-matter-go", ProductName: "Bridged " + kindName, NodeLabel: label,
			UniqueID: fmt.Sprintf("tmg-bridged-%d", ep),
		}
		a.d.Node.AddCluster(a.d.Node.Endpoint(ep), info)
		infos[ep] = info
		return nil
	}
	add("light", 3, "Lamp")
	add("contact", 4, "Door")
	add("temperature", 5, "Outdoor")

	a.handle(1, "add", "<kind> [label]", func(now time.Time, args []string) error {
		if len(args) < 1 {
			return errors.New("add <kind> [label]")
		}
		ep := uint16(3)
		for a.d.Node.Endpoint(ep) != nil {
			ep++
		}
		if err := add(args[0], ep, strings.Join(args[1:], " ")); err != nil {
			return err
		}
		a.d.AddedEndpoint(ep)
		log.Printf("bridged %s on endpoint %d", args[0], ep)
		return nil
	})
	a.handle(1, "remove", "<ep>", func(now time.Time, args []string) error {
		ep, err := bridgedEP(args, infos)
		if err != nil {
			return err
		}
		a.d.RemoveEndpoint(ep)
		delete(infos, ep)
		a.forget(func(e uint16) bool { return e == ep })
		log.Printf("removed bridged endpoint %d", ep)
		return nil
	})
	a.handle(1, "reach", "<ep> on|off", func(now time.Time, args []string) error {
		if len(args) != 2 || args[1] != "on" && args[1] != "off" {
			return errors.New("reach <ep> on|off")
		}
		ep, err := bridgedEP(args[:1], infos)
		if err != nil {
			return err
		}
		infos[ep].SetReachable(a.d.Node, ep, now, args[1] == "on")
		return nil
	})
}

func bridgedEP(args []string, infos map[uint16]*clusters.BridgedDeviceBasicInformation) (uint16, error) {
	if len(args) != 1 {
		return 0, errors.New("want a bridged endpoint")
	}
	v, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil || infos[uint16(v)] == nil {
		return 0, fmt.Errorf("%q is not a bridged endpoint", args[0])
	}
	return uint16(v), nil
}
