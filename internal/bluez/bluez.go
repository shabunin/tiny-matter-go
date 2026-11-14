// Package bluez is a BLE central for Matter commissioning over BlueZ's
// D-Bus API (Linux): it finds devices advertising the Matter BLE service
// and talks to their Matter GATT characteristics, C1 (written) and C2
// (indicated).
package bluez

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shabunin/tiny-matter-go/internal/dbus"
)

const (
	service        = "org.bluez"
	ifaceAdapter   = "org.bluez.Adapter1"
	ifaceDevice    = "org.bluez.Device1"
	ifaceService   = "org.bluez.GattService1"
	ifaceChar      = "org.bluez.GattCharacteristic1"
	ifaceProps     = "org.freedesktop.DBus.Properties"
	ifaceObjectMgr = "org.freedesktop.DBus.ObjectManager"

	// MatterUUID is the Matter BLE service (0xFFF6).
	MatterUUID = "0000fff6-0000-1000-8000-00805f9b34fb"
	uuidC1     = "18ee2ef5-263d-4559-959f-4f9c429f9d11"
	uuidC2     = "18ee2ef5-263d-4559-959f-4f9c429f9d12"

	// Connection attempts: one may be aborted when the device misses the
	// connection request (radio interference, Wi-Fi coexistence).
	connectAttempts = 4
)

// ErrNoAdapter is returned when BlueZ has no Bluetooth adapter.
var ErrNoAdapter = errors.New("bluez: no Bluetooth adapter")

// Client is a connection to BlueZ that uses one adapter.
type Client struct {
	bus *dbus.Conn
	// Adapter is the adapter's object path, such as /org/bluez/hci0.
	Adapter dbus.ObjectPath

	mu       sync.Mutex
	watchers map[int]func(*dbus.Message)
	nextID   int
}

// Open connects to BlueZ on the system bus and picks the first powered
// adapter.
func Open(ctx context.Context) (*Client, error) {
	bus, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("bluez: system bus: %w", err)
	}
	c := &Client{bus: bus, watchers: map[int]func(*dbus.Message){}}
	if err := bus.AddMatch(ctx, "type='signal',sender='org.bluez'"); err != nil {
		bus.Close()
		return nil, fmt.Errorf("bluez: %w", err)
	}
	go c.dispatch()
	objs, err := c.objects(ctx)
	if err != nil {
		bus.Close()
		return nil, fmt.Errorf("bluez: is bluetoothd running? %w", err)
	}
	var adapters []string
	powered := map[string]bool{}
	for path, ifaces := range objs {
		if props, ok := ifaces[ifaceAdapter]; ok {
			adapters = append(adapters, path)
			powered[path] = props["Powered"] == true
		}
	}
	sort.Strings(adapters)
	for _, a := range adapters {
		if powered[a] {
			c.Adapter = dbus.ObjectPath(a)
			return c, nil
		}
	}
	bus.Close()
	if len(adapters) > 0 {
		return nil, fmt.Errorf("bluez: adapter %s is powered off", adapters[0])
	}
	return nil, ErrNoAdapter
}

// Close closes the connection to BlueZ.
func (c *Client) Close() error { return c.bus.Close() }

func (c *Client) call(ctx context.Context, path dbus.ObjectPath, iface, member string, sig dbus.Signature, args ...any) ([]any, error) {
	return c.bus.Call(ctx, service, path, iface, member, sig, args...)
}

// objects returns BlueZ's objects: path, interface, properties (variant
// values unwrapped).
func (c *Client) objects(ctx context.Context) (map[string]map[string]map[string]any, error) {
	body, err := c.call(ctx, "/", ifaceObjectMgr, "GetManagedObjects", "")
	if err != nil {
		return nil, err
	}
	if len(body) != 1 {
		return nil, errors.New("bluez: bad GetManagedObjects reply")
	}
	all, _ := body[0].(map[string]any)
	out := make(map[string]map[string]map[string]any, len(all))
	for path, v := range all {
		ifaces, _ := v.(map[string]any)
		m := make(map[string]map[string]any, len(ifaces))
		for name, p := range ifaces {
			props, _ := p.(map[string]any)
			m[name] = unwrap(props)
		}
		out[path] = m
	}
	return out, nil
}

// unwrap replaces the variants of a property map by their values.
func unwrap(props map[string]any) map[string]any {
	out := make(map[string]any, len(props))
	for k, v := range props {
		if vv, ok := v.(dbus.Variant); ok {
			v = vv.Value
		}
		out[k] = v
	}
	return out
}

func (c *Client) dispatch() {
	for {
		select {
		case m := <-c.bus.Signals():
			c.mu.Lock()
			ws := make([]func(*dbus.Message), 0, len(c.watchers))
			for _, w := range c.watchers {
				ws = append(ws, w)
			}
			c.mu.Unlock()
			for _, w := range ws {
				w(m)
			}
		case <-c.bus.Done():
			return
		}
	}
}

// watch calls f, on the dispatch goroutine, for each BlueZ signal until
// the returned function is called. f must not block.
func (c *Client) watch(f func(*dbus.Message)) func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	c.watchers[id] = f
	return func() {
		c.mu.Lock()
		delete(c.watchers, id)
		c.mu.Unlock()
	}
}

// queue is an unbounded FIFO filled by a watcher.
type queue[T any] struct {
	mu    sync.Mutex
	items []T
	wake  chan struct{}
}

func newQueue[T any]() *queue[T] { return &queue[T]{wake: make(chan struct{}, 1)} }

func (q *queue[T]) push(v T) {
	q.mu.Lock()
	q.items = append(q.items, v)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *queue[T]) take() []T {
	q.mu.Lock()
	defer q.mu.Unlock()
	items := q.items
	q.items = nil
	return items
}

// Device is a device advertising the Matter BLE service.
type Device struct {
	Path    dbus.ObjectPath
	Address string
	Name    string
	RSSI    int16
	// ServiceData is the advertisement's service data for MatterUUID.
	ServiceData []byte
}

func matterData(props map[string]any) []byte {
	sd, _ := props["ServiceData"].(map[string]any)
	v, _ := sd[MatterUUID].(dbus.Variant)
	b, _ := v.Value.([]byte)
	return b
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func device(path dbus.ObjectPath, props map[string]any) Device {
	d := Device{Path: path, Address: str(props["Address"]), Name: str(props["Name"]), ServiceData: matterData(props)}
	d.RSSI, _ = props["RSSI"].(int16)
	return d
}

// Scan reports the devices advertising the Matter service until found
// returns true or ctx ends. Matter devices BlueZ remembers from earlier
// scans are forgotten first (unless paired), so only devices advertising
// now are reported; a device is reported again when its advertisement
// changes.
func (c *Client) Scan(ctx context.Context, found func(Device) bool) error {
	events := newQueue[*dbus.Message]()
	stop := c.watch(func(m *dbus.Message) {
		if m.Member == "InterfacesAdded" || m.Member == "PropertiesChanged" {
			events.push(m)
		}
	})
	defer stop()

	objs, err := c.objects(ctx)
	if err != nil {
		return fmt.Errorf("bluez: %w", err)
	}
	devices := map[dbus.ObjectPath]map[string]any{}
	for path, ifaces := range objs {
		props, ok := ifaces[ifaceDevice]
		if !ok || props["Adapter"] != c.Adapter {
			continue
		}
		if matterData(props) != nil && props["Connected"] != true && props["Paired"] != true &&
			props["Bonded"] != true && props["Trusted"] != true {
			c.call(ctx, c.Adapter, ifaceAdapter, "RemoveDevice", "o", dbus.ObjectPath(path))
			continue
		}
		devices[dbus.ObjectPath(path)] = props
	}
	// LE only. Filtering by UUID would hide Matter devices: the kernel
	// matches only advertised service UUID lists, which they do not have.
	c.call(ctx, c.Adapter, ifaceAdapter, "SetDiscoveryFilter", "a{sv}", map[string]dbus.Variant{
		"Transport": {Sig: "s", Value: "le"}, "DuplicateData": {Sig: "b", Value: true},
	})
	if _, err := c.call(ctx, c.Adapter, ifaceAdapter, "StartDiscovery", ""); err != nil {
		return fmt.Errorf("bluez: StartDiscovery: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c.call(sctx, c.Adapter, ifaceAdapter, "StopDiscovery", "")
	}()

	reported := map[dbus.ObjectPath]string{}
	report := func(path dbus.ObjectPath) bool {
		props := devices[path]
		sd := matterData(props)
		if sd == nil || reported[path] == string(sd) {
			return false
		}
		reported[path] = string(sd)
		return found(device(path, props))
	}
	for {
		select {
		case <-events.wake:
			for _, m := range events.take() {
				var path dbus.ObjectPath
				switch m.Member {
				case "InterfacesAdded":
					if len(m.Body) != 2 {
						continue
					}
					path, _ = m.Body[0].(dbus.ObjectPath)
					ifaces, _ := m.Body[1].(map[string]any)
					p, ok := ifaces[ifaceDevice].(map[string]any)
					if !ok {
						continue
					}
					props := unwrap(p)
					if props["Adapter"] != c.Adapter {
						continue
					}
					devices[path] = props
				case "PropertiesChanged":
					if len(m.Body) != 3 || m.Body[0] != ifaceDevice {
						continue
					}
					path = m.Path
					props := devices[path]
					if props == nil {
						continue // not ours, or seen before the scan started
					}
					changed, _ := m.Body[1].(map[string]any)
					maps.Copy(props, unwrap(changed))
					invalidated, _ := m.Body[2].([]any)
					for _, k := range invalidated {
						delete(props, str(k))
					}
				}
				if path != "" && report(path) {
					return nil
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-c.bus.Done():
			return c.bus.Err()
		}
	}
}

// Link is a connection to a device's Matter GATT service.
type Link struct {
	c   *Client
	dev dbus.ObjectPath
	mtu int

	mu     sync.Mutex
	c1, c2 dbus.ObjectPath

	resolved chan struct{}
	events   *queue[[]byte] // C2 values; nil marks the end of the link
	values   chan []byte
	done     chan struct{}
	quit     chan struct{} // closed by Close
	stop     func()
	once     sync.Once
}

// Connect connects to a device found by Scan and finds its Matter GATT
// service.
func (c *Client) Connect(ctx context.Context, dev dbus.ObjectPath) (*Link, error) {
	l := &Link{c: c, dev: dev, resolved: make(chan struct{}, 1), events: newQueue[[]byte](),
		values: make(chan []byte), done: make(chan struct{}), quit: make(chan struct{})}
	l.stop = c.watch(l.signal)
	go l.pump()
	err := l.connect(ctx)
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Link) signal(m *dbus.Message) {
	if m.Member != "PropertiesChanged" || len(m.Body) != 3 {
		return
	}
	changed, _ := m.Body[1].(map[string]any)
	switch {
	case m.Path == l.dev && m.Body[0] == ifaceDevice:
		if v, ok := changed["ServicesResolved"].(dbus.Variant); ok && v.Value == true {
			select {
			case l.resolved <- struct{}{}:
			default:
			}
		}
		if v, ok := changed["Connected"].(dbus.Variant); ok && v.Value == false {
			l.events.push(nil)
		}
	case m.Body[0] == ifaceChar:
		l.mu.Lock()
		c2 := l.c2
		l.mu.Unlock()
		if v, ok := changed["Value"].(dbus.Variant); ok && m.Path == c2 {
			if b, _ := v.Value.([]byte); b != nil {
				l.events.push(b)
			}
		}
	}
}

// pump hands C2 values to Values in order; the end of the link closes Done
// after every value before it has been taken.
func (l *Link) pump() {
	defer close(l.done)
	for {
		select {
		case <-l.events.wake:
		case <-l.quit:
			return
		case <-l.c.bus.Done():
			return
		}
		for _, b := range l.events.take() {
			if b == nil {
				return
			}
			select {
			case l.values <- b:
			case <-l.quit:
				return
			case <-l.c.bus.Done():
				return
			}
		}
	}
}

func (l *Link) connect(ctx context.Context) error {
	var err error
	for range connectAttempts {
		if _, err = l.c.call(ctx, l.dev, ifaceDevice, "Connect", ""); err == nil || ctx.Err() != nil {
			break
		}
		var de *dbus.Error
		if errors.As(err, &de) && de.Name == "org.bluez.Error.AlreadyConnected" {
			err = nil
			break
		}
		if de == nil || de.Name == "org.bluez.Error.DoesNotExist" {
			break
		}
		// An aborted attempt must be cancelled, or the next returns at once.
		l.c.call(ctx, l.dev, ifaceDevice, "Disconnect", "")
	}
	if err != nil {
		return fmt.Errorf("bluez: connecting: %w", err)
	}
	body, err := l.c.call(ctx, l.dev, ifaceProps, "Get", "ss", ifaceDevice, "ServicesResolved")
	if err != nil {
		return fmt.Errorf("bluez: %w", err)
	}
	if v, _ := body[0].(dbus.Variant); v.Value != true {
		select {
		case <-l.resolved:
		case <-l.done:
			return errors.New("bluez: disconnected while discovering services")
		case <-ctx.Done():
			return fmt.Errorf("bluez: discovering services: %w", ctx.Err())
		}
	}
	objs, err := l.c.objects(ctx)
	if err != nil {
		return fmt.Errorf("bluez: %w", err)
	}
	var svc string
	for path, ifaces := range objs {
		if p, ok := ifaces[ifaceService]; ok && p["Device"] == l.dev && strings.EqualFold(str(p["UUID"]), MatterUUID) {
			svc = path
		}
	}
	if svc == "" {
		return errors.New("bluez: the device has no Matter GATT service")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for path, ifaces := range objs {
		p, ok := ifaces[ifaceChar]
		if !ok || p["Service"] != dbus.ObjectPath(svc) {
			continue
		}
		switch strings.ToLower(str(p["UUID"])) {
		case uuidC1:
			l.c1 = dbus.ObjectPath(path)
			if mtu, ok := p["MTU"].(uint16); ok {
				l.mtu = int(mtu)
			}
		case uuidC2:
			l.c2 = dbus.ObjectPath(path)
		}
	}
	if l.c1 == "" || l.c2 == "" {
		return errors.New("bluez: the Matter GATT service lacks C1 or C2")
	}
	return nil
}

// MTU returns the connection's ATT MTU, or 0 if BlueZ does not say.
func (l *Link) MTU() int { return l.mtu }

// Write writes to C1 and waits for the device's write response.
func (l *Link) Write(ctx context.Context, b []byte) error {
	_, err := l.c.call(ctx, l.c1, ifaceChar, "WriteValue", "aya{sv}", b,
		map[string]dbus.Variant{"type": {Sig: "s", Value: "request"}})
	return err
}

// Subscribe enables C2 indications.
func (l *Link) Subscribe(ctx context.Context) error {
	_, err := l.c.call(ctx, l.c2, ifaceChar, "StartNotify", "")
	return err
}

// Values delivers the values the device indicates on C2.
func (l *Link) Values() <-chan []byte { return l.values }

// Done is closed when the connection ends, after the values received
// before have been taken from Values.
func (l *Link) Done() <-chan struct{} { return l.done }

// Close disconnects.
func (l *Link) Close() error {
	l.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		l.mu.Lock()
		c2 := l.c2
		l.mu.Unlock()
		if c2 != "" {
			l.c.call(ctx, c2, ifaceChar, "StopNotify", "")
		}
		l.c.call(ctx, l.dev, ifaceDevice, "Disconnect", "")
		l.stop()
		close(l.quit)
		l.events.push(nil)
	})
	return nil
}
