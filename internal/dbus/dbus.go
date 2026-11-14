// Package dbus is a small D-Bus client: enough of the wire protocol to call
// methods and receive signals on the system bus, which is how a Linux host
// talks to BlueZ. It authenticates with EXTERNAL, writes little-endian
// messages, exports no objects and passes no file descriptors.
package dbus

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Message types.
const (
	TypeMethodCall   = 1
	TypeMethodReturn = 2
	TypeError        = 3
	TypeSignal       = 4
)

const flagNoReplyExpected = 0x01

// Header field codes.
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSender      = 7
	fieldSignature   = 8
)

const maxMessage = 1 << 27 // the protocol's limit

// Message is a D-Bus message.
type Message struct {
	Type        byte
	Flags       byte
	Serial      uint32
	Path        ObjectPath
	Interface   string
	Member      string
	ErrorName   string
	ReplySerial uint32
	Destination string
	Sender      string
	Signature   Signature
	Body        []any
}

// Error is an error reply to a method call.
type Error struct {
	Name    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Name
	}
	return e.Name + ": " + e.Message
}

// ErrClosed is returned once the connection is closed.
var ErrClosed = errors.New("dbus: connection closed")

func (m *Message) encode(serial uint32) ([]byte, error) {
	body := encoder{}
	if err := body.args(string(m.Signature), m.Body); err != nil {
		return nil, err
	}
	var fields []any
	add := func(code byte, sig Signature, v any) { fields = append(fields, []any{code, Variant{sig, v}}) }
	if m.Path != "" {
		add(fieldPath, "o", m.Path)
	}
	if m.Interface != "" {
		add(fieldInterface, "s", m.Interface)
	}
	if m.Member != "" {
		add(fieldMember, "s", m.Member)
	}
	if m.ErrorName != "" {
		add(fieldErrorName, "s", m.ErrorName)
	}
	if m.ReplySerial != 0 {
		add(fieldReplySerial, "u", m.ReplySerial)
	}
	if m.Destination != "" {
		add(fieldDestination, "s", m.Destination)
	}
	if m.Signature != "" {
		add(fieldSignature, "g", m.Signature)
	}
	h := encoder{b: []byte{'l', m.Type, m.Flags, 1}}
	h.u32(uint32(len(body.b)))
	h.u32(serial)
	if err := h.value("a(yv)", fields, 0); err != nil {
		return nil, err
	}
	h.align(8)
	if len(h.b)+len(body.b) > maxMessage {
		return nil, errors.New("dbus: message too long")
	}
	return append(h.b, body.b...), nil
}

// readMessage reads one message.
func readMessage(r io.Reader) (*Message, error) {
	var fixed [16]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch fixed[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return nil, errors.New("dbus: bad byte order")
	}
	bodyLen := order.Uint32(fixed[4:])
	fieldsLen := order.Uint32(fixed[12:])
	hdrLen := (16 + int(fieldsLen) + 7) &^ 7
	if fieldsLen > maxMessage || bodyLen > maxMessage || hdrLen+int(bodyLen) > maxMessage {
		return nil, errors.New("dbus: message too long")
	}
	buf := make([]byte, hdrLen+int(bodyLen))
	copy(buf, fixed[:])
	if _, err := io.ReadFull(r, buf[16:]); err != nil {
		return nil, err
	}
	m := &Message{Type: fixed[1], Flags: fixed[2], Serial: order.Uint32(fixed[8:])}
	d := &decoder{b: buf[:16+fieldsLen], off: 12, order: order}
	f, err := d.value("a(yv)", 0)
	if err != nil {
		return nil, err
	}
	for _, e := range f.([]any) {
		fe := e.([]any)
		v := fe[1].(Variant).Value
		switch fe[0].(byte) {
		case fieldPath:
			m.Path, _ = v.(ObjectPath)
		case fieldInterface:
			m.Interface, _ = v.(string)
		case fieldMember:
			m.Member, _ = v.(string)
		case fieldErrorName:
			m.ErrorName, _ = v.(string)
		case fieldReplySerial:
			m.ReplySerial, _ = v.(uint32)
		case fieldDestination:
			m.Destination, _ = v.(string)
		case fieldSender:
			m.Sender, _ = v.(string)
		case fieldSignature:
			m.Signature, _ = v.(Signature)
		}
	}
	bd := &decoder{b: buf, off: hdrLen, order: order}
	if m.Body, err = bd.args(string(m.Signature)); err != nil {
		return nil, err
	}
	if bd.off != len(buf) {
		return nil, errors.New("dbus: body longer than its signature")
	}
	return m, nil
}

// Conn is a connection to a message bus.
type Conn struct {
	conn net.Conn
	name string

	wmu    sync.Mutex
	serial atomic.Uint32

	mu      sync.Mutex
	pending map[uint32]chan *Message
	sigq    []*Message
	sigWake chan struct{}
	err     error

	signals chan *Message
	closed  chan struct{}
	once    sync.Once
}

// SystemBus connects to the system message bus.
func SystemBus() (*Conn, error) {
	addr := os.Getenv("DBUS_SYSTEM_BUS_ADDRESS")
	if addr == "" {
		addr = "unix:path=/var/run/dbus/system_bus_socket"
	}
	return Dial(addr)
}

// Dial connects to the bus at a D-Bus server address (such as
// "unix:path=/run/dbus/system_bus_socket"), authenticates and says Hello.
func Dial(address string) (*Conn, error) {
	var lastErr error = errors.New("dbus: no usable address in " + strconv.Quote(address))
	for a := range strings.SplitSeq(address, ";") {
		path, err := unixPath(a)
		if err != nil {
			lastErr = err
			continue
		}
		nc, err := net.DialTimeout("unix", path, 5*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := newConn(nc)
		if err != nil {
			nc.Close()
			lastErr = err
			continue
		}
		return c, nil
	}
	return nil, lastErr
}

func unixPath(addr string) (string, error) {
	transport, params, ok := strings.Cut(addr, ":")
	if !ok || transport != "unix" {
		return "", fmt.Errorf("dbus: unsupported address %q", addr)
	}
	for kv := range strings.SplitSeq(params, ",") {
		k, v, _ := strings.Cut(kv, "=")
		v, err := url.PathUnescape(v)
		if err != nil {
			return "", err
		}
		switch k {
		case "path":
			return v, nil
		case "abstract":
			return "@" + v, nil
		}
	}
	return "", fmt.Errorf("dbus: unsupported address %q", addr)
}

func newConn(nc net.Conn) (*Conn, error) {
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	uid := strconv.Itoa(os.Getuid())
	if _, err := fmt.Fprintf(nc, "\x00AUTH EXTERNAL %s\r\n", hex.EncodeToString([]byte(uid))); err != nil {
		return nil, err
	}
	br := bufio.NewReader(nc)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "OK ") {
		return nil, fmt.Errorf("dbus: authentication refused: %q", strings.TrimSpace(line))
	}
	if _, err := io.WriteString(nc, "BEGIN\r\n"); err != nil {
		return nil, err
	}
	nc.SetDeadline(time.Time{})
	c := &Conn{
		conn: nc, pending: map[uint32]chan *Message{},
		sigWake: make(chan struct{}, 1), signals: make(chan *Message),
		closed: make(chan struct{}),
	}
	go c.read(br)
	go c.pumpSignals()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, err := c.Call(ctx, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "")
	if err != nil {
		c.Close()
		return nil, err
	}
	if len(body) == 1 {
		c.name, _ = body[0].(string)
	}
	return c, nil
}

// Name returns the connection's unique bus name.
func (c *Conn) Name() string { return c.name }

// Close closes the connection; pending calls fail with ErrClosed.
func (c *Conn) Close() error {
	c.fail(ErrClosed)
	return nil
}

func (c *Conn) fail(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.closed)
		c.conn.Close()
	})
}

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.closed }

// Err returns why the connection ended.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) read(r io.Reader) {
	for {
		m, err := readMessage(r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				err = ErrClosed
			}
			c.fail(err)
			return
		}
		switch m.Type {
		case TypeMethodReturn, TypeError:
			c.mu.Lock()
			ch := c.pending[m.ReplySerial]
			delete(c.pending, m.ReplySerial)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case TypeSignal:
			c.mu.Lock()
			c.sigq = append(c.sigq, m)
			c.mu.Unlock()
			select {
			case c.sigWake <- struct{}{}:
			default:
			}
		case TypeMethodCall:
			// Nothing is exported here.
			if m.Flags&flagNoReplyExpected == 0 {
				c.send(&Message{Type: TypeError, ErrorName: "org.freedesktop.DBus.Error.UnknownMethod",
					ReplySerial: m.Serial, Destination: m.Sender, Signature: "s",
					Body: []any{"no objects are exported"}})
			}
		}
	}
}

// pumpSignals hands queued signals to the Signals channel, so a slow
// reader never holds up method replies.
func (c *Conn) pumpSignals() {
	for {
		c.mu.Lock()
		q := c.sigq
		c.sigq = nil
		c.mu.Unlock()
		for _, m := range q {
			select {
			case c.signals <- m:
			case <-c.closed:
				return
			}
		}
		select {
		case <-c.sigWake:
		case <-c.closed:
			return
		}
	}
}

// Signals delivers the signals the connection receives, in order. Ask the
// bus for them with AddMatch.
func (c *Conn) Signals() <-chan *Message { return c.signals }

func (c *Conn) send(m *Message) (uint32, error) {
	serial := c.serial.Add(1)
	b, err := m.encode(serial)
	if err != nil {
		return 0, err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.conn.Write(b); err != nil {
		c.fail(err)
		return 0, err
	}
	return serial, nil
}

// Call calls a method and returns the reply's values. An error reply is
// returned as *Error.
func (c *Conn) Call(ctx context.Context, dest string, path ObjectPath, iface, member string, sig Signature, args ...any) ([]any, error) {
	m := &Message{Type: TypeMethodCall, Path: path, Interface: iface, Member: member,
		Destination: dest, Signature: sig, Body: args}
	ch := make(chan *Message, 1)
	// Register before sending: the reply may come back at once.
	serial := c.serial.Add(1)
	b, err := m.encode(serial)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return nil, err
	}
	c.pending[serial] = ch
	c.mu.Unlock()
	c.wmu.Lock()
	_, err = c.conn.Write(b)
	c.wmu.Unlock()
	if err != nil {
		c.fail(err)
	}
	select {
	case r := <-ch:
		if r.Type == TypeError {
			e := &Error{Name: r.ErrorName}
			if len(r.Body) > 0 {
				e.Message, _ = r.Body[0].(string)
			}
			return nil, e
		}
		return r.Body, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, serial)
		c.mu.Unlock()
		return nil, ctx.Err()
	case <-c.closed:
		return nil, c.Err()
	}
}

// AddMatch asks the bus for the signals that match a rule, such as
// "type='signal',sender='org.bluez'".
func (c *Conn) AddMatch(ctx context.Context, rule string) error {
	_, err := c.Call(ctx, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch", "s", rule)
	return err
}
