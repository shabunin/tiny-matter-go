// Package matterble is the Matter BLE commissioning transport over the
// host side of tinygo.org/x/bluetooth/hci: the BTP GATT service,
// connectable advertising, and the BTP session that carries Matter
// messages. It runs from the caller's main loop (Poll), with no goroutines.
package matterble

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/btp"
	"tinygo.org/x/bluetooth/ble"
	"tinygo.org/x/bluetooth/hci"
)

// Peer is the address Matter messages over BTP are exchanged with. No UDP
// datagram can come from the unspecified address and port 0.
var Peer = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)

// Connection parameters requested after connecting: 30-50 ms interval and
// a 6 s supervision timeout (units of 1.25 ms and 10 ms).
const (
	connIntervalMin    = 24
	connIntervalMax    = 40
	supervisionTimeout = 600
)

// resetDelay lets the controller settle after HCI Reset.
var resetDelay = 150 * time.Millisecond

// Log, if set, receives progress messages.
var Log func(msg string)

func logf(args ...any) {
	if Log == nil {
		return
	}
	var b []byte
	for i, a := range args {
		if i > 0 {
			b = append(b, ' ')
		}
		switch v := a.(type) {
		case string:
			b = append(b, v...)
		case int:
			b = strconv.AppendInt(b, int64(v), 10)
		case uint16:
			b = strconv.AppendUint(b, uint64(v), 10)
		}
	}
	Log(string(b))
}

// maxATTMTU keeps a notification within the hci package's 256-byte write
// buffer: 9 bytes of HCI, L2CAP and 3 of ATT header, plus a 244-byte segment.
const maxATTMTU = 247

// Options adapts the server to a controller.
type Options struct {
	// MTU caps the ATT MTU, for transports that take shorter packets than
	// the hci package; 0 or above 247 means 247. A notification is an HCI
	// packet of MTU + 9 bytes.
	MTU int

	// Setup, if set, runs after the controller is reset, before anything
	// else is sent, for vendor commands such as setting the address.
	Setup func(h *hci.HCI) error
}

// GATT characteristic properties.
const (
	propRead     = 0x02
	propWrite    = 0x08
	propNotify   = 0x10
	propIndicate = 0x20
)

// Server is the Matter BLE commissioning transport: a GATT service with
// the BTP characteristics, advertised while commissionable.
type Server struct {
	st        *hci.Stack
	conn      btp.Conn
	handle    uint16
	connected bool
	c2        uint16 // C2 value handle
	cccd      uint16
	adv       []byte
	advOn     bool
	mtu       uint16
	writes    [][]byte // C1 writes not yet processed
	subscribe bool     // the C2 subscription changed
	closing   bool     // disconnect once the send queue drains
	closeBy   time.Time
	logged    bool
	paramsAt  time.Time // when to request connection parameters
}

// requestParams sends an L2CAP Connection Parameter Update Request
// (Core spec Vol 3 Part A 4.20), which the central's host answers itself.
func (b *Server) requestParams() {
	// Identifier 1 is taken by the request the hci package sends itself.
	req := []byte{0x12, 0x4D, 8, 0}
	req = binary.LittleEndian.AppendUint16(req, connIntervalMin)
	req = binary.LittleEndian.AppendUint16(req, connIntervalMax)
	req = binary.LittleEndian.AppendUint16(req, 0)
	req = binary.LittleEndian.AppendUint16(req, supervisionTimeout)
	if err := b.st.HCI.SendACLPacket(b.handle, hci.CIDSignaling, req); err != nil {
		logf("ble: parameter request:", err.Error())
	}
}

func mustUUID(s string) ble.UUID {
	u, err := ble.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

// New brings up the controller behind t and the Matter GATT service.
func New(t hci.Transport, discriminator, vendorID, productID uint16, opts Options) (*Server, error) {
	b := &Server{st: hci.NewStack(t), mtu: maxATTMTU}
	if opts.MTU > 0 && opts.MTU < maxATTMTU {
		b.mtu = uint16(opts.MTU)
	}
	h := b.st.HCI
	if err := h.Start(); err != nil {
		return nil, err
	}
	if err := h.Reset(); err != nil {
		return nil, err
	}
	time.Sleep(resetDelay)
	if opts.Setup != nil {
		if err := opts.Setup(h); err != nil {
			return nil, err
		}
	}
	if err := h.SetEventMask(0x3FFFFFFFFFFFFFFF); err != nil {
		return nil, err
	}
	if err := h.SetLEEventMask(0x3FF); err != nil {
		return nil, err
	}
	b.st.ATT.SetMaxMTU(b.mtu)
	if tr, ok := t.(*Transport); ok {
		tr.Snoop = snoop
	}
	b.addService()
	b.adv = btp.AdvertisingData(discriminator, vendorID, productID)
	b.conn.Reset(int(b.mtu))
	return b, nil
}

func (b *Server) addService() {
	a := b.st.ATT
	svc := ble.New16BitUUID(btp.ServiceUUID16)
	start := a.AddLocalAttribute(hci.AttributeTypeService, 0, hci.UUIDPrimaryService.UUID(), 0,
		[]byte{btp.ServiceUUID16 & 0xFF, btp.ServiceUUID16 >> 8})

	// C1: the central writes BTP segments.
	c1 := mustUUID(btp.C1UUID)
	le := c1.BytesLittleEndian()
	decl := a.AddLocalAttribute(hci.AttributeTypeCharacteristic, start, hci.UUIDCharacteristic.UUID(), propRead, le[:])
	val := a.AddLocalAttribute(hci.AttributeTypeCharacteristicValue, decl, c1, propWrite, nil)
	a.AddLocalCharacteristic(decl, propWrite, val, c1, hci.CharacteristicHandler{
		WriteValue: func(data []byte) (int, error) {
			if len(b.writes) < 16 {
				b.writes = append(b.writes, append([]byte(nil), data...))
			}
			return len(data), nil
		},
	})

	// C2: the peripheral notifies BTP segments; the central subscribes.
	c2 := mustUUID(btp.C2UUID)
	le = c2.BytesLittleEndian()
	decl = a.AddLocalAttribute(hci.AttributeTypeCharacteristic, start, hci.UUIDCharacteristic.UUID(), propRead, le[:])
	b.c2 = a.AddLocalAttribute(hci.AttributeTypeCharacteristicValue, decl, c2, propRead, nil)
	end := a.AddLocalAttribute(hci.AttributeTypeDescriptor, decl, hci.UUIDClientCharacteristicConfig.UUID(), propRead|propWrite, []byte{0, 0})
	a.AddLocalCharacteristic(decl, propNotify|propIndicate, b.c2, c2, hci.CharacteristicHandler{
		ReadValue: func() ([]byte, error) { return nil, nil },
		ReadCCCD:  func() (uint16, error) { return b.cccd, nil },
		WriteCCCD: func(v uint16) error {
			b.cccd, b.subscribe = v, true
			return nil
		},
	})
	a.AddLocalService(start, end, svc)
}

// Advertise starts or stops connectable advertising.
func (b *Server) Advertise(on bool) {
	if on == b.advOn {
		return
	}
	h := b.st.HCI
	if on {
		// 20-60 ms for the first 30 s is what the spec recommends; a fixed
		// 100 ms keeps it simple and is still found quickly.
		h.LESetAdvertisingParameters(0xA0, 0xA0, 0x00, 0x00, 0x00, [6]byte{}, 0x07, 0)
		h.LESetAdvertisingData(b.adv)
	}
	h.LESetAdvertiseEnable(on)
	b.advOn = on
}

// Send queues a Matter message for the central.
func (b *Server) Send(pkt []byte) error {
	if !b.connected {
		return nil
	}
	return b.conn.Send(pkt)
}

// Close drops the connection once queued messages have been sent and
// acknowledged, or after a timeout.
func (b *Server) Close(now time.Time) {
	if b.connected && !b.closing {
		b.closing, b.closeBy = true, now.Add(3*time.Second)
	}
}

// Poll services the controller and BTP. deliver receives complete Matter
// messages from the central.
func (b *Server) Poll(now time.Time, deliver func(msg []byte)) {
	for i := 0; i < 16; i++ {
		err := b.st.ATT.Poll()
		b.pollConnectionEvents(now)
		if err != nil {
			break
		}
	}
	if !b.connected {
		return
	}
	if !b.paramsAt.IsZero() && !now.Before(b.paramsAt) {
		b.paramsAt = time.Time{}
		logf("ble: requesting a 6 s supervision timeout")
		b.requestParams()
	}
	b.conn.SetMTU(int(b.st.ATT.MTU()))
	for len(b.writes) > 0 {
		w := b.writes[0]
		b.writes = b.writes[1:]
		msg, err := b.conn.HandleWrite(now, w)
		if err != nil {
			logf("btp:", err.Error())
			b.drop()
			return
		}
		if !b.logged && b.conn.FragmentSize() > 0 {
			b.logged = true
			logf("btp: handshake, MTU", b.st.ATT.MTU(), "segment", b.conn.FragmentSize(), "window", b.conn.Window())
		}
		if msg != nil {
			start := time.Now()
			deliver(msg)
			if d := time.Since(start); d > 50*time.Millisecond {
				logf("ble: message took", int(d/time.Millisecond), "ms")
			}
		}
	}
	if b.subscribe {
		b.subscribe = false
		if b.cccd != 0 {
			b.conn.Subscribed(now)
		}
	}
	for i := 0; i < btp.MaxWindow; i++ {
		pkt, _, err := b.conn.Poll(now)
		if err != nil {
			logf("btp:", err.Error())
			b.drop()
			return
		}
		if pkt == nil {
			break
		}
		if err := b.st.ATT.SendNotification(b.c2, pkt); err != nil {
			logf("ble notify:", err.Error())
		}
	}
	if b.conn.Closed() || b.closing && (b.conn.Flushed() || !now.Before(b.closeBy)) {
		b.drop()
	}
}

func (b *Server) pollConnectionEvents(now time.Time) {
	h := b.st.HCI
	if h.HasConnection() {
		cp, _ := h.Connection()
		c := *cp // ClearConnection zeroes the event
		h.ClearConnection()
		if c.Status == 0 {
			b.connected, b.handle, b.closing = true, c.Handle, false
			b.advOn = false // the controller stops advertising on connection
			b.cccd, b.writes, b.subscribe, b.logged = 0, b.writes[:0], false, false
			b.conn.Reset(int(b.mtu))
			logf("ble: connected")
			// Ask for a long supervision timeout: the link must outlive the
			// CPU stalls of PASE and CASE computations, during which the
			// controller may miss connection events.
			b.paramsAt = now.Add(300 * time.Millisecond)
		}
	}
	if h.HasDisconnection() {
		dc, _ := h.Disconnection()
		reason := int(dc.Reason)
		h.ClearConnection()
		if b.connected {
			logf("ble: disconnected, reason", reason)
		}
		b.connected, b.closing = false, false
		b.cccd, b.writes, b.subscribe, b.paramsAt = 0, b.writes[:0], false, time.Time{}
		b.conn.Reset(int(b.mtu))
	}
}

// snoop logs the connection parameters from LE meta events.
func snoop(pkt []byte) {
	// L2CAP signaling (CID 5): the answer to our parameter request.
	if len(pkt) >= 13 && pkt[0] == 0x02 && binary.LittleEndian.Uint16(pkt[7:]) == hci.CIDSignaling {
		sig := pkt[9:]
		if sig[0] == 0x13 && len(sig) >= 6 {
			logf("ble: parameter request result", int(binary.LittleEndian.Uint16(sig[4:])), "(0 accepted)")
		} else {
			logf("ble: l2cap signaling code", int(sig[0]))
		}
		return
	}
	// pkt: 0x04, 0x3E, length, subevent, parameters
	if len(pkt) < 4 || pkt[0] != 0x04 || pkt[1] != 0x3E {
		return
	}
	p := pkt[4:]
	var interval, timeout, status int
	switch pkt[3] {
	case 0x01: // Connection Complete
		if len(p) < 17 {
			return
		}
		status, interval, timeout = int(p[0]), int(binary.LittleEndian.Uint16(p[11:])), int(binary.LittleEndian.Uint16(p[15:]))
	case 0x0A: // Enhanced Connection Complete
		if len(p) < 29 {
			return
		}
		status, interval, timeout = int(p[0]), int(binary.LittleEndian.Uint16(p[23:])), int(binary.LittleEndian.Uint16(p[27:]))
	case 0x03: // Connection Update Complete
		if len(p) < 9 {
			return
		}
		status, interval, timeout = int(p[0]), int(binary.LittleEndian.Uint16(p[3:])), int(binary.LittleEndian.Uint16(p[7:]))
	default:
		return
	}
	logf("ble: connection parameters, event", int(pkt[3]), "status", status, "interval", interval*5/4, "ms, timeout", timeout*10, "ms")
}

// Connected reports whether a central is connected.
func (b *Server) Connected() bool { return b.connected }

func (b *Server) drop() {
	if b.connected {
		b.st.HCI.Disconnect(b.handle)
	}
	b.closing = false
}
