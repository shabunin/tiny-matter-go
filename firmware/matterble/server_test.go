package matterble

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/btp"
	"tinygo.org/x/bluetooth/hci"
)

// fakeController is the controller side of an H4 byte stream. It answers
// commands, records advertising, and splits what the "central" sends into
// ACL fragments of fragSize bytes, as a controller without data length
// extension does.
type fakeController struct {
	t        *testing.T
	rx       []byte   // bytes for the host to read
	acl      [][]byte // L2CAP payloads the host sent (CID 4)
	advData  []byte
	advOn    bool
	disc     bool
	fragSize int
	ops      []uint16 // commands, in order
	longest  int      // longest packet the host wrote
}

func (f *fakeController) Buffered() int { return len(f.rx) }

func (f *fakeController) Read(buf []byte) (int, error) {
	n := copy(buf, f.rx)
	f.rx = f.rx[n:]
	return n, nil
}

func (f *fakeController) Write(buf []byte) (int, error) {
	f.longest = max(f.longest, len(buf))
	switch buf[0] {
	case 0x01: // command
		op := binary.LittleEndian.Uint16(buf[1:])
		f.ops = append(f.ops, op)
		params := buf[4 : 4+int(buf[3])]
		switch op {
		case 0x2008: // LE Set Advertising Data
			f.advData = append([]byte(nil), params[1:1+int(params[0])]...)
		case 0x200A: // LE Set Advertise Enable
			f.advOn = params[0] == 1
		case 0x0406: // Disconnect
			f.disc = true
		}
		// Command Complete: one packet allowed, opcode, status 0.
		f.rx = append(f.rx, 0x04, 0x0E, 4, 1, byte(op), byte(op>>8), 0)
	case 0x02: // ACL data from the host: whole PDUs
		l2 := buf[5:]
		if binary.LittleEndian.Uint16(l2[2:]) == 4 {
			f.acl = append(f.acl, append([]byte(nil), l2[4:]...))
		}
	}
	return len(buf), nil
}

// event queues an HCI event.
func (f *fakeController) event(code byte, params ...byte) {
	f.rx = append(f.rx, 0x04, code, byte(len(params)))
	f.rx = append(f.rx, params...)
}

// att sends an ATT PDU from the central on connection handle 0x40,
// fragmented into ACL packets.
func (f *fakeController) att(pdu []byte) {
	l2 := binary.LittleEndian.AppendUint16(nil, uint16(len(pdu)))
	l2 = binary.LittleEndian.AppendUint16(l2, 4)
	l2 = append(l2, pdu...)
	for i := 0; i < len(l2); i += f.fragSize {
		chunk := l2[i:min(i+f.fragSize, len(l2))]
		pb := uint16(2)
		if i > 0 {
			pb = 1
		}
		f.rx = append(f.rx, 0x02)
		f.rx = binary.LittleEndian.AppendUint16(f.rx, 0x40|pb<<12)
		f.rx = binary.LittleEndian.AppendUint16(f.rx, uint16(len(chunk)))
		f.rx = append(f.rx, chunk...)
	}
}

// takeACL returns and clears the PDUs the host sent.
func (f *fakeController) takeACL() [][]byte {
	a := f.acl
	f.acl = nil
	return a
}

// GATT handles: service 1, C1 declaration 2 and value 3, C2 declaration 4,
// value 5 and CCCD 6.
const (
	hC1   = 3
	hC2   = 5
	hCCCD = 6
)

func writeReq(handle uint16, v []byte) []byte {
	b := []byte{0x12, byte(handle), byte(handle >> 8)}
	return append(b, v...)
}

func setup(t *testing.T) (*Server, *fakeController, *[][]byte) {
	resetDelay = 0
	f := &fakeController{t: t, fragSize: 27}
	s, err := New(NewTransport(f), 3840, 0xFFF1, 0x8000, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	return s, f, &got
}

func poll(s *Server, got *[][]byte) {
	for i := 0; i < 20; i++ {
		s.Poll(time.Unix(1000, 0), func(msg []byte) { *got = append(*got, append([]byte(nil), msg...)) })
	}
}

func TestServer(t *testing.T) {
	s, f, got := setup(t)
	s.Advertise(true)
	if !f.advOn || !bytes.Equal(f.advData, btp.AdvertisingData(3840, 0xFFF1, 0x8000)) {
		t.Fatalf("advertising %v % x", f.advOn, f.advData)
	}

	// LE Connection Complete: handle 0x40, peripheral role.
	f.event(0x3E, 0x01, 0, 0x40, 0, 1, 0, 1, 2, 3, 4, 5, 6, 24, 0, 0, 0, 0x48, 0, 0)
	poll(s, got)
	if !s.Connected() || f.advOn {
		t.Fatalf("connected %v, advertising %v", s.Connected(), f.advOn)
	}

	// MTU exchange, then the handshake in a fragmented write request.
	f.att([]byte{0x02, 247, 0})
	poll(s, got)
	if a := f.takeACL(); len(a) != 1 || !bytes.Equal(a[0], []byte{0x03, 247, 0}) {
		t.Fatalf("MTU response % x", a)
	}
	f.att(writeReq(hC1, []byte{0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, 6}))
	f.att(writeReq(hCCCD, []byte{1, 0}))
	poll(s, got)
	a := f.takeACL()
	if len(a) != 3 || a[0][0] != 0x13 || a[1][0] != 0x13 {
		t.Fatalf("expected two write responses and a notification: % x", a)
	}
	resp := a[2]
	if resp[0] != 0x1B || binary.LittleEndian.Uint16(resp[1:]) != hC2 ||
		!bytes.Equal(resp[3:], []byte{0x65, 0x6C, 4, 244, 0, 6}) {
		t.Fatalf("handshake response % x", resp)
	}

	// A 300-byte message in two segments, acking the response (seq 0).
	msg := bytes.Repeat([]byte("matter!"), 43)[:300]
	seg1 := append([]byte{0x09, 0, 0, 44, 1}, msg[:239]...)
	seg2 := append([]byte{0x06, 1}, msg[239:]...)
	f.att(writeReq(hC1, seg1))
	f.att(writeReq(hC1, seg2))
	poll(s, got)
	if len(*got) != 1 || !bytes.Equal((*got)[0], msg) {
		t.Fatalf("server delivered %d messages", len(*got))
	}
	f.takeACL()

	// The reply goes out as notifications, piggybacking the ack of seq 1.
	reply := bytes.Repeat([]byte{0xAB}, 400)
	if err := s.Send(reply); err != nil {
		t.Fatal(err)
	}
	poll(s, got)
	a = f.takeACL()
	if len(a) != 2 {
		t.Fatalf("%d notifications for a 400-byte reply", len(a))
	}
	first, second := a[0][3:], a[1][3:]
	if first[0] != 0x09 || first[1] != 1 || first[2] != 1 || binary.LittleEndian.Uint16(first[3:]) != 400 {
		t.Fatalf("first segment header % x", first[:5])
	}
	if second[0] != 0x06 || second[1] != 2 {
		t.Fatalf("second segment header % x", second[:2])
	}
	if !bytes.Equal(append(bytes.Clone(first[5:]), second[2:]...), reply) {
		t.Fatal("reply reassembles wrongly")
	}

	// Close waits for the central to acknowledge, then disconnects.
	s.Close(time.Unix(1000, 0))
	poll(s, got)
	if f.disc {
		t.Fatal("disconnected before the reply was acknowledged")
	}
	f.att(writeReq(hC1, []byte{0x08, 2, 2}))
	poll(s, got)
	if !f.disc {
		t.Fatal("not disconnected after the acknowledgement")
	}
	// Disconnection Complete.
	f.event(0x05, 0, 0x40, 0, 0x13)
	poll(s, got)
	if s.Connected() {
		t.Fatal("still connected")
	}
}

// TestOptions checks that Setup runs right after the reset and that a
// smaller MTU caps the ATT MTU, the BTP segments and so every packet the
// server writes (the CYW43439 driver takes at most 252 bytes).
func TestOptions(t *testing.T) {
	resetDelay = 0
	f := &fakeController{t: t, fragSize: 27}
	var setupAfter []uint16
	s, err := New(NewTransport(f), 3840, 0xFFF1, 0x8000, Options{
		MTU: 243,
		Setup: func(h *hci.HCI) error {
			setupAfter = append([]uint16(nil), f.ops...)
			return h.SendVendorCommand(0x0001, []byte{1, 2, 3, 4, 5, 6})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(setupAfter); n == 0 || setupAfter[n-1] != 0x0C03 {
		t.Fatalf("Setup ran after % x, want right after Reset", setupAfter)
	}
	if i := len(setupAfter); len(f.ops) <= i || f.ops[i] != 0xFC01 {
		t.Fatalf("commands % x: the vendor command is not next", f.ops)
	}

	var got [][]byte
	f.event(0x3E, 0x01, 0, 0x40, 0, 1, 0, 1, 2, 3, 4, 5, 6, 24, 0, 0, 0, 0x48, 0, 0)
	poll(s, &got)
	f.att([]byte{0x02, 247, 0})
	poll(s, &got)
	if a := f.takeACL(); len(a) != 1 || !bytes.Equal(a[0], []byte{0x03, 243, 0}) {
		t.Fatalf("MTU response % x", a)
	}
	f.att(writeReq(hC1, []byte{0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, 6}))
	f.att(writeReq(hCCCD, []byte{1, 0}))
	poll(s, &got)
	a := f.takeACL()
	if len(a) != 3 || !bytes.Equal(a[2][3:], []byte{0x65, 0x6C, 4, 240, 0, 6}) {
		t.Fatalf("handshake response % x", a)
	}
	if err := s.Send(bytes.Repeat([]byte{0xAB}, 600)); err != nil {
		t.Fatal(err)
	}
	poll(s, &got)
	if len(f.takeACL()) != 3 || f.longest != 252 {
		t.Fatalf("longest packet %d bytes, want 252", f.longest)
	}
}

func TestConnectAndHandshakeInOnePoll(t *testing.T) {
	s, f, got := setup(t)
	s.Advertise(true)
	f.event(0x3E, 0x01, 0, 0x40, 0, 1, 0, 1, 2, 3, 4, 5, 6, 24, 0, 0, 0, 0x48, 0, 0)
	f.att(writeReq(hC1, []byte{0x65, 0x6C, 0x04, 0, 0, 0, 0, 0, 6}))
	f.att(writeReq(hCCCD, []byte{1, 0}))
	s.Poll(time.Unix(1000, 0), func(msg []byte) { *got = append(*got, append([]byte(nil), msg...)) })
	if !s.Connected() {
		t.Fatal("not connected")
	}
	a := f.takeACL()
	if len(a) != 3 || a[2][0] != 0x1B || binary.LittleEndian.Uint16(a[2][1:]) != hC2 {
		t.Fatalf("expected handshake notification in same Poll batch, got % x", a)
	}
}

func TestTransportReassembly(t *testing.T) {
	f := &fakeController{t: t, fragSize: 5}
	tr := NewTransport(f)
	f.event(0x0E, 4, 1, 3, 0x0C, 0)
	f.att(bytes.Repeat([]byte{7}, 30))
	f.event(0x13, 1, 0x40, 0, 1, 0)
	var pkts [][]byte
	for tr.Buffered() > 0 {
		buf := make([]byte, 300)
		n, _ := tr.Read(buf)
		pkts = append(pkts, buf[:n])
	}
	if len(pkts) != 3 {
		t.Fatalf("%d packets", len(pkts))
	}
	acl := pkts[1]
	if acl[0] != 0x02 || binary.LittleEndian.Uint16(acl[1:])>>12 != 2 ||
		binary.LittleEndian.Uint16(acl[3:]) != 34 || len(acl) != 39 {
		t.Fatalf("reassembled % x", acl)
	}
	if pkts[2][1] != 0x13 {
		t.Fatal("event after the ACL packet lost")
	}
}
