package matterble

import (
	"encoding/binary"
	"runtime"

	"tinygo.org/x/bluetooth/hci"
)

// Source is the controller side: H4 packets (type byte first) as a byte
// stream. Read must not block when Buffered reports data.
type Source interface {
	Buffered() int
	Read(buf []byte) (int, error)
	Write(buf []byte) (int, error)
}

// NewTransport returns a Transport over src.
func NewTransport(src Source) *Transport { return &Transport{t: src} }

// Transport adapts a byte-stream HCI source (such as the espradio VHCI
// ring) to hci.Transport, reassembling ACL
// packets the controller delivers in fragments (the hci package only
// accepts whole L2CAP PDUs). It hands over one packet at a time: the hci
// package reads all that Buffered reports into a buffer of one packet.
type Transport struct {
	t    Source
	in   []byte // raw controller bytes not yet parsed into packets
	out  []byte // whole packets ready for the hci package
	lens []int  // lengths of the packets in out
	cur  int    // unread bytes of the packet at the head of out
	acl  []byte // ACL packet being reassembled (type byte included)
	read [512]byte

	// Snoop, if set, sees every event and reassembled ACL packet before
	// the hci package does.
	Snoop func(pkt []byte)
}

func (v *Transport) StartRead() { runtime.Gosched() }
func (v *Transport) EndRead()   {}

func (v *Transport) Buffered() int {
	v.fill()
	if v.cur == 0 && len(v.lens) > 0 {
		v.cur = v.lens[0]
		v.lens = v.lens[1:]
	}
	return v.cur
}

func (v *Transport) Read(buf []byte) (int, error) {
	if v.Buffered() == 0 {
		return 0, nil
	}
	n := copy(buf, v.out[:v.cur])
	v.out = v.out[n:]
	v.cur -= n
	if len(v.out) == 0 {
		v.out = v.out[:0:0]
	}
	return n, nil
}

func (v *Transport) emit(pkt []byte) {
	v.out = append(v.out, pkt...)
	v.lens = append(v.lens, len(pkt))
}

func (v *Transport) Write(buf []byte) (int, error) { return v.t.Write(buf) }

// fill moves what the controller has delivered into out, packet by packet.
func (v *Transport) fill() {
	for v.t.Buffered() > 0 {
		n, _ := v.t.Read(v.read[:])
		v.in = append(v.in, v.read[:n]...)
	}
	for len(v.in) > 0 {
		var total int
		switch v.in[0] {
		case hci.PacketEvent:
			if len(v.in) < 3 {
				return
			}
			total = 3 + int(v.in[2])
		case hci.PacketACLData:
			if len(v.in) < 5 {
				return
			}
			total = 5 + int(binary.LittleEndian.Uint16(v.in[3:]))
		default: // not expected from a controller: drop what is buffered
			v.in = v.in[:0]
			return
		}
		if len(v.in) < total {
			return
		}
		pkt := v.in[:total]
		if pkt[0] == hci.PacketACLData {
			v.handleACL(pkt)
		} else {
			if v.Snoop != nil {
				v.Snoop(pkt)
			}
			v.emit(pkt)
		}
		v.in = append(v.in[:0], v.in[total:]...)
	}
}

func (v *Transport) handleACL(pkt []byte) {
	hdr := binary.LittleEndian.Uint16(pkt[1:])
	pb := hdr >> 12 & 3
	data := pkt[5:]
	if pb == 1 { // continuing fragment
		if len(v.acl) == 0 || binary.LittleEndian.Uint16(v.acl[1:])&0x0FFF != hdr&0x0FFF {
			return
		}
		v.acl = append(v.acl, data...)
	} else {
		v.acl = append(v.acl[:0], pkt...)
		// Present the reassembled packet as a single start fragment.
		binary.LittleEndian.PutUint16(v.acl[1:], hdr&0x0FFF|2<<12)
	}
	if len(v.acl) < 9 {
		return
	}
	l2len := int(binary.LittleEndian.Uint16(v.acl[5:]))
	if have := len(v.acl) - 9; have < l2len {
		return
	} else if have > l2len {
		v.acl = v.acl[:0]
		return
	}
	binary.LittleEndian.PutUint16(v.acl[3:], uint16(len(v.acl)-5))
	if v.Snoop != nil {
		v.Snoop(v.acl)
	}
	if len(v.acl) <= hci.MaxPacketSize {
		v.emit(v.acl)
	}
	v.acl = v.acl[:0]
}
