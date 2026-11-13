// Two exchange.Managers talking over an in-memory transport on an MCU target:
// secure session, request/response with piggybacked acks.
package main

import (
	"bytes"
	"net/netip"
	"time"

	"tinymatter/exchange"
	"tinymatter/message"
)

// NOT secure: deterministic stand-in for a hardware TRNG.
type xr struct{ s uint32 }

func (x *xr) Read(b []byte) (int, error) {
	for i := range b {
		x.s = x.s*1664525 + 1013904223
		b[i] = byte(x.s >> 24)
	}
	return len(b), nil
}

type pkt struct {
	to   netip.AddrPort
	from netip.AddrPort
	data []byte
}

var queue []pkt

type tr struct{ me netip.AddrPort }

func (t tr) Send(to netip.AddrPort, p []byte) error {
	queue = append(queue, pkt{to, t.me, bytes.Clone(p)})
	return nil
}

type echo struct{ got string }

func (e *echo) OnMessage(now time.Time, ex *exchange.Exchange, m exchange.Message) {
	e.got = string(m.Payload)
	if !ex.IsInitiator() {
		ex.Send(now, m.ProtocolID, m.Opcode+1, []byte("reply:"+e.got))
	}
}
func (e *echo) OnError(now time.Time, ex *exchange.Exchange, err error) { println("error:", err.Error()) }

func main() {
	rng := &xr{7}
	aAddr := netip.MustParseAddrPort("[fe80::1]:5540")
	bAddr := netip.MustParseAddrPort("[fe80::2]:5540")
	a, _ := exchange.NewManager(exchange.Config{Transport: tr{aAddr}, Rand: rng})
	b, _ := exchange.NewManager(exchange.Config{Transport: tr{bAddr}, Rand: rng})
	srv := &echo{}
	b.Register(message.ProtocolInteractionModel, func(ex *exchange.Exchange) exchange.Delegate { return srv })

	now := time.Unix(0, 0)
	k1, k2 := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	sa, _ := a.NewSecureSession(now, exchange.SecureSessionParams{Peer: bAddr, LocalSessionID: 1, PeerSessionID: 2, EncryptKey: k1, DecryptKey: k2})
	b.NewSecureSession(now, exchange.SecureSessionParams{Peer: aAddr, LocalSessionID: 2, PeerSessionID: 1, EncryptKey: k2, DecryptKey: k1})

	cli := &echo{}
	ex, _ := a.NewExchange(sa, cli)
	ex.Send(now, message.ProtocolInteractionModel, 0x02, []byte("hello matter"))
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if p.to == bAddr {
			b.HandlePacket(now, p.from, p.data)
		} else {
			a.HandlePacket(now, p.from, p.data)
		}
	}
	println("server got:", srv.got)
	println("client got:", cli.got)
	println("ok:", cli.got == "reply:hello matter" && !ex.AwaitingAck())
}
