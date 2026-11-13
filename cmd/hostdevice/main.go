// Command hostdevice runs the stack on a host over UDP for interoperability
// testing against a Matter controller such as chip-tool. It uses the SDK
// test passcode (20202021) and salt.
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/securechannel/pase"
)

type udpTransport struct{ c *net.UDPConn }

func (t udpTransport) Send(to exchange.Addr, pkt []byte) error {
	_, err := t.c.WriteToUDPAddrPort(pkt, to)
	return err
}

func main() {
	addr := flag.String("listen", "[::]:5540", "UDP listen address")
	passcode := flag.Uint("passcode", 20202021, "setup passcode")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	salt := []byte("SPAKE2P Key Salt")
	const iterations = 1000
	v, err := spake2p.NewVerifier(uint32(*passcode), salt, iterations)
	if err != nil {
		log.Fatal(err)
	}

	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}
	m, err := exchange.NewManager(exchange.Config{Transport: udpTransport{conn}, Rand: rand.Reader})
	if err != nil {
		log.Fatal(err)
	}
	d := securechannel.NewDispatcher(m)
	r, err := pase.NewResponder(m, d, pase.ResponderConfig{
		Verifier: v, Salt: salt, Iterations: iterations, Rand: rand.Reader,
		OnEstablished: func(now time.Time, s *exchange.Session) {
			log.Printf("PASE session established with %v (local session %d)", s.Peer, s.LocalSessionID())
		},
		OnFailed: func(now time.Time, err error) { log.Printf("PASE failed: %v", err) },
	})
	if err != nil {
		log.Fatal(err)
	}
	r.OpenWindow()
	log.Printf("listening on %v, passcode %d", conn.LocalAddr(), *passcode)

	buf := make([]byte, 1280)
	for {
		deadline := m.Poll(time.Now())
		if deadline.IsZero() {
			deadline = time.Now().Add(time.Hour)
		}
		conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			log.Fatal(err)
		}
		if err := m.HandlePacket(time.Now(), from, buf[:n]); err != nil {
			log.Printf("drop packet from %v: %v", from, err)
		}
	}
}
