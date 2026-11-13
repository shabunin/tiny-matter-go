// Package simnet is a deterministic simulated network of exchange.Managers
// for tests: packets queue until delivered, time advances explicitly.
package simnet

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
)

// Packet is a datagram in flight.
type Packet struct {
	From, To exchange.Addr
	Data     []byte
}

// World holds the nodes, the packet queue and the simulated clock.
type World struct {
	t     testing.TB
	Now   time.Time
	Queue []Packet
	// Drop, if set, discards packets for which it returns true.
	Drop  func(p Packet) bool
	nodes []*Node
}

// Node is one endpoint.
type Node struct {
	M    *exchange.Manager
	Addr exchange.Addr
}

type port struct {
	w    *World
	addr exchange.Addr
}

func (p port) Send(to exchange.Addr, pkt []byte) error {
	pk := Packet{From: p.addr, To: to, Data: bytes.Clone(pkt)}
	if p.w.Drop == nil || !p.w.Drop(pk) {
		p.w.Queue = append(p.w.Queue, pk)
	}
	return nil
}

// New returns an empty world.
func New(t testing.TB) *World { return &World{t: t, Now: time.Unix(1000, 0)} }

// Node adds a node listening on [fe80::1]:port.
func (w *World) Node(p uint16) *Node {
	addr := netip.AddrPortFrom(netip.MustParseAddr("fe80::1"), p)
	m, err := exchange.NewManager(exchange.Config{Transport: port{w, addr}, Rand: rand.Reader})
	if err != nil {
		w.t.Fatal(err)
	}
	n := &Node{M: m, Addr: addr}
	w.nodes = append(w.nodes, n)
	return n
}

// Deliver delivers queued packets until the network is quiet.
func (w *World) Deliver() {
	for len(w.Queue) > 0 {
		p := w.Queue[0]
		w.Queue = w.Queue[1:]
		for _, n := range w.nodes {
			if n.Addr == p.To {
				n.M.HandlePacket(w.Now, p.From, p.Data)
			}
		}
	}
}

// Advance moves time forward by d, firing timers as they come due and
// delivering the resulting packets.
func (w *World) Advance(d time.Duration) {
	end := w.Now.Add(d)
	for {
		var next time.Time
		for _, n := range w.nodes {
			if t := n.M.Poll(w.Now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
				next = t
			}
		}
		w.Deliver()
		if next.IsZero() || next.After(end) {
			break
		}
		if next.After(w.Now) {
			w.Now = next
		}
	}
	w.Now = end
}
