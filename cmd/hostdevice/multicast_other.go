//go:build !unix

package main

import (
	"log"
	"net"
	"net/netip"
)

// groupMemberships tracks Matter group multicast addresses on platforms
// where IPv6 multicast membership is not configured via Unix setsockopt.
type groupMemberships struct {
	c      *net.UDPConn
	joined map[netip.Addr]bool
}

func (g *groupMemberships) set(addrs []netip.Addr) {
	if len(addrs) > 0 && len(g.joined) == 0 {
		log.Print("multicast group joins are not supported on this OS")
	}
	clear(g.joined)
	for _, a := range addrs {
		g.joined[a] = true
	}
}
