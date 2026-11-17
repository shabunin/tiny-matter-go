package controller

import (
	"net/netip"

	"github.com/shabunin/tiny-matter-go/internal/mcast"
)

// sendMulticast sends a packet to an IPv6 multicast address out of each
// interface (group members may be on any of them).
func (c *Controller) sendMulticast(to netip.AddrPort, pkt []byte) error {
	ifs, err := mcast.Send(c.conn, to, pkt)
	for _, name := range ifs {
		c.logf("group message to %v on %s", to.Addr(), name)
	}
	return err
}
