//go:build !linux

package controller

import "net/netip"

// sendMulticast sends a packet to a multicast address out of the default
// interface.
func (c *Controller) sendMulticast(to netip.AddrPort, pkt []byte) error {
	_, err := c.conn.WriteToUDPAddrPort(pkt, to)
	return err
}
