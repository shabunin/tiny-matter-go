package controller

import "net/netip"

// SetGroupDestination sends group messages to a unicast address instead
// of their multicast address.
func (c *Controller) SetGroupDestination(to netip.AddrPort) { c.groupTo = to }
