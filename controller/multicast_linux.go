package controller

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// sendMulticast sends a packet to an IPv6 multicast address out of each
// up, multicast-capable interface (group members may be on any of them).
func (c *Controller) sendMulticast(to netip.AddrPort, pkt []byte) error {
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	rc, err := c.conn.SyscallConn()
	if err != nil {
		return err
	}
	var errs []error
	sent := false
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifc.Index)
		}); err != nil {
			return err
		}
		if serr == nil {
			_, serr = c.conn.WriteToUDPAddrPort(pkt, to)
		}
		if serr != nil {
			errs = append(errs, serr)
			continue
		}
		sent = true
		c.logf("group message to %v on %s", to.Addr(), ifc.Name)
	}
	if sent {
		return nil
	}
	if len(errs) == 0 {
		return errors.New("controller: no multicast interface is up")
	}
	return errors.Join(errs...)
}
