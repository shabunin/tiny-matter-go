//go:build unix

// Package mcast sends UDP datagrams to IPv6 multicast addresses on hosts,
// out of every interface: group members may be on any of them.
package mcast

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// Send sends pkt to a multicast address out of each up, multicast-capable,
// non-loopback interface, and returns the names of those it went out of.
func Send(conn *net.UDPConn, to netip.AddrPort, pkt []byte) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		errs []error
		sent []string
	)
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifc.Index)
		}); err != nil {
			return sent, err
		}
		if serr == nil {
			_, serr = conn.WriteToUDPAddrPort(pkt, to)
		}
		if serr != nil {
			errs = append(errs, serr)
			continue
		}
		sent = append(sent, ifc.Name)
	}
	if len(sent) > 0 {
		return sent, nil
	}
	if len(errs) == 0 {
		return nil, errors.New("mcast: no multicast interface is up")
	}
	return nil, errors.Join(errs...)
}
