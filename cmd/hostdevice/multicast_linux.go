package main

import (
	"log"
	"net"
	"net/netip"
	"syscall"
)

// groupMemberships keeps the socket a member of the Matter group multicast
// addresses the device listens on, on every up multicast interface.
type groupMemberships struct {
	c      *net.UDPConn
	joined map[netip.Addr]bool
}

func (g *groupMemberships) set(addrs []netip.Addr) {
	want := map[netip.Addr]bool{}
	for _, a := range addrs {
		want[a] = true
	}
	for a := range g.joined {
		if !want[a] {
			g.setsockopt(syscall.IPV6_LEAVE_GROUP, a)
			delete(g.joined, a)
		}
	}
	for a := range want {
		if !g.joined[a] {
			g.setsockopt(syscall.IPV6_JOIN_GROUP, a)
			g.joined[a] = true
			log.Printf("listening on group address %v", a)
		}
	}
}

func (g *groupMemberships) setsockopt(opt int, a netip.Addr) {
	ifs, err := net.Interfaces()
	if err != nil {
		log.Print(err)
		return
	}
	rc, err := g.c.SyscallConn()
	if err != nil {
		log.Print(err)
		return
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		mreq := &syscall.IPv6Mreq{Multiaddr: a.As16(), Interface: uint32(ifc.Index)}
		rc.Control(func(fd uintptr) {
			err = syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, opt, mreq)
		})
		if err != nil {
			log.Printf("multicast membership of %v on %s: %v", a, ifc.Name, err)
		}
	}
}
