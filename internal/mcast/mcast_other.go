//go:build !linux

// Package mcast sends UDP datagrams to IPv6 multicast addresses on hosts.
package mcast

import (
	"net"
	"net/netip"
)

// Send sends pkt to a multicast address out of the default interface.
func Send(conn *net.UDPConn, to netip.AddrPort, pkt []byte) ([]string, error) {
	_, err := conn.WriteToUDPAddrPort(pkt, to)
	if err != nil {
		return nil, err
	}
	return []string{"default"}, nil
}
