// Package dnssd describes the DNS-SD services a Matter node advertises
// (spec 4.3): the commissionable node service and one operational service
// per fabric. Publishing them is left to an Advertiser (an mDNS responder).
package dnssd

import (
	"strconv"
	"time"
)

// Service is one DNS-SD service instance.
type Service struct {
	Instance string   // instance name
	Type     string   // e.g. "_matterc._udp"
	Subtypes []string // e.g. "_L3840"
	Port     uint16
	TXT      []string // "key=value"
}

// Advertiser publishes services, replacing what it published before.
type Advertiser interface {
	Advertise(services []Service)
}

// MRP intervals advertised in TXT records.
type MRP struct {
	Idle, Active, ActiveThreshold time.Duration
}

func (m MRP) txt() []string {
	return []string{
		"SII=" + strconv.Itoa(int(m.Idle/time.Millisecond)),
		"SAI=" + strconv.Itoa(int(m.Active/time.Millisecond)),
		"SAT=" + strconv.Itoa(int(m.ActiveThreshold/time.Millisecond)),
		"T=0", // no TCP
	}
}

// Commissionable describes the commissionable node service (spec 4.3.1).
type Commissionable struct {
	Instance      uint64 // random, regenerated per window
	Port          uint16
	Discriminator uint16 // 12 bits
	VendorID      uint16
	ProductID     uint16
	DeviceType    uint32
	DeviceName    string
	MRP           MRP
	// Mode is 1 for basic commissioning (passcode), 2 for enhanced.
	Mode int
}

// Service returns the _matterc._udp service.
func (c *Commissionable) Service() Service {
	s := Service{
		Instance: hex16(c.Instance),
		Type:     "_matterc._udp",
		Port:     c.Port,
		Subtypes: []string{
			"_L" + strconv.Itoa(int(c.Discriminator)),
			"_S" + strconv.Itoa(int(c.Discriminator>>8)),
			"_V" + strconv.Itoa(int(c.VendorID)),
			"_CM",
		},
		TXT: []string{
			"D=" + strconv.Itoa(int(c.Discriminator)),
			"CM=" + strconv.Itoa(c.Mode),
			"VP=" + strconv.Itoa(int(c.VendorID)) + "+" + strconv.Itoa(int(c.ProductID)),
			"PH=33",
		},
	}
	if c.DeviceType != 0 {
		s.Subtypes = append(s.Subtypes, "_T"+strconv.Itoa(int(c.DeviceType)))
		s.TXT = append(s.TXT, "DT="+strconv.Itoa(int(c.DeviceType)))
	}
	if c.DeviceName != "" {
		s.TXT = append(s.TXT, "DN="+c.DeviceName)
	}
	s.TXT = append(s.TXT, c.MRP.txt()...)
	return s
}

// Operational describes the operational service of one fabric (spec 4.3.2).
type Operational struct {
	CompressedFabricID [8]byte
	NodeID             uint64
	Port               uint16
	MRP                MRP
}

// Service returns the _matter._tcp service.
func (o *Operational) Service() Service {
	var cf uint64
	for _, b := range o.CompressedFabricID {
		cf = cf<<8 | uint64(b)
	}
	return Service{
		Instance: hex16(cf) + "-" + hex16(o.NodeID),
		Type:     "_matter._tcp",
		Port:     o.Port,
		Subtypes: []string{"_I" + hex16(cf)},
		TXT:      o.MRP.txt(),
	}
}

func hex16(v uint64) string {
	const digits = "0123456789ABCDEF"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = digits[v&0xF]
		v >>= 4
	}
	return string(b[:])
}
