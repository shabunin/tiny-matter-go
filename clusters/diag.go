package clusters

import (
	"runtime"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// SoftwareDiagnostics is the Software Diagnostics cluster (endpoint 0) with
// the current heap attributes. The high watermark (the WTRMRK feature) is
// left out: the Go and TinyGo runtimes do not track it, and one sampled at
// reads would understate it.
type SoftwareDiagnostics struct {
	im.ClusterBase
	// Heap, if set, returns the free and used heap in bytes (RuntimeHeap,
	// say). Without it the cluster has no heap attributes.
	Heap func() (free, used uint64)
}

func (*SoftwareDiagnostics) ID() uint32       { return IDSoftwareDiagnostics }
func (*SoftwareDiagnostics) Revision() uint16 { return 1 }

const (
	sdCurrentHeapFree = 0x01
	sdCurrentHeapUsed = 0x02
)

var swDiagHeapAttrs = []uint32{sdCurrentHeapFree, sdCurrentHeapUsed}

func (s *SoftwareDiagnostics) Attributes() []uint32 {
	if s.Heap == nil {
		return nil
	}
	return swDiagHeapAttrs
}

func (s *SoftwareDiagnostics) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	if s.Heap == nil {
		return im.UnsupportedAttribute
	}
	free, used := s.Heap()
	switch attr {
	case sdCurrentHeapFree:
		w.PutUint(tag, free)
	case sdCurrentHeapUsed:
		w.PutUint(tag, used)
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

// RuntimeHeap returns the heap the Go runtime has free and in use. Under
// TinyGo "in use" includes garbage not yet collected, and free space may be
// fragmented: a large allocation can fail with much free.
func RuntimeHeap() (free, used uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapIdle - m.HeapReleased, m.HeapInuse
}

// Wi-Fi security types (SecurityTypeEnum).
const (
	WiFiSecurityUnspecified = 0
	WiFiSecurityNone        = 1
	WiFiSecurityWEP         = 2
	WiFiSecurityWPA         = 3
	WiFiSecurityWPA2        = 4
	WiFiSecurityWPA3        = 5
)

// WiFiStatus is what a node knows of its Wi-Fi association. Attributes it
// does not know read as null, as the spec allows.
type WiFiStatus struct {
	Connected  bool
	BSSID      [6]byte // all zero: unknown
	Security   uint8   // WiFiSecurity*; Unspecified when unknown
	Version    uint8   // WiFiVersionEnum (0 a, 1 b, 2 g, 3 n, 4 ac, 5 ax, 6 ah)
	HasVersion bool
	Channel    uint16 // 0: unknown
	RSSI       int8
	HasRSSI    bool
}

// WiFiNetworkDiagnostics is the Wi-Fi Network Diagnostics cluster
// (endpoint 0 of a Wi-Fi node), without the packet and error counts.
type WiFiNetworkDiagnostics struct {
	im.ClusterBase
	// Status, if set, returns the current association; without it every
	// attribute is null.
	Status func() WiFiStatus
}

func (*WiFiNetworkDiagnostics) ID() uint32       { return IDWiFiDiagnostics }
func (*WiFiNetworkDiagnostics) Revision() uint16 { return 1 }

const (
	wdBSSID         = 0x00
	wdSecurityType  = 0x01
	wdWiFiVersion   = 0x02
	wdChannelNumber = 0x03
	wdRSSI          = 0x04
)

var wifiDiagAttrs = []uint32{wdBSSID, wdSecurityType, wdWiFiVersion, wdChannelNumber, wdRSSI}

func (*WiFiNetworkDiagnostics) Attributes() []uint32 { return wifiDiagAttrs }

func (c *WiFiNetworkDiagnostics) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	var s WiFiStatus
	if c.Status != nil {
		s = c.Status()
	}
	switch attr {
	case wdBSSID:
		if !s.Connected || s.BSSID == [6]byte{} {
			w.PutNull(tag)
		} else {
			w.PutBytes(tag, s.BSSID[:])
		}
	case wdSecurityType:
		if !s.Connected {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(s.Security))
		}
	case wdWiFiVersion:
		if !s.Connected || !s.HasVersion {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(s.Version))
		}
	case wdChannelNumber:
		if !s.Connected || s.Channel == 0 {
			w.PutNull(tag)
		} else {
			w.PutUint(tag, uint64(s.Channel))
		}
	case wdRSSI:
		if !s.Connected || !s.HasRSSI {
			w.PutNull(tag)
		} else {
			w.PutInt(tag, int64(s.RSSI))
		}
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}
