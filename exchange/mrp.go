package exchange

import (
	"io"
	"time"
)

// MRP parameters (spec 4.12.8).
const (
	// MaxTransmissions is MRP_MAX_TRANSMISSIONS: the initial send plus
	// retransmissions.
	MaxTransmissions = 5
	// StandaloneAckTimeout is MRP_STANDALONE_ACK_TIMEOUT: how long a pending
	// acknowledgement waits for a message to piggyback on.
	StandaloneAckTimeout = 200 * time.Millisecond
)

// MRPConfig holds a node's session parameters for reliable messaging
// (SESSION_IDLE_INTERVAL, SESSION_ACTIVE_INTERVAL,
// SESSION_ACTIVE_THRESHOLD). They are advertised in DNS-SD and exchanged
// during PASE and CASE.
type MRPConfig struct {
	IdleInterval    time.Duration
	ActiveInterval  time.Duration
	ActiveThreshold time.Duration
}

// DefaultMRPConfig holds the spec defaults.
var DefaultMRPConfig = MRPConfig{
	IdleInterval:    500 * time.Millisecond,
	ActiveInterval:  300 * time.Millisecond,
	ActiveThreshold: 4000 * time.Millisecond,
}

// Backoff returns the delay before retransmission number sendCount+1 of a
// message (sendCount 0 is the initial transmission), per spec 4.12.2.1:
//
//	i * MRP_BACKOFF_MARGIN * MRP_BACKOFF_BASE^max(0, n-MRP_BACKOFF_THRESHOLD) * (1 + random*MRP_BACKOFF_JITTER)
//
// It uses the same fixed-point constants as the Matter SDK. jitter is a
// random byte; 255 gives the maximum delay.
func Backoff(base time.Duration, sendCount int, jitter uint8) time.Duration {
	const (
		marginNum, marginDen = 1127, 1024 // MRP_BACKOFF_MARGIN = 1.1
		baseNum, baseDen     = 16, 10     // MRP_BACKOFF_BASE = 1.6
		threshold            = 1          // MRP_BACKOFF_THRESHOLD
		jitterBase           = 1024       // MRP_BACKOFF_JITTER = 0.25
	)
	ms := int64(base / time.Millisecond)
	ms = ms * marginNum / marginDen
	exp := min(max(sendCount-threshold, 0), 4)
	num, den := int64(1), int64(1)
	for range exp {
		num *= baseNum
		den *= baseDen
	}
	ms = ms * num / den
	ms = ms * (jitterBase + int64(jitter)) / jitterBase
	return time.Duration(ms) * time.Millisecond
}

func randByte(r io.Reader) uint8 {
	var b [1]byte
	if r == nil {
		return 0
	}
	io.ReadFull(r, b[:])
	return b[0]
}
