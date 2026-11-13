package message

import (
	"encoding/binary"
	"errors"
	"io"
)

// CounterWindowSize is MSG_COUNTER_WINDOW_SIZE (spec 4.6.5).
const CounterWindowSize = 32

var (
	// ErrDuplicate is returned for a message counter that was already seen
	// or is too old to tell.
	ErrDuplicate = errors.New("message: duplicate message counter")
	// ErrCounterExhausted is returned when an encrypted session has used all
	// of its message counters and must be re-established.
	ErrCounterExhausted = errors.New("message: message counter exhausted")
)

// Counter is a local outgoing message counter (spec 4.6.1).
type Counter struct {
	next uint32
}

// NewCounter returns a counter whose first value is a random number in
// [1, 2^28], as required for both the global unencrypted counter and secure
// session counters.
func NewCounter(rand io.Reader) (Counter, error) {
	var b [4]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return Counter{}, err
	}
	return Counter{next: binary.LittleEndian.Uint32(b[:])&0x0FFFFFFF + 1}, nil
}

// Next returns the next counter value for an encrypted session, which must
// never wrap (spec 4.6.1.1).
func (c *Counter) Next() (uint32, error) {
	if c.next == 0 {
		return 0, ErrCounterExhausted
	}
	v := c.next
	c.next++ // wraps to 0 after 0xFFFFFFFF, marking exhaustion
	return v, nil
}

// NextWrapping returns the next value of a counter that may roll over, such
// as the global unencrypted message counter.
func (c *Counter) NextWrapping() uint32 {
	v := c.next
	c.next++
	return v
}

// ReceptionState tracks counters received from one peer to reject replays
// (spec 4.6.5): the largest counter seen and a bitmap of the
// CounterWindowSize counters before it. Bit i of window is counter max-1-i.
//
// Check is separate from Commit so that a message is only recorded after it
// authenticates.
type ReceptionState struct {
	synced bool
	max    uint32
	window uint32
}

// Reset forgets all state; the next counter will be trusted where allowed.
func (s *ReceptionState) Reset() { *s = ReceptionState{} }

// SetCounter synchronizes the state to max with an empty window. Secure
// unicast sessions start synchronized to 0.
func (s *ReceptionState) SetCounter(max uint32) {
	*s = ReceptionState{synced: true, max: max}
}

// Synced reports whether the state holds a reference counter.
func (s *ReceptionState) Synced() bool { return s.synced }

type position uint8

const (
	posBefore position = iota
	posInWindow
	posMax
	posFuture
)

func (s *ReceptionState) classify(c uint32, rollover bool) position {
	if rollover {
		if d := c - s.max; d >= 1 && d <= 1<<31-1 {
			return posFuture
		}
	} else if c > s.max {
		return posFuture
	}
	if c == s.max {
		return posMax
	}
	if s.max-c <= CounterWindowSize {
		return posInWindow
	}
	return posBefore
}

func (s *ReceptionState) seen(c uint32) bool {
	return s.window&(1<<(s.max-c-1)) != 0
}

func (s *ReceptionState) verifyEncrypted(c uint32, rollover bool) error {
	switch s.classify(c, rollover) {
	case posFuture:
		return nil
	case posInWindow:
		if s.seen(c) {
			return ErrDuplicate
		}
		return nil
	}
	return ErrDuplicate
}

func (s *ReceptionState) commit(c uint32, rollover bool) {
	switch s.classify(c, rollover) {
	case posInWindow:
		s.window |= 1 << (s.max - c - 1)
	case posMax:
	default: // future, or before the window for unencrypted rollover
		shift := c - s.max
		s.max = c
		if shift > CounterWindowSize {
			s.window = 0
		} else {
			// shift is in [1, 32]; shifting a uint32 by 32 yields 0 in Go.
			s.window = s.window<<shift | 1<<(shift-1)
		}
	}
}

// CheckEncryptedUnicast verifies a counter of an encrypted unicast session.
// Counters never roll over within a session.
func (s *ReceptionState) CheckEncryptedUnicast(c uint32) error {
	if !s.synced {
		return errors.New("message: peer counter not synchronized")
	}
	return s.verifyEncrypted(c, false)
}

// CommitEncryptedUnicast records an authenticated encrypted unicast counter.
func (s *ReceptionState) CommitEncryptedUnicast(c uint32) { s.commit(c, false) }

// CheckGroup verifies a counter of an encrypted group message. The first
// counter from a peer is trusted.
func (s *ReceptionState) CheckGroup(c uint32) error {
	if !s.synced {
		return nil
	}
	return s.verifyEncrypted(c, true)
}

// CommitGroup records an authenticated group counter.
func (s *ReceptionState) CommitGroup(c uint32) { s.commitTrustFirst(c) }

// CheckUnencrypted verifies a counter of an unencrypted message. Only exact
// duplicates within the window are rejected: a counter behind the window is
// accepted (the peer may have rebooted), and the first is trusted.
func (s *ReceptionState) CheckUnencrypted(c uint32) error {
	if !s.synced {
		return nil
	}
	switch s.classify(c, true) {
	case posMax:
		return ErrDuplicate
	case posInWindow:
		if s.seen(c) {
			return ErrDuplicate
		}
	}
	return nil
}

// CommitUnencrypted records an unencrypted counter.
func (s *ReceptionState) CommitUnencrypted(c uint32) { s.commitTrustFirst(c) }

func (s *ReceptionState) commitTrustFirst(c uint32) {
	if !s.synced {
		s.SetCounter(c)
		return
	}
	s.commit(c, true)
}
