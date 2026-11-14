package clusters

import (
	"time"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Switch events.
const (
	EventInitialPress = 0x01
	EventLongPress    = 0x02
	EventShortRelease = 0x03
	EventLongRelease  = 0x04
)

// Switch features.
const (
	featureMomentarySwitch          = 1 << 1
	featureMomentarySwitchRelease   = 1 << 2
	featureMomentarySwitchLongPress = 1 << 3
)

// DefaultLongPress is how long a press lasts before it is a long press.
const DefaultLongPress = time.Second

// Switch is the Switch cluster for a momentary two-position switch, such
// as a push button, that reports releases and long presses (features MS,
// MSR and MSL). Press and Release feed it the button state; a press
// generates InitialPress, then LongPress once it lasts LongPressTime,
// and the release ShortRelease or LongRelease.
type Switch struct {
	im.ClusterBase
	// LongPressTime is the long-press threshold (DefaultLongPress if
	// zero).
	LongPressTime time.Duration

	pressed   bool
	long      bool
	pressedAt time.Time
}

func (*Switch) ID() uint32       { return IDSwitch }
func (*Switch) Revision() uint16 { return 2 }
func (*Switch) FeatureMap() uint32 {
	return featureMomentarySwitch | featureMomentarySwitchRelease | featureMomentarySwitchLongPress
}

var (
	switchAttrs  = []uint32{0, 1}
	switchEvents = []uint32{EventInitialPress, EventLongPress, EventShortRelease, EventLongRelease}
)

func (*Switch) Attributes() []uint32 { return switchAttrs }
func (*Switch) Events() []uint32     { return switchEvents }

// Pressed reports whether the switch is pressed.
func (s *Switch) Pressed() bool { return s.pressed }

func (s *Switch) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0: // NumberOfPositions
		w.PutUint(tag, 2)
	case 1: // CurrentPosition
		w.PutUint(tag, uint64(s.position()))
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (s *Switch) position() uint8 {
	if s.pressed {
		return 1
	}
	return 0
}

func (s *Switch) emit(n *im.Node, endpoint uint16, now time.Time, event uint32) {
	n.Emit(now, im.Event{
		Path:     im.ConcreteEventPath{Endpoint: endpoint, Cluster: IDSwitch, Event: event},
		Priority: im.PriorityInfo,
		// NewPosition or PreviousPosition: the pressed position.
		Fields: func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 1) },
	})
}

// Press records that the switch on endpoint was pressed.
func (s *Switch) Press(n *im.Node, endpoint uint16, now time.Time) {
	if s.pressed {
		return
	}
	s.pressed, s.long, s.pressedAt = true, false, now
	n.Changed(endpoint, IDSwitch, 1)
	s.emit(n, endpoint, now, EventInitialPress)
}

// Release records that the switch on endpoint was released.
func (s *Switch) Release(n *im.Node, endpoint uint16, now time.Time) {
	if !s.pressed {
		return
	}
	s.Poll(n, endpoint, now) // a long press not yet reported
	s.pressed = false
	n.Changed(endpoint, IDSwitch, 1)
	if s.long {
		s.emit(n, endpoint, now, EventLongRelease)
	} else {
		s.emit(n, endpoint, now, EventShortRelease)
	}
}

// Poll reports a long press once the switch has been held long enough
// (im.Poller).
func (s *Switch) Poll(n *im.Node, endpoint uint16, now time.Time) time.Time {
	if !s.pressed || s.long {
		return time.Time{}
	}
	d := s.LongPressTime
	if d <= 0 {
		d = DefaultLongPress
	}
	at := s.pressedAt.Add(d)
	if now.Before(at) {
		return at
	}
	s.long = true
	s.emit(n, endpoint, now, EventLongPress)
	return time.Time{}
}
