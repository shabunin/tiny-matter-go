package device

import (
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
)

// Subscription resumption (spec 8.5.1, as the SDK does it): established
// subscriptions are saved with the state. Those a restart ended, and those
// whose subscriber stopped answering, are resumed: the device opens a CASE
// session to the subscriber (found with DNS-SD, or where it was last
// reached) and reports all the paths under the subscription's ID, which
// the subscriber still holds. A subscriber that no longer knows the ID
// answers so, which ends the subscription; one that cannot be reached is
// tried again, less and less often, until resumeDelays runs out.

// resumeDelays is how long after a failed attempt (the subscription's
// tries) the next one starts; after the last, the subscription is ended.
var resumeDelays = [...]time.Duration{
	5 * time.Second, 30 * time.Second, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute,
	30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 6 * time.Hour,
}

// resumeBootDelay is the least wait after a start before the first
// resumption (the SDK waits the longest min interval of the subscriptions,
// so a node in a reboot loop does not flood its subscribers).
const resumeBootDelay = 5 * time.Second

type resumer struct {
	d       *Device
	at      time.Time       // next round (zero: none planned)
	pending map[uint32]bool // being resumed
}

func (d *Device) resumer() *resumer {
	if d.resume == nil {
		d.resume = &resumer{d: d, pending: map[uint32]bool{}}
	}
	return d.resume
}

// boot plans the first round after a start: after the longest min interval
// of the subscriptions restored.
func (r *resumer) boot(now time.Time) {
	wait := resumeBootDelay
	n := 0
	r.d.Server.Lost(func(s im.LostSubscription) {
		n++
		if s.Min > wait {
			wait = s.Min
		}
	})
	if n > 0 {
		r.d.log("resuming " + strconv.Itoa(n) + " subscription(s) in " + wait.String())
		r.at = now.Add(wait)
	}
}

// poll starts the attempts that are due and returns when it next needs to
// run (zero: idle).
func (r *resumer) poll(now time.Time) time.Time {
	if !r.at.IsZero() && now.Before(r.at) {
		return r.at
	}
	round := !r.at.IsZero()
	r.at = time.Time{}
	var drop []uint32
	r.d.Server.Lost(func(s im.LostSubscription) {
		if r.pending[s.ID] {
			return
		}
		if int(s.Tries) >= len(resumeDelays) {
			drop = append(drop, s.ID)
			return
		}
		if !round {
			r.plan(now.Add(resumeDelays[s.Tries])) // lost since the last round
			return
		}
		r.start(now, s)
	})
	for _, id := range drop {
		r.d.log("subscription " + hex64(uint64(id))[8:] + ": subscriber not reached; ended")
		r.d.Server.Drop(id)
	}
	if round {
		// Plan the round after this one, for attempts that fail.
		return r.poll(now)
	}
	return r.at
}

// plan moves the next round to t if that is sooner.
func (r *resumer) plan(t time.Time) {
	if r.at.IsZero() || t.Before(r.at) {
		r.at = t
	}
}

// start queues an attempt to resume s with the binding machinery, which
// finds the subscriber and opens (or reuses) a CASE session to it.
func (r *resumer) start(now time.Time, s im.LostSubscription) {
	id := s.ID
	r.pending[id] = true
	k := peerKey{s.Fabric, s.Peer}
	b := r.d.bound()
	if p := b.peers[k]; (p == nil || !p.addr.IsValid()) && s.Addr.IsValid() {
		if p == nil {
			p = &boundPeer{}
			b.peers[k] = p
		}
		p.addr = s.Addr // used if DNS-SD does not find it
	}
	b.queue(now, k, &boundCall{expires: now.Add(boundExpiry),
		run: func(now time.Time, sess *exchange.Session) {
			delete(r.pending, id)
			if r.d.Server.Resume(now, sess, id) {
				r.d.log("subscription " + hex64(uint64(id))[8:] + " resumed")
			}
		},
		expired: func(now time.Time) {
			delete(r.pending, id)
			r.d.Server.ResumeFailed(id)
			if int(s.Tries)+1 < len(resumeDelays) {
				r.plan(now.Add(resumeDelays[s.Tries+1]))
			} else {
				r.plan(now)
			}
		},
	})
}
