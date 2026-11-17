package device

import (
	"errors"
	"net/netip"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Sending through bindings: a command for a bound node waits in its
// peer's queue while the node is looked up with DNS-SD and a CASE session
// established (or an open one reused), then is invoked. A newer command
// for the same endpoint and cluster replaces one still waiting (and goes
// after the others), so a sensor that changes its mind sends only its
// latest state.
const (
	boundExpiry      = 30 * time.Second // a command not delivered by then is dropped
	boundResolveTime = 5 * time.Second  // looking a node up before using its last address
	boundRetry       = 2 * time.Second
)

type peerKey struct {
	fabric uint8
	node   uint64
}

type boundCall struct {
	endpoint uint16
	cluster  uint32
	cmd      uint32
	fields   func(w *tlv.Writer)
	expires  time.Time
}

type boundPeer struct {
	calls     []*boundCall
	busy      bool           // connecting or invoking
	addr      netip.AddrPort // where the node was last reached
	lookUntil time.Time      // resolving until (zero: not resolving)
	at        time.Time      // next step (zero: now)
}

type binder struct {
	d     *Device
	peers map[peerKey]*boundPeer
}

// NewBinding returns a Binding cluster for an application endpoint whose
// client clusters send commands through it (add it to the endpoint, and
// the clients to Endpoint.Clients).
func (d *Device) NewBinding() *clusters.Binding { return &clusters.Binding{} }

// SendBound invokes a command of cluster on every node target the
// endpoint's Binding cluster holds for that cluster, from the target's
// fabric. Delivery is asynchronous and best effort; failures are logged.
// It reports how many targets the command is queued for.
func (d *Device) SendBound(now time.Time, endpoint uint16, cluster, cmd uint32, fields func(w *tlv.Writer)) int {
	e := d.Node.Endpoint(endpoint)
	if e == nil {
		return 0
	}
	b, ok := e.Cluster(clusters.IDBinding).(*clusters.Binding)
	if !ok {
		return 0
	}
	n := 0
	for _, t := range b.Targets {
		if !t.For(cluster) {
			continue
		}
		if t.IsGroup() {
			d.log("binding: group targets are not supported yet")
			continue
		}
		d.bound().queue(now, peerKey{t.FabricIndex, t.Node}, &boundCall{
			endpoint: t.Endpoint, cluster: cluster, cmd: cmd, fields: fields, expires: now.Add(boundExpiry)})
		n++
	}
	return n
}

func (d *Device) bound() *binder {
	if d.binder == nil {
		d.binder = &binder{d: d, peers: map[peerKey]*boundPeer{}}
	}
	return d.binder
}

func (b *binder) queue(now time.Time, k peerKey, c *boundCall) {
	p := b.peers[k]
	if p == nil {
		p = &boundPeer{}
		b.peers[k] = p
	}
	// A waiting command for the same endpoint and cluster is dropped (one in
	// flight is the first, while busy), and the new one goes last: at most
	// one of each waits, in the order they were last given. So a knob's Off
	// then a level still ends with the level, and a colour and the level
	// command that follows it alternate without piling up.
	first := 0
	if p.busy {
		first = 1
	}
	for i := first; i < len(p.calls); i++ {
		if p.calls[i].endpoint == c.endpoint && p.calls[i].cluster == c.cluster {
			p.calls = append(p.calls[:i], p.calls[i+1:]...)
			break
		}
	}
	p.calls = append(p.calls, c)
	if !p.busy {
		p.at = time.Time{}
	}
}

func (b *binder) log(k peerKey, msg string) {
	b.d.log("binding: node " + hex64(k.node) + ": " + msg)
}

// poll moves every peer's queue along and returns when it next needs to
// run (zero: idle).
func (b *binder) poll(now time.Time) time.Time {
	var next time.Time
	for k, p := range b.peers {
		if !p.busy {
			b.step(now, k, p)
		}
		if p.busy || len(p.calls) == 0 {
			continue
		}
		if t := p.at; !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	return next
}

func (b *binder) fabric(k peerKey) *fabric.Fabric {
	f := b.d.Fabrics.Get(k.fabric)
	if f == nil || f.Pending {
		return nil
	}
	return f
}

// step starts delivering a peer's first command if it is due.
func (b *binder) step(now time.Time, k peerKey, p *boundPeer) {
	for len(p.calls) > 0 && !now.Before(p.calls[0].expires) {
		b.log(k, "command not delivered in time; dropped")
		p.calls = p.calls[1:]
	}
	if len(p.calls) == 0 {
		p.lookUntil, p.at = time.Time{}, time.Time{}
		return
	}
	if !p.at.IsZero() && now.Before(p.at) {
		return
	}
	fab := b.fabric(k)
	if fab == nil {
		b.log(k, "fabric gone; commands dropped")
		p.calls = nil
		return
	}
	for _, s := range b.d.M.Sessions() {
		if s.IsSecure() && !s.Closed() && s.AuthMode == exchange.AuthCASE && s.FabricIndex == k.fabric &&
			s.PeerNodeID() == k.node {
			b.invoke(now, k, p, s, true)
			return
		}
	}
	if resolve := b.d.cfg.Resolve; resolve != nil {
		if p.lookUntil.IsZero() {
			p.lookUntil = now.Add(boundResolveTime)
		}
		if addr, ok := resolve(now, fab.CompressedFabricID, k.node); ok {
			p.addr = addr
		} else if now.Before(p.lookUntil) {
			p.at = now.Add(250 * time.Millisecond)
			return
		}
	}
	p.lookUntil = time.Time{}
	if !p.addr.IsValid() {
		b.log(k, "not found")
		p.at = now.Add(boundRetry)
		return
	}
	p.busy = true
	err := casesession.Connect(now, b.d.M, p.addr, casesession.InitiatorConfig{
		Fabric: fab, PeerNodeID: k.node, Rand: b.d.cfg.Rand, Resumptions: b.d.Resumptions,
		Done: func(now time.Time, s *exchange.Session, err error) {
			p.busy = false
			if err != nil {
				b.log(k, "CASE: "+err.Error())
				p.at = now.Add(boundRetry)
				return
			}
			b.invoke(now, k, p, s, false)
		},
	})
	if err != nil {
		p.busy = false
		b.log(k, "CASE: "+err.Error())
		p.at = now.Add(boundRetry)
	}
}

// invoke sends the peer's first command on s. A failure on a session
// that was already open closes it, as the peer may have restarted and
// lost it; the command is then retried with a new one.
func (b *binder) invoke(now time.Time, k peerKey, p *boundPeer, s *exchange.Session, reused bool) {
	c := p.calls[0]
	p.busy = true
	inv := &im.Invocation{Timeout: 5 * time.Second, Done: func(now time.Time, res im.InvokeResult, err error) {
		p.busy = false
		if err == nil && res.Status != im.Success {
			err = res.Status
		}
		var st im.Status
		if err != nil && !errors.As(err, &st) {
			// The session failed (no answer): drop it and retry.
			b.log(k, err.Error())
			if !s.Closed() {
				b.d.M.CloseSession(now, s)
			}
			if !reused {
				p.addr = netip.AddrPort{} // look it up again
			}
			p.at = now.Add(boundRetry / 4)
			return
		}
		if err != nil {
			b.log(k, "command failed: "+err.Error())
		}
		if len(p.calls) > 0 && p.calls[0] == c {
			p.calls = p.calls[1:]
		}
		p.at = time.Time{}
		if s.Peer.IsValid() {
			p.addr = s.Peer
		}
	}}
	path := im.CommandPath{Endpoint: c.endpoint, Cluster: c.cluster, Command: c.cmd}
	if err := inv.Start(now, b.d.M, s, path, c.fields); err != nil {
		p.busy = false
		b.log(k, err.Error())
		p.at = now.Add(boundRetry)
	}
}

// removeFabricBindings drops a removed fabric's targets on every endpoint.
func (d *Device) removeFabricBindings(index uint8) {
	for _, e := range d.Node.Endpoints() {
		if b, ok := e.Cluster(clusters.IDBinding).(*clusters.Binding); ok {
			b.RemoveFabric(d.Node, e.ID, index)
		}
	}
	if d.binder != nil {
		for k := range d.binder.peers {
			if k.fabric == index && !d.binder.peers[k].busy {
				delete(d.binder.peers, k)
			}
		}
	}
}

func hex64(v uint64) string {
	const digits = "0123456789ABCDEF"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = digits[v&15]
		v >>= 4
	}
	return string(b[:])
}
