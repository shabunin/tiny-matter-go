// Package controller is a Matter controller for hosts. It keeps its own
// fabric (a root CA it generates and stores), commissions devices onto it
// over the IP network or Bluetooth LE (giving them a Wi-Fi network), and
// reads, writes, invokes and subscribes on them. Devices are found with
// mDNS, or in BLE advertisements. Device attestation is checked against a
// PAA trust store.
//
// Commissioned nodes grant Administer to a CASE Authenticated Tag rather
// than to one node ID. Each opened Controller is a node of its own with
// that tag, so several processes can work with the same nodes at once
// without being taken for one peer at different addresses.
//
// One goroutine owns the protocol state; the methods are safe for
// concurrent use and block until their operation completes or their
// context ends.
package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
)

// Options configures a controller.
type Options struct {
	// Dir holds the controller's state: its fabric keys and the nodes it
	// commissioned. It is created if needed.
	Dir string
	// PAAs are the trusted product attestation authorities, such as
	// attestation.ProductionPAAs, plus attestation.TestPAAs for
	// development devices.
	PAAs []*x509.Certificate
	// AllowTestCD accepts certification declarations signed with the SDK
	// test key.
	AllowTestCD bool
	// Port is the local UDP port (0: any free port).
	Port int
	// Log, if set, receives progress messages.
	Log func(msg string)
	// NoDiscovery disables mDNS: nodes are reached at their stored or
	// given addresses only.
	NoDiscovery bool
	// Bluetooth is used to commission over BLE. If nil, BlueZ is used
	// (over D-Bus, on Linux) when first needed.
	Bluetooth Bluetooth
}

// ErrClosed is returned by operations on a closed controller.
var ErrClosed = errors.New("controller: closed")

// ErrUnknownNode is returned for a node ID the controller has not
// commissioned.
var ErrUnknownNode = errors.New("controller: unknown node")

// Controller is a Matter controller with its own fabric.
type Controller struct {
	opts Options

	mu        sync.Mutex // guards st and reserving
	st        *state
	reserving map[uint64]struct{}

	rootKey *p256.PrivateKey
	root    *credentials.Cert
	fab     *fabric.Fabric
	fabrics *fabric.Table // fab, for the CASE responder

	conn    *net.UDPConn
	m       *exchange.Manager
	disc    *discovery
	packets chan packet
	calls   chan func(now time.Time)
	quit    chan struct{}
	done    chan struct{}

	connMu   sync.Mutex
	connLock map[uint64]*sync.Mutex // serializes CASE attempts per node

	bleMu sync.Mutex
	ble   Bluetooth

	// Owned by the loop goroutine.
	// groupTo, if valid, receives group messages instead of their
	// multicast address (for tests).
	groupTo netip.AddrPort

	sessions map[uint64]*exchange.Session
	subs     map[uint32]*subState
	server   *im.Server // serves nodes' requests (the OTA provider), if set
	links    map[netip.AddrPort]*bleLink
	nextLink uint16
	// resumptions lets reconnects to nodes skip the full CASE handshake;
	// kept in memory, as each run of the controller has its own node ID.
	resumptions *casesession.ResumptionStore
	id          *identity
}

type packet struct {
	from netip.AddrPort
	b    []byte
}

// Open loads (or creates) the controller's fabric in opts.Dir and starts
// it.
func Open(opts Options) (*Controller, error) {
	st, err := loadState(opts.Dir)
	if err != nil {
		return nil, err
	}
	c := &Controller{
		opts: opts, st: st,
		packets:  make(chan packet, 64),
		calls:    make(chan func(time.Time)),
		quit:     make(chan struct{}),
		done:     make(chan struct{}),
		connLock: make(map[uint64]*sync.Mutex),
		sessions: make(map[uint64]*exchange.Session),
		subs:     make(map[uint32]*subState),
		links:    make(map[netip.AddrPort]*bleLink),

		resumptions: &casesession.ResumptionStore{Max: 64},
	}
	if c.rootKey, err = p256.NewPrivateKey(st.RootKey); err != nil {
		return nil, err
	}
	if c.root, err = credentials.DecodeCert(st.Root); err != nil {
		return nil, err
	}
	key, err := p256.NewPrivateKey(st.Key)
	if err != nil {
		return nil, err
	}
	// This controller's identity: a node ID of its own, with the
	// administrator CAT, and the sessions it can resume (see identity).
	if c.id, err = claimIdentity(opts.Dir, c.resumptions); err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			c.id.release()
		}
	}()
	c.resumptions.OnChange = func() {
		if err := c.id.save(c.resumptions); err != nil {
			c.logf("saving CASE resumption records: %v", err)
		}
	}
	noc, err := credentials.IssueNOC(c.root, c.rootKey, key.PublicKey().Bytes(), st.FabricID, c.id.NodeID, st.AdminCAT)
	if err != nil {
		return nil, err
	}
	c.fabrics = &fabric.Table{}
	if c.fab, err = c.fabrics.Add(st.Root, nil, noc.Encode(), key, st.IPK, st.VendorID); err != nil {
		return nil, fmt.Errorf("controller: stored fabric: %w", err)
	}
	if c.conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: opts.Port}); err != nil {
		return nil, err
	}
	c.m, err = exchange.NewManager(exchange.Config{
		Transport: c, Rand: rand.Reader, Clock: time.Now,
		MaxSecureSessions: 64, MaxUnsecuredSessions: 8, MaxExchanges: 128,
	})
	if err != nil {
		c.conn.Close()
		return nil, err
	}
	disp := securechannel.NewDispatcher(c.m)
	disp.Handle(securechannel.OpStatusReport, func(ex *exchange.Exchange) exchange.Delegate {
		return closeHandler{c}
	})
	// Nodes may open CASE sessions to the controller, as OTA requestors
	// do to their provider.
	casesession.NewResponder(c.m, disp, casesession.ResponderConfig{Fabrics: c.fabrics, Rand: rand.Reader, Resumptions: c.resumptions})
	c.m.Register(message.ProtocolInteractionModel, c.imFactory)
	if !opts.NoDiscovery {
		if c.disc, err = newDiscovery(); err != nil {
			c.conn.Close()
			return nil, err
		}
	}
	go c.read()
	go c.loop()
	opened = true
	return c, nil
}

// Close stops the controller. Its sessions are closed, which tells nodes
// to end their subscriptions; the state stays on disk.
func (c *Controller) Close() error {
	select {
	case <-c.quit:
		return nil
	default:
	}
	c.CloseSessions(0)
	var links []*bleLink
	c.do(func(time.Time) {
		for _, l := range c.links {
			links = append(links, l)
		}
	})
	for _, l := range links {
		l.close()
	}
	close(c.quit)
	<-c.done
	if c.disc != nil {
		c.disc.close()
	}
	c.bleMu.Lock()
	if c.ble != nil && c.opts.Bluetooth == nil {
		closeBluetooth(c.ble)
	}
	c.bleMu.Unlock()
	c.id.release()
	return c.conn.Close()
}

// LocalAddr returns the controller's UDP address.
func (c *Controller) LocalAddr() netip.AddrPort { return c.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// NodeID returns the node ID of this controller on its fabric, which is
// new each time it is opened.
func (c *Controller) NodeID() uint64 { return c.fab.NodeID }

// AdminCAT returns the CASE Authenticated Tag that nodes commissioned by
// the controller grant Administer to.
func (c *Controller) AdminCAT() uint32 { return c.st.AdminCAT }

// FabricID returns the controller's fabric ID.
func (c *Controller) FabricID() uint64 { return c.fab.FabricID }

// CompressedFabricID returns the compressed fabric ID, which names the
// fabric's nodes in DNS-SD.
func (c *Controller) CompressedFabricID() [8]byte { return c.fab.CompressedFabricID }

// Nodes returns the commissioned nodes.
func (c *Controller) Nodes() []Node {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Node, len(c.st.Nodes))
	for i, n := range c.st.Nodes {
		out[i] = *n
	}
	return out
}

// Node returns a commissioned node.
func (c *Controller) Node(id uint64) (Node, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.st.node(id); n != nil {
		return *n, true
	}
	return Node{}, false
}

// SetLabel renames a node in the controller's records.
func (c *Controller) SetLabel(id uint64, label string) error {
	return c.update(id, func(n *Node) { n.Label = label })
}

// update changes a node record and saves the state.
func (c *Controller) update(id uint64, f func(n *Node)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.st.node(id)
	if n == nil {
		return ErrUnknownNode
	}
	f(n)
	return c.st.save(c.opts.Dir)
}

func (c *Controller) logf(format string, args ...any) {
	if c.opts.Log != nil {
		c.opts.Log(fmt.Sprintf(format, args...))
	}
}

// Send transmits a packet (exchange.Transport), over UDP or, for a BLE
// link's address, BTP. It runs on the loop goroutine.
func (c *Controller) Send(to exchange.Addr, pkt []byte) error {
	if isBLE(to) {
		if l := c.links[to]; l != nil {
			return l.send(pkt)
		}
		return errLinkClosed
	}
	if to.Addr().IsMulticast() {
		if c.groupTo.IsValid() {
			to = c.groupTo
		} else {
			return c.sendMulticast(to, pkt)
		}
	}
	_, err := c.conn.WriteToUDPAddrPort(pkt, to)
	return err
}

func (c *Controller) read() {
	buf := make([]byte, 2048)
	for {
		n, from, err := c.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // closed
		}
		p := packet{netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), bytes.Clone(buf[:n])}
		select {
		case c.packets <- p:
		case <-c.quit:
			return
		}
	}
}

// loop runs the protocol: packets, calls from other goroutines, and
// timers.
func (c *Controller) loop() {
	defer close(c.done)
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		now := time.Now()
		next := c.m.Poll(now)
		if t := c.pollSubs(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
		wait := time.Second
		if !next.IsZero() {
			wait = min(max(next.Sub(now), time.Millisecond), time.Second)
		}
		timer.Reset(wait)
		select {
		case p := <-c.packets:
			if err := c.m.HandlePacket(time.Now(), p.from, p.b); err != nil {
				c.logf("drop packet from %v: %v", p.from, err)
			}
		case f := <-c.calls:
			f(time.Now())
		case <-timer.C:
		case <-c.quit:
			return
		}
	}
}

// do runs f on the loop goroutine and waits until it returns.
func (c *Controller) do(f func(now time.Time)) error {
	ran := make(chan struct{})
	select {
	case c.calls <- func(now time.Time) { f(now); close(ran) }:
		<-ran
		return nil
	case <-c.done:
		return ErrClosed
	}
}

// closeHandler handles unsolicited Secure Channel status reports: a
// CloseSession from a peer releases the session.
type closeHandler struct{ c *Controller }

func (h closeHandler) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if sr, err := securechannel.ParseStatusReport(msg.Payload); err == nil &&
		sr.ProtocolCode == securechannel.CodeCloseSession && ex.Session().IsSecure() {
		h.c.forget(ex.Session())
		h.c.m.CloseSession(now, ex.Session())
		return
	}
	ex.Close(now)
}

func (closeHandler) OnError(time.Time, *exchange.Exchange, error) {}

// forget drops a session from the cache (loop goroutine).
func (c *Controller) forget(s *exchange.Session) {
	for id, cached := range c.sessions {
		if cached == s {
			delete(c.sessions, id)
		}
	}
}

func (c *Controller) nodeLock(id uint64) *sync.Mutex {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	l := c.connLock[id]
	if l == nil {
		l = &sync.Mutex{}
		c.connLock[id] = l
	}
	return l
}

// session returns a CASE session to a node, establishing one if there is
// none.
func (c *Controller) session(ctx context.Context, id uint64) (*exchange.Session, error) {
	if s := c.cachedSession(id); s != nil {
		return s, nil
	}
	l := c.nodeLock(id)
	l.Lock()
	defer l.Unlock()
	if s := c.cachedSession(id); s != nil {
		return s, nil
	}
	n, ok := c.Node(id)
	if !ok {
		return nil, ErrUnknownNode
	}
	addrs := c.operationalAddrs(ctx, id, n.Addr)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("controller: node %d not found on the network", id)
	}
	var lastErr error
	for _, a := range addrs {
		s, err := c.connect(ctx, id, a)
		if err == nil {
			if a.String() != n.Addr {
				c.update(id, func(n *Node) { n.Addr = a.String() })
			}
			return s, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("controller: CASE with node %d: %w", id, lastErr)
}

func (c *Controller) cachedSession(id uint64) *exchange.Session {
	var s *exchange.Session
	c.do(func(time.Time) {
		if cached := c.sessions[id]; cached != nil && !cached.Closed() {
			s = cached
		} else {
			delete(c.sessions, id)
		}
	})
	return s
}

// operationalAddrs returns where a node may be: the addresses mDNS finds
// for it, then its last known address.
func (c *Controller) operationalAddrs(ctx context.Context, id uint64, last string) []netip.AddrPort {
	var out []netip.AddrPort
	if c.disc != nil {
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		in, err := c.disc.operational(dctx, c.fab.CompressedFabricID, id)
		cancel()
		if err == nil {
			out = instanceAddrs(in)
		}
	}
	if a, err := netip.ParseAddrPort(last); err == nil && !containsAddr(out, a) {
		out = append(out, a)
	}
	return out
}

func containsAddr(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// connect runs CASE with a node at addr.
func (c *Controller) connect(ctx context.Context, id uint64, addr netip.AddrPort) (*exchange.Session, error) {
	type result struct {
		s   *exchange.Session
		err error
	}
	res := make(chan result, 1)
	err := c.do(func(now time.Time) {
		how := ""
		if c.resumptions.Resumable(c.fab, id) {
			how = " (resuming)"
		}
		c.logf("CASE with node %d at %v%s", id, addr, how)
		err := casesession.Connect(now, c.m, addr, casesession.InitiatorConfig{
			Fabric: c.fab, PeerNodeID: id, Rand: rand.Reader, Resumptions: c.resumptions,
			Done: func(now time.Time, s *exchange.Session, err error) {
				if err == nil {
					if old := c.sessions[id]; old != nil && old != s {
						c.m.CloseSession(now, old)
					}
					c.sessions[id] = s
				}
				res <- result{s, err}
			},
		})
		if err != nil {
			res <- result{nil, err}
		}
	})
	if err != nil {
		return nil, err
	}
	select {
	case r := <-res:
		return r.s, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// withSession runs f with a CASE session to a node. If the session turns
// out to be dead (the device restarted, or closed it), it reconnects and
// runs f once more.
func (c *Controller) withSession(ctx context.Context, id uint64, f func(s *exchange.Session) error) error {
	for attempt := 0; ; attempt++ {
		s, err := c.session(ctx, id)
		if err != nil {
			return err
		}
		err = f(s)
		if attempt > 0 || !sessionFailure(err) || ctx.Err() != nil {
			return err
		}
		c.logf("node %d: %v; reconnecting", id, err)
		c.do(func(now time.Time) {
			c.forget(s)
			c.m.CloseSession(now, s)
		})
	}
}

func sessionFailure(err error) bool {
	return errors.Is(err, exchange.ErrDeliveryFailed) || errors.Is(err, exchange.ErrSessionClosed) ||
		errors.Is(err, errResponseTimeout)
}

// CloseSessions closes the CASE sessions to a node (or to all nodes if id
// is 0), telling the node; the next operation reconnects.
func (c *Controller) CloseSessions(id uint64) {
	c.do(func(now time.Time) {
		for nid, s := range c.sessions {
			if id == 0 || nid == id {
				delete(c.sessions, nid)
				securechannel.CloseSession(now, c.m, s)
			}
		}
	})
}

func (c *Controller) reserveNodeID(requested uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inUse := func(id uint64) bool {
		if id == 0 || c.st.node(id) != nil {
			return true
		}
		_, busy := c.reserving[id]
		return busy
	}
	id := requested
	if id == 0 {
		for inUse(c.st.NextNodeID) {
			c.st.NextNodeID++
		}
		id = c.st.NextNodeID
		c.st.NextNodeID++
	} else if c.st.node(id) != nil {
		return 0, fmt.Errorf("controller: node %d exists", id)
	} else if _, busy := c.reserving[id]; busy {
		return 0, fmt.Errorf("controller: node %d is being commissioned", id)
	}
	if c.reserving == nil {
		c.reserving = make(map[uint64]struct{})
	}
	c.reserving[id] = struct{}{}
	return id, nil
}

func (c *Controller) releaseNodeID(id uint64) {
	c.mu.Lock()
	delete(c.reserving, id)
	c.mu.Unlock()
}
