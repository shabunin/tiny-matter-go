package controller

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/onboarding"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// timedWindow is the timed interaction window for commands that require
// one, in milliseconds.
const timedWindow = 5000

// RemoveNode removes the controller's fabric from a node (RemoveFabric)
// and then forgets the node. A node that cannot be reached is not
// forgotten; use ForgetNode for that.
func (c *Controller) RemoveNode(ctx context.Context, id uint64) error {
	rep, err := c.Read(ctx, id, im.Request{Attributes: []im.AttributePath{
		{Cluster: clOperationalCreds, Attribute: attrCurrentFabricIx}}})
	if err != nil {
		return err
	}
	index := rep.uint(clOperationalCreds, attrCurrentFabricIx, 0)
	if index == 0 {
		return fmt.Errorf("controller: node %d did not report its fabric index", id)
	}
	// No retry: once the fabric is gone, so is the session.
	s, err := c.session(ctx, id)
	if err != nil {
		return err
	}
	res, err := c.invokeOn(ctx, s, ocCmd(cmdRemoveFabric), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), index)
	})
	if err == nil {
		err = nocError(res.Fields)
	}
	if err != nil {
		return fmt.Errorf("controller: RemoveFabric: %w", err)
	}
	return c.ForgetNode(id)
}

// ForgetNode drops a node from the controller's records without telling
// the node, which keeps the fabric until it is removed there.
func (c *Controller) ForgetNode(id uint64) error {
	c.CloseSessions(id)
	c.do(func(time.Time) { c.resumptions.Forget(c.fab.Index, id) })
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.removeNodeLocked(id) {
		return ErrUnknownNode
	}
	return c.st.save(c.opts.Dir)
}

// Window is an open commissioning window: the onboarding payload another
// commissioner uses, and when the window closes.
type Window struct {
	Payload  onboarding.Payload
	Deadline time.Time
}

// OpenWindow opens a commissioning window on a node with a new passcode
// (the enhanced commissioning method), so another administrator can
// commission it onto their fabric. timeout is between 3 and 15 minutes.
func (c *Controller) OpenWindow(ctx context.Context, id uint64, timeout time.Duration) (*Window, error) {
	n, ok := c.Node(id)
	if !ok {
		return nil, ErrUnknownNode
	}
	secs := uint64(timeout / time.Second)
	if secs < 180 || secs > 900 {
		return nil, fmt.Errorf("controller: window timeout %v out of range 3m..15m", timeout)
	}
	var passcode uint32
	for passcode == 0 || !onboarding.ValidPasscode(passcode) {
		passcode = randUint32() % 100000000
	}
	discriminator := uint16(randUint32() & 0xFFF)
	salt := make([]byte, 32)
	rand.Read(salt)
	const iterations = 1000
	v, err := spake2p.NewVerifier(passcode, salt, iterations)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	_, err = c.Invoke(ctx, id, im.CommandPath{Cluster: clAdminCommissioning, Command: cmdOpenWindow}, timedWindow,
		func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), secs)
			w.PutBytes(tlv.ContextTag(1), v.Bytes())
			w.PutUint(tlv.ContextTag(2), uint64(discriminator))
			w.PutUint(tlv.ContextTag(3), iterations)
			w.PutBytes(tlv.ContextTag(4), salt)
		})
	if err != nil {
		return nil, fmt.Errorf("controller: OpenCommissioningWindow: %w", err)
	}
	return &Window{
		Payload: onboarding.Payload{VendorID: n.VendorID, ProductID: n.ProductID,
			Flow: onboarding.FlowStandard, Discovery: onboarding.DiscoveryOnNetwork,
			Discriminator: discriminator, Passcode: passcode},
		Deadline: start.Add(timeout),
	}, nil
}

// CloseWindow closes a node's open commissioning window.
func (c *Controller) CloseWindow(ctx context.Context, id uint64) error {
	_, err := c.Invoke(ctx, id, im.CommandPath{Cluster: clAdminCommissioning, Command: cmdRevokeCommissioning}, timedWindow, nil)
	if err != nil {
		return fmt.Errorf("controller: RevokeCommissioning: %w", err)
	}
	return nil
}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}
