package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/credentials/attestation"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const cmdUpdateNOC = 0x07

// UpdateNOC gives a node a new operational certificate and key on the
// controller's fabric (UpdateNOC), as node newID, or with its current ID
// if newID is 0. The node makes a new key under the fail-safe; the
// controller issues its certificate, then commits the change over a CASE
// session to the new identity. If that fails the node rolls back when its
// fail-safe expires.
func (c *Controller) UpdateNOC(ctx context.Context, id, newID uint64) (*Node, error) {
	if _, ok := c.Node(id); !ok {
		return nil, ErrUnknownNode
	}
	if newID == 0 {
		newID = id
	} else if newID != id {
		if _, err := c.reserveNodeID(newID); err != nil {
			return nil, err
		}
		defer c.releaseNodeID(newID)
	}
	s, err := c.session(ctx, id)
	if err != nil {
		return nil, err
	}
	step := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, stepTimeout) }

	sctx, cancel := step()
	res, err := c.invokeOn(sctx, s, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), failSafeSeconds)
		w.PutUint(tlv.ContextTag(1), 0)
	})
	cancel()
	if err = commissioningError("ArmFailSafe", res, err); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed && !s.Closed() {
			// Roll back now rather than when the fail-safe expires.
			dctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
			c.invokeOn(dctx, s, gcCmd(cmdArmFailSafe), 0, func(w *tlv.Writer) {
				w.PutUint(tlv.ContextTag(0), 0)
				w.PutUint(tlv.ContextTag(1), 0)
			})
			cancel()
		}
	}()

	// The node's DAC, to check its CSR with.
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, s, ocCmd(cmdCertificateChain), 0, func(w *tlv.Writer) {
		w.PutUint(tlv.ContextTag(0), certTypeDAC)
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: CertificateChainRequest: %w", err)
	}
	dac, err := bytesField(res.Fields, 0)
	if err != nil {
		return nil, fmt.Errorf("controller: CertificateChainResponse: %w", err)
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, s, ocCmd(cmdCSRRequest), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), nonce)
		w.PutBool(tlv.ContextTag(1), true) // IsForUpdateNOC
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("controller: CSRRequest: %w", err)
	}
	nocsr, err1 := bytesField(res.Fields, 0)
	signature, err2 := bytesField(res.Fields, 1)
	if err1 != nil || err2 != nil {
		return nil, errors.New("controller: malformed CSRResponse")
	}
	pub, err := attestation.VerifyNOCSR(dac, nocsr, signature, s.AttestationChallenge[:], nonce)
	if err != nil {
		return nil, err
	}
	noc, err := credentials.IssueNOC(c.root, c.rootKey, pub, c.fab.FabricID, newID)
	if err != nil {
		return nil, err
	}
	sctx, cancel = step()
	res, err = c.invokeOn(sctx, s, ocCmd(cmdUpdateNOC), 0, func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), noc.Encode())
	})
	cancel()
	if err == nil {
		err = nocError(res.Fields)
	}
	if err != nil {
		return nil, fmt.Errorf("controller: UpdateNOC: %w", err)
	}
	c.logf("node %d has a new certificate as node %d", id, newID)

	// The old session belongs to the old identity: commit over a new one.
	c.do(func(now time.Time) {
		c.forget(s)
		securechannel.CloseSession(now, c.m, s)
		c.resumptions.Forget(c.fab.Index, id)
	})
	committed = true // the session is gone; on failure the fail-safe rolls back
	if newID != id {
		c.mu.Lock()
		c.st.node(id).ID = newID
		c.mu.Unlock()
	}
	err = c.withSession(ctx, newID, func(s *exchange.Session) error {
		sctx, cancel := step()
		defer cancel()
		res, err := c.invokeOn(sctx, s, gcCmd(cmdCommissioningComplete), 0, nil)
		return commissioningError("CommissioningComplete", res, err)
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if newID != id {
			c.st.node(newID).ID = id
		}
		return nil, fmt.Errorf("%w (the node keeps its old certificate once its fail-safe expires)", err)
	}
	if err := c.st.save(c.opts.Dir); err != nil {
		return nil, err
	}
	out := *c.st.node(newID)
	return &out, nil
}
