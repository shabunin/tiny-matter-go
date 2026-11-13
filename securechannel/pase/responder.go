package pase

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

const (
	// MaxFailedAttempts is how many failed PASE attempts close the
	// commissioning window (spec 5.4.2.6 / 4.14.1).
	MaxFailedAttempts = 20
	// handshakeTimeout bounds how long an unfinished handshake blocks others.
	handshakeTimeout = 60 * time.Second
	// busyWait is the minimum wait advertised in a Busy status report.
	busyWait = 1000 // milliseconds
)

var (
	ErrWindowClosed = errors.New("pase: commissioning window closed")
	ErrConfirm      = errors.New("pase: key confirmation failed (wrong passcode?)")
	ErrUnexpected   = errors.New("pase: unexpected message")
)

// ResponderConfig configures the device side of PASE.
type ResponderConfig struct {
	Verifier      *spake2p.Verifier
	Salt          []byte
	Iterations    uint32
	SessionParams securechannel.SessionParams // advertised to commissioners
	Rand          io.Reader

	// OnEstablished is called with each new PASE session.
	OnEstablished func(now time.Time, s *exchange.Session)
	// OnFailed, if set, is called when a handshake fails.
	OnFailed func(now time.Time, err error)
}

// Responder is the device side of PASE. It accepts handshakes only while
// its commissioning window is open, one at a time.
type Responder struct {
	cfg     ResponderConfig
	m       *exchange.Manager
	open    bool
	failed  int
	current *responderHandshake
}

// NewResponder returns a Responder and registers it with d for
// PBKDFParamRequest. The commissioning window starts closed.
func NewResponder(m *exchange.Manager, d *securechannel.Dispatcher, cfg ResponderConfig) (*Responder, error) {
	if cfg.Verifier == nil || len(cfg.Salt) < spake2p.MinSaltSize || len(cfg.Salt) > spake2p.MaxSaltSize ||
		cfg.Iterations < spake2p.MinIterations || cfg.Iterations > spake2p.MaxIterations || cfg.Rand == nil {
		return nil, errors.New("pase: invalid responder configuration")
	}
	if cfg.SessionParams == (securechannel.SessionParams{}) {
		cfg.SessionParams = securechannel.DefaultSessionParams
	}
	r := &Responder{cfg: cfg, m: m}
	d.Handle(securechannel.OpPBKDFParamRequest, r.factory)
	return r, nil
}

// OpenWindow allows PASE (opens the commissioning window).
func (r *Responder) OpenWindow() { r.open, r.failed = true, 0 }

// CloseWindow stops accepting new PASE handshakes.
func (r *Responder) CloseWindow() { r.open = false }

// WindowOpen reports whether PASE is accepted.
func (r *Responder) WindowOpen() bool { return r.open }

func (r *Responder) factory(ex *exchange.Exchange) exchange.Delegate {
	if ex.Session().IsSecure() {
		return nil // PASE runs over unsecured sessions only
	}
	return &responderHandshake{r: r}
}

type responderState uint8

const (
	waitPBKDFRequest responderState = iota
	waitPake1
	waitPake3
	finished
)

type responderHandshake struct {
	r       *Responder
	state   responderState
	started time.Time
	ctx     hash.Hash
	spake   *spake2p.Session

	localSessionID uint16
	peerSessionID  uint16
	peerParams     securechannel.SessionParams
}

func (h *responderHandshake) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if msg.ProtocolID != message.ProtocolSecureChannel {
		h.fail(now, ex, ErrUnexpected, true)
		return
	}
	if msg.Opcode == securechannel.OpStatusReport {
		err := error(ErrUnexpected)
		if sr, perr := securechannel.ParseStatusReport(msg.Payload); perr == nil {
			err = &securechannel.StatusError{Report: sr}
		}
		h.fail(now, ex, err, false)
		return
	}
	var err error
	switch {
	case h.state == waitPBKDFRequest && msg.Opcode == securechannel.OpPBKDFParamRequest:
		err = h.onPBKDFParamRequest(now, ex, msg.Payload)
	case h.state == waitPake1 && msg.Opcode == securechannel.OpPASEPake1:
		err = h.onPake1(now, ex, msg.Payload)
	case h.state == waitPake3 && msg.Opcode == securechannel.OpPASEPake3:
		err = h.onPake3(now, ex, msg.Payload)
	default:
		err = ErrUnexpected
	}
	if err != nil {
		h.fail(now, ex, err, true)
	}
}

func (h *responderHandshake) OnError(now time.Time, ex *exchange.Exchange, err error) {
	h.release()
	if h.r.cfg.OnFailed != nil {
		h.r.cfg.OnFailed(now, err)
	}
}

func (h *responderHandshake) release() {
	h.state = finished
	if h.r.current == h {
		h.r.current = nil
	}
}

// fail ends the handshake, optionally telling the peer.
func (h *responderHandshake) fail(now time.Time, ex *exchange.Exchange, err error, report bool) {
	if h.state == finished {
		return
	}
	if report {
		securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(
			securechannel.GeneralFailure, securechannel.CodeInvalidParameter))
	}
	ex.Close(now)
	h.release()
	if errors.Is(err, ErrConfirm) {
		if h.r.failed++; h.r.failed >= MaxFailedAttempts {
			h.r.CloseWindow()
		}
	}
	if h.r.cfg.OnFailed != nil {
		h.r.cfg.OnFailed(now, err)
	}
}

func (h *responderHandshake) onPBKDFParamRequest(now time.Time, ex *exchange.Exchange, payload []byte) error {
	r := h.r
	if !r.open {
		return ErrWindowClosed
	}
	if c := r.current; c != nil && c != h && now.Sub(c.started) < handshakeTimeout {
		// Another commissioner is mid-handshake: ask this one to retry.
		sr := securechannel.SecureChannelStatus(securechannel.GeneralBusy, securechannel.CodeBusy)
		sr.Data = binary.LittleEndian.AppendUint16(nil, busyWait)
		securechannel.SendStatus(now, ex, sr)
		ex.Close(now)
		h.state = finished
		return nil
	}
	req, err := DecodePBKDFParamRequest(payload)
	if err != nil {
		return err
	}
	if req.PasscodeID != 0 {
		return errors.New("pase: unsupported passcode ID")
	}
	h.peerSessionID = req.InitiatorSessionID
	h.peerParams = securechannel.SessionParams{MRP: exchange.DefaultMRPConfig}
	if req.SessionParams != nil {
		h.peerParams = *req.SessionParams
	}
	if h.localSessionID, err = r.m.AllocateSessionID(); err != nil {
		return err
	}
	resp := PBKDFParamResponse{
		InitiatorRandom:    req.InitiatorRandom,
		ResponderSessionID: h.localSessionID,
		SessionParams:      &r.cfg.SessionParams,
	}
	if _, err := io.ReadFull(r.cfg.Rand, resp.ResponderRandom[:]); err != nil {
		return err
	}
	if !req.HasPBKDFParameters {
		resp.Iterations, resp.Salt = r.cfg.Iterations, r.cfg.Salt
	}
	respBytes := resp.Encode()

	h.ctx = sha256.New()
	h.ctx.Write([]byte(contextPrefix))
	h.ctx.Write(payload)
	h.ctx.Write(respBytes)

	ex.Session().PeerMRP = h.peerParams.MRP
	if err := ex.Send(now, message.ProtocolSecureChannel, securechannel.OpPBKDFParamResponse, respBytes); err != nil {
		return err
	}
	if c := r.current; c != nil && c != h {
		c.state = finished // stale handshake replaced
	}
	r.current, h.started, h.state = h, now, waitPake1
	return nil
}

func (h *responderHandshake) onPake1(now time.Time, ex *exchange.Exchange, payload []byte) error {
	pA, err := DecodePake1(payload)
	if err != nil {
		return err
	}
	h.spake, err = spake2p.NewVerifierSession(h.ctx.Sum(nil), nil, nil, h.r.cfg.Verifier)
	if err != nil {
		return err
	}
	pB, err := h.spake.RoundOne(h.r.cfg.Rand)
	if err != nil {
		return err
	}
	cB, err := h.spake.RoundTwo(pA)
	if err != nil {
		return err
	}
	if err := ex.Send(now, message.ProtocolSecureChannel, securechannel.OpPASEPake2, EncodePake2(pB, cB)); err != nil {
		return err
	}
	h.state = waitPake3
	return nil
}

func (h *responderHandshake) onPake3(now time.Time, ex *exchange.Exchange, payload []byte) error {
	cA, err := DecodePake3(payload)
	if err != nil {
		return err
	}
	if h.spake.Confirm(cA) != nil {
		return ErrConfirm
	}
	ke, err := h.spake.Ke()
	if err != nil {
		return err
	}
	keys, err := securechannel.DeriveSessionKeys(ke, nil, "SessionKeys")
	if err != nil {
		return err
	}
	s, err := h.r.m.NewSecureSession(now, exchange.SecureSessionParams{
		Peer:           ex.Session().Peer,
		PeerMRP:        h.peerParams.MRP,
		LocalSessionID: h.localSessionID,
		PeerSessionID:  h.peerSessionID,
		EncryptKey:     keys.R2I[:],
		DecryptKey:     keys.I2R[:],
	})
	if err != nil {
		return err
	}
	s.Attachment = &Info{AttestationChallenge: keys.AttestationChallenge}
	securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(
		securechannel.GeneralSuccess, securechannel.CodeSessionEstablishmentSuccess))
	ex.Close(now)
	h.release()
	h.r.failed = 0
	if h.r.cfg.OnEstablished != nil {
		h.r.cfg.OnEstablished(now, s)
	}
	return nil
}

// Info is attached to PASE sessions (Session.Attachment).
type Info struct {
	// AttestationChallenge is used in device attestation during
	// commissioning.
	AttestationChallenge [16]byte
}
