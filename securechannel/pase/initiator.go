package pase

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

// InitiatorConfig configures the commissioner side of PASE.
type InitiatorConfig struct {
	Passcode      uint32
	SessionParams securechannel.SessionParams
	Rand          io.Reader
	// Done is called once, with the PASE session or an error.
	Done func(now time.Time, s *exchange.Session, err error)
}

type initiator struct {
	cfg   InitiatorConfig
	m     *exchange.Manager
	state uint8
	ctx   hash.Hash
	spake *spake2p.Session

	random         [RandomSize]byte
	localSessionID uint16
	peerSessionID  uint16
	peerParams     securechannel.SessionParams
	done           bool
}

const (
	iWaitPBKDFResponse = iota
	iWaitPake2
	iWaitStatus
)

// Pair starts PASE with the device at peer as commissioner.
func Pair(now time.Time, m *exchange.Manager, peer exchange.Addr, cfg InitiatorConfig) error {
	if cfg.Done == nil || cfg.Rand == nil {
		return errors.New("pase: Done and Rand are required")
	}
	if cfg.SessionParams == (securechannel.SessionParams{}) {
		cfg.SessionParams = securechannel.DefaultSessionParams
	}
	in := &initiator{cfg: cfg, m: m, peerParams: securechannel.SessionParams{MRP: exchange.DefaultMRPConfig}}
	s, err := m.NewUnsecuredSession(now, peer, exchange.MRPConfig{})
	if err != nil {
		return err
	}
	ex, err := m.NewExchange(s, in)
	if err != nil {
		m.CloseSession(now, s)
		return err
	}
	failSync := func(err error) error {
		in.done = true
		m.CloseSession(now, s)
		return err
	}
	if in.localSessionID, err = m.AllocateSessionID(); err != nil {
		return failSync(err)
	}
	if _, err := io.ReadFull(cfg.Rand, in.random[:]); err != nil {
		return failSync(err)
	}
	req := PBKDFParamRequest{
		InitiatorRandom:    in.random,
		InitiatorSessionID: in.localSessionID,
		SessionParams:      &cfg.SessionParams,
	}
	b := req.Encode()
	in.ctx = sha256.New()
	in.ctx.Write([]byte(contextPrefix))
	in.ctx.Write(b)
	if err := ex.Send(now, message.ProtocolSecureChannel, securechannel.OpPBKDFParamRequest, b); err != nil {
		return failSync(err)
	}
	return nil
}

func (in *initiator) finish(now time.Time, ex *exchange.Exchange, s *exchange.Session, err error) {
	if in.done {
		return
	}
	in.done = true
	ex.Close(now)
	in.cfg.Done(now, s, err)
}

func (in *initiator) OnError(now time.Time, ex *exchange.Exchange, err error) {
	in.finish(now, ex, nil, err)
}

func (in *initiator) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if in.done {
		return
	}
	var err error
	switch {
	case msg.ProtocolID != message.ProtocolSecureChannel:
		err = ErrUnexpected
	case msg.Opcode == securechannel.OpStatusReport:
		in.onStatus(now, ex, msg.Payload)
		return
	case in.state == iWaitPBKDFResponse && msg.Opcode == securechannel.OpPBKDFParamResponse:
		err = in.onPBKDFParamResponse(now, ex, msg.Payload)
	case in.state == iWaitPake2 && msg.Opcode == securechannel.OpPASEPake2:
		err = in.onPake2(now, ex, msg.Payload)
	default:
		err = ErrUnexpected
	}
	if err != nil {
		securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(
			securechannel.GeneralFailure, securechannel.CodeInvalidParameter))
		in.finish(now, ex, nil, err)
	}
}

func (in *initiator) onPBKDFParamResponse(now time.Time, ex *exchange.Exchange, payload []byte) error {
	resp, err := DecodePBKDFParamResponse(payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(resp.InitiatorRandom[:], in.random[:]) || resp.Salt == nil {
		return errMessage
	}
	in.peerSessionID = resp.ResponderSessionID
	if resp.SessionParams != nil {
		in.peerParams = *resp.SessionParams
		ex.Session().PeerMRP = in.peerParams.MRP
	}
	in.ctx.Write(payload)
	w0, w1, err := spake2p.W0W1(in.cfg.Passcode, resp.Salt, int(resp.Iterations))
	if err != nil {
		return err
	}
	if in.spake, err = spake2p.NewProver(in.ctx.Sum(nil), nil, nil, w0, w1); err != nil {
		return err
	}
	pA, err := in.spake.RoundOne(in.cfg.Rand)
	if err != nil {
		return err
	}
	in.state = iWaitPake2
	return ex.Send(now, message.ProtocolSecureChannel, securechannel.OpPASEPake1, EncodePake1(pA))
}

func (in *initiator) onPake2(now time.Time, ex *exchange.Exchange, payload []byte) error {
	pB, cB, err := DecodePake2(payload)
	if err != nil {
		return err
	}
	cA, err := in.spake.RoundTwo(pB)
	if err != nil {
		return err
	}
	if in.spake.Confirm(cB) != nil {
		return ErrConfirm
	}
	in.state = iWaitStatus
	return ex.Send(now, message.ProtocolSecureChannel, securechannel.OpPASEPake3, EncodePake3(cA))
}

func (in *initiator) onStatus(now time.Time, ex *exchange.Exchange, payload []byte) {
	sr, err := securechannel.ParseStatusReport(payload)
	if err != nil {
		in.finish(now, ex, nil, err)
		return
	}
	if !sr.IsSuccess() || in.state != iWaitStatus {
		in.finish(now, ex, nil, &securechannel.StatusError{Report: sr})
		return
	}
	ke, err := in.spake.Ke()
	if err != nil {
		in.finish(now, ex, nil, err)
		return
	}
	keys, err := securechannel.DeriveSessionKeys(ke, nil, "SessionKeys")
	if err != nil {
		in.finish(now, ex, nil, err)
		return
	}
	s, err := in.m.NewSecureSession(now, exchange.SecureSessionParams{
		Peer:           ex.Session().Peer,
		PeerMRP:        in.peerParams.MRP,
		LocalSessionID: in.localSessionID,
		PeerSessionID:  in.peerSessionID,
		EncryptKey:     keys.I2R[:],
		DecryptKey:     keys.R2I[:],
		AuthMode:       exchange.AuthPASE,

		AttestationChallenge: keys.AttestationChallenge,
	})
	if err == nil {
	}
	in.finish(now, ex, s, err)
}
