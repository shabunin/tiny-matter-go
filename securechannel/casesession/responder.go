package casesession

import (
	"crypto/sha256"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

// ResponderConfig configures the CASE responder.
type ResponderConfig struct {
	Fabrics       *fabric.Table
	SessionParams securechannel.SessionParams
	Rand          io.Reader
	// Resumptions, if set, keeps resumption records of established
	// sessions and lets initiators resume them.
	Resumptions *ResumptionStore
	// OnEstablished is called with each new CASE session, full or resumed.
	OnEstablished func(now time.Time, s *exchange.Session, f *fabric.Fabric)
	// OnFailed, if set, is called when a handshake fails.
	OnFailed func(now time.Time, err error)
}

// Responder answers CASE handshakes for the node's fabrics.
type Responder struct {
	cfg ResponderConfig
	m   *exchange.Manager
}

// NewResponder returns a Responder registered with d for Sigma1.
func NewResponder(m *exchange.Manager, d *securechannel.Dispatcher, cfg ResponderConfig) *Responder {
	if cfg.SessionParams == (securechannel.SessionParams{}) {
		cfg.SessionParams = securechannel.DefaultSessionParams
	}
	r := &Responder{cfg: cfg, m: m}
	d.Handle(securechannel.OpCASESigma1, r.factory)
	return r
}

func (r *Responder) factory(ex *exchange.Exchange) exchange.Delegate {
	if ex.Session().IsSecure() {
		return nil
	}
	return &responderHandshake{r: r}
}

type responderHandshake struct {
	r      *Responder
	state  uint8 // 0 wait Sigma1, 1 wait Sigma3, 2 done, 3 wait status after Sigma2_Resume
	fabric *fabric.Fabric
	tr     *transcript

	resumptionID    []byte      // offered in Sigma2, or the new one in Sigma2_Resume
	resume          *Resumption // the record being resumed
	initiatorRandom []byte

	shared          []byte
	ephPub, peerEph []byte
	localSessionID  uint16
	peerSessionID   uint16
	peerMRP         exchange.MRPConfig
}

func (h *responderHandshake) OnError(now time.Time, ex *exchange.Exchange, err error) {
	if h.state != 2 && h.r.cfg.OnFailed != nil {
		h.r.cfg.OnFailed(now, err)
	}
	clear(h.shared)
	h.state = 2
}

func (h *responderHandshake) fail(now time.Time, ex *exchange.Exchange, err error) {
	code := uint16(securechannel.CodeInvalidParameter)
	if err == ErrNoFabric {
		code = securechannel.CodeNoSharedTrustRoots
	}
	if err != errPeerStatus {
		securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(securechannel.GeneralFailure, code))
	}
	ex.Close(now)
	clear(h.shared)
	h.state = 2
	if h.r.cfg.OnFailed != nil {
		h.r.cfg.OnFailed(now, err)
	}
}

func (h *responderHandshake) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if h.state == 2 {
		return
	}
	var err error
	switch {
	case msg.ProtocolID != message.ProtocolSecureChannel:
		err = ErrUnexpected
	case msg.Opcode == securechannel.OpStatusReport && h.state == 3:
		err = h.onResumeStatus(now, ex, msg.Payload)
	case msg.Opcode == securechannel.OpStatusReport:
		err = errPeerStatus
	case h.state == 0 && msg.Opcode == securechannel.OpCASESigma1:
		err = h.onSigma1(now, ex, msg.Payload)
	case h.state == 1 && msg.Opcode == securechannel.OpCASESigma3:
		err = h.onSigma3(now, ex, msg.Payload)
	default:
		err = ErrUnexpected
	}
	if err != nil {
		h.fail(now, ex, err)
	}
}

func (h *responderHandshake) onSigma1(now time.Time, ex *exchange.Exchange, payload []byte) error {
	s1, err := DecodeSigma1(payload)
	if err != nil {
		return err
	}
	h.peerSessionID = s1.InitiatorSessionID
	h.peerMRP = exchange.DefaultMRPConfig
	if s1.SessionParams != nil {
		h.peerMRP = s1.SessionParams.MRP
		ex.Session().PeerMRP = h.peerMRP
	}
	if rs := h.r.cfg.Resumptions; rs != nil && s1.ResumptionID != nil {
		// Resume if the record is known and the MIC proves the initiator
		// holds its secret; otherwise run the full handshake.
		if rec := rs.byID(s1.ResumptionID); rec != nil && h.r.cfg.Fabrics != nil &&
			checkResumeMIC(s1.ResumeMIC, rec.Secret, s1.InitiatorRandom[:], rec.ID[:], infoResume1, nonceResume1) {
			if f := h.r.cfg.Fabrics.Get(rec.FabricIndex); f != nil && f.NodeID == rec.LocalNodeID {
				return h.sendSigma2Resume(now, ex, s1, rec, f)
			}
		}
	}
	if h.r.cfg.Fabrics != nil {
		for _, f := range h.r.cfg.Fabrics.Fabrics() {
			d := DestinationID(f.OperationalIPK[:], s1.InitiatorRandom[:], f.RootPublicKey, f.FabricID, f.NodeID)
			if d == s1.DestinationID {
				h.fabric = f
				break
			}
		}
	}
	if h.fabric == nil {
		return ErrNoFabric
	}
	peerPub, err := p256.NewPublicKey(s1.InitiatorEphPubKey[:])
	if err != nil {
		return err
	}
	eph, err := p256.GenerateKey(h.r.cfg.Rand)
	if err != nil {
		return err
	}
	if h.shared, err = eph.ECDH(peerPub); err != nil {
		return err
	}
	h.ephPub = eph.PublicKey().Bytes()
	h.peerEph = append([]byte{}, s1.InitiatorEphPubKey[:]...)
	h.tr = newTranscript()
	h.tr.add(payload)

	f := h.fabric
	sig, err := f.Key.SignMessage(h.r.cfg.Rand, tbsData(f.NOC, f.ICAC, h.ephPub, h.peerEph))
	if err != nil {
		return err
	}
	resumptionID := make([]byte, ResumptionIDSize)
	if _, err := io.ReadFull(h.r.cfg.Rand, resumptionID); err != nil {
		return err
	}
	s2 := Sigma2{SessionParams: &h.r.cfg.SessionParams}
	if _, err := io.ReadFull(h.r.cfg.Rand, s2.ResponderRandom[:]); err != nil {
		return err
	}
	copy(s2.ResponderEphPubKey[:], h.ephPub)
	s1Hash := sha256.Sum256(payload)
	s2k, err := sigmaKey(h.shared, cat(f.OperationalIPK[:], s2.ResponderRandom[:], h.ephPub, s1Hash[:]), "Sigma2")
	if err != nil {
		return err
	}
	h.resumptionID = resumptionID
	if s2.Encrypted2, err = seal(s2k, nonceSigma2, tbeData(f.NOC, f.ICAC, sig, resumptionID)); err != nil {
		return err
	}
	if h.localSessionID, err = h.r.m.AllocateSessionID(); err != nil {
		return err
	}
	s2.ResponderSessionID = h.localSessionID
	b := s2.Encode()
	h.tr.add(b)
	if err := ex.Send(now, message.ProtocolSecureChannel, securechannel.OpCASESigma2, b); err != nil {
		return err
	}
	h.state = 1
	return nil
}

func (h *responderHandshake) onSigma3(now time.Time, ex *exchange.Exchange, payload []byte) error {
	enc, err := DecodeSigma3(payload)
	if err != nil {
		return err
	}
	f := h.fabric
	s3k, err := sigmaKey(h.shared, cat(f.OperationalIPK[:], h.tr.sum()), "Sigma3")
	if err != nil {
		return err
	}
	pt, err := open(s3k, nonceSigma3, enc)
	if err != nil {
		return err
	}
	t, err := decodeTBEData(pt)
	if err != nil {
		return err
	}
	if t.resumptionID != nil {
		return ErrPeerCert
	}
	id, err := credentials.ValidateNOCChain(t.noc, t.icac, f.RCAC)
	if err != nil || id.FabricID != f.FabricID {
		return ErrPeerCert
	}
	peerKey, err := p256.NewPublicKey(id.PublicKey)
	if err != nil {
		return ErrPeerCert
	}
	if !peerKey.VerifyMessage(tbsData(t.noc, t.icac, h.peerEph, h.ephPub), t.signature) {
		return ErrSignature
	}
	h.tr.add(payload)
	keys, err := securechannel.DeriveSessionKeys(h.shared, cat(f.OperationalIPK[:], h.tr.sum()), "SessionKeys")
	if err != nil {
		return err
	}
	s, err := h.r.m.NewSecureSession(now, exchange.SecureSessionParams{
		Peer:                 ex.Session().Peer,
		PeerMRP:              h.peerMRP,
		LocalSessionID:       h.localSessionID,
		PeerSessionID:        h.peerSessionID,
		LocalNodeID:          f.NodeID,
		PeerNodeID:           id.NodeID,
		EncryptKey:           keys.R2I[:],
		DecryptKey:           keys.I2R[:],
		AuthMode:             exchange.AuthCASE,
		FabricIndex:          f.Index,
		PeerCATs:             id.CATs,
		AttestationChallenge: keys.AttestationChallenge,
	})
	if err != nil {
		return err
	}
	securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(
		securechannel.GeneralSuccess, securechannel.CodeSessionEstablishmentSuccess))
	ex.Close(now)
	h.state = 2
	if rs := h.r.cfg.Resumptions; rs != nil {
		rec := &Resumption{Secret: append([]byte{}, h.shared...), FabricIndex: f.Index, LocalNodeID: f.NodeID,
			PeerNodeID: id.NodeID, PeerCATs: id.CATs}
		copy(rec.ID[:], h.resumptionID)
		rs.save(rec)
	}
	clear(h.shared)
	if h.r.cfg.OnEstablished != nil {
		h.r.cfg.OnEstablished(now, s, f)
	}
	return nil
}

// sendSigma2Resume answers a Sigma1 that resumes rec with a new resumption
// ID; the session starts when the initiator confirms.
func (h *responderHandshake) sendSigma2Resume(now time.Time, ex *exchange.Exchange, s1 *Sigma1, rec *Resumption, f *fabric.Fabric) error {
	m := Sigma2Resume{SessionParams: &h.r.cfg.SessionParams}
	if _, err := io.ReadFull(h.r.cfg.Rand, m.ResumptionID[:]); err != nil {
		return err
	}
	mic, err := resumeMIC(rec.Secret, s1.InitiatorRandom[:], m.ResumptionID[:], infoResume2, nonceResume2)
	if err != nil {
		return err
	}
	copy(m.MIC[:], mic)
	if h.localSessionID, err = h.r.m.AllocateSessionID(); err != nil {
		return err
	}
	m.ResponderSessionID = h.localSessionID
	h.fabric, h.resume = f, rec
	h.resumptionID = append([]byte{}, m.ResumptionID[:]...)
	h.initiatorRandom = append([]byte{}, s1.InitiatorRandom[:]...)
	if err := ex.Send(now, message.ProtocolSecureChannel, securechannel.OpCASESigma2Resume, m.Encode()); err != nil {
		return err
	}
	h.state = 3
	return nil
}

// onResumeStatus completes a resumption when the initiator reports
// success.
func (h *responderHandshake) onResumeStatus(now time.Time, ex *exchange.Exchange, payload []byte) error {
	sr, err := securechannel.ParseStatusReport(payload)
	if err != nil {
		return err
	}
	if !sr.IsSuccess() {
		return errPeerStatus
	}
	rec, f := h.resume, h.fabric
	keys, err := securechannel.DeriveSessionKeys(rec.Secret, cat(h.initiatorRandom, rec.ID[:]), infoResumedKeys)
	if err != nil {
		return err
	}
	s, err := h.r.m.NewSecureSession(now, exchange.SecureSessionParams{
		Peer:                 ex.Session().Peer,
		PeerMRP:              h.peerMRP,
		LocalSessionID:       h.localSessionID,
		PeerSessionID:        h.peerSessionID,
		LocalNodeID:          f.NodeID,
		PeerNodeID:           rec.PeerNodeID,
		EncryptKey:           keys.R2I[:],
		DecryptKey:           keys.I2R[:],
		AuthMode:             exchange.AuthCASE,
		FabricIndex:          f.Index,
		PeerCATs:             rec.PeerCATs,
		AttestationChallenge: keys.AttestationChallenge,
		Resumed:              true,
	})
	if err != nil {
		return err
	}
	ex.Close(now)
	h.state = 2
	next := *rec
	copy(next.ID[:], h.resumptionID)
	h.r.cfg.Resumptions.save(&next)
	if h.r.cfg.OnEstablished != nil {
		h.r.cfg.OnEstablished(now, s, f)
	}
	return nil
}
