package casesession

import (
	"errors"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

var errPeerStatus = errors.New("case: peer reported failure")

// InitiatorConfig configures the initiator side of CASE.
type InitiatorConfig struct {
	Fabric        *fabric.Fabric // our fabric membership
	PeerNodeID    uint64
	SessionParams securechannel.SessionParams
	Rand          io.Reader
	// Resumptions, if set, is where a session to the peer is resumed from
	// and recorded for resumption.
	Resumptions *ResumptionStore
	// Done is called once, with the CASE session or an error.
	Done func(now time.Time, s *exchange.Session, err error)
}

type initiator struct {
	cfg   InitiatorConfig
	m     *exchange.Manager
	state uint8 // 0 wait Sigma2, 1 wait status, 2 done
	tr    *transcript
	eph   *p256.PrivateKey

	shared         []byte
	ephPub         []byte
	peerEph        []byte
	localSessionID uint16
	peerSessionID  uint16
	peerMRP        exchange.MRPConfig
	peerCATs       []uint32

	initiatorRandom []byte
	resume          *Resumption // the record offered in Sigma1
	resumptionID    []byte      // from Sigma2
}

// Connect starts CASE with the node at peer.
func Connect(now time.Time, m *exchange.Manager, peer exchange.Addr, cfg InitiatorConfig) error {
	if cfg.Done == nil || cfg.Rand == nil || cfg.Fabric == nil {
		return errors.New("case: Fabric, Done and Rand are required")
	}
	if cfg.SessionParams == (securechannel.SessionParams{}) {
		cfg.SessionParams = securechannel.DefaultSessionParams
	}
	in := &initiator{cfg: cfg, m: m, peerMRP: exchange.DefaultMRPConfig}
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
		in.state = 2
		clear(in.shared)
		m.CloseSession(now, s)
		return err
	}
	if in.eph, err = p256.GenerateKey(cfg.Rand); err != nil {
		return failSync(err)
	}
	in.ephPub = in.eph.PublicKey().Bytes()
	if in.localSessionID, err = m.AllocateSessionID(); err != nil {
		return failSync(err)
	}
	s1 := Sigma1{InitiatorSessionID: in.localSessionID, SessionParams: &cfg.SessionParams}
	if _, err := io.ReadFull(cfg.Rand, s1.InitiatorRandom[:]); err != nil {
		return failSync(err)
	}
	f := cfg.Fabric
	in.initiatorRandom = s1.InitiatorRandom[:]
	if cfg.Resumptions != nil {
		if rec := cfg.Resumptions.byPeer(f.Index, f.NodeID, cfg.PeerNodeID); rec != nil {
			mic, err := resumeMIC(rec.Secret, s1.InitiatorRandom[:], rec.ID[:], infoResume1, nonceResume1)
			if err != nil {
				return failSync(err)
			}
			in.resume = rec
			s1.ResumptionID, s1.ResumeMIC = rec.ID[:], mic
		}
	}
	s1.DestinationID = DestinationID(f.OperationalIPK[:], s1.InitiatorRandom[:], f.RootPublicKey, f.FabricID, cfg.PeerNodeID)
	copy(s1.InitiatorEphPubKey[:], in.ephPub)
	b := s1.Encode()
	in.tr = newTranscript()
	in.tr.add(b)
	if err := ex.Send(now, message.ProtocolSecureChannel, securechannel.OpCASESigma1, b); err != nil {
		return failSync(err)
	}
	return nil
}

func (in *initiator) finish(now time.Time, ex *exchange.Exchange, s *exchange.Session, err error) {
	if in.state == 2 {
		return
	}
	in.state = 2
	clear(in.shared)
	ex.Close(now)
	in.cfg.Done(now, s, err)
}

func (in *initiator) OnError(now time.Time, ex *exchange.Exchange, err error) {
	in.finish(now, ex, nil, err)
}

func (in *initiator) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if in.state == 2 {
		return
	}
	var err error
	switch {
	case msg.ProtocolID != message.ProtocolSecureChannel:
		err = ErrUnexpected
	case msg.Opcode == securechannel.OpStatusReport:
		in.onStatus(now, ex, msg.Payload)
		return
	case in.state == 0 && msg.Opcode == securechannel.OpCASESigma2:
		err = in.onSigma2(now, ex, msg.Payload)
	case in.state == 0 && msg.Opcode == securechannel.OpCASESigma2Resume && in.resume != nil:
		err = in.onSigma2Resume(now, ex, msg.Payload)
		if err == nil {
			return
		}
		// The record is no good: the next attempt runs the full handshake.
		in.cfg.Resumptions.Forget(in.resume.FabricIndex, in.resume.PeerNodeID)
	default:
		err = ErrUnexpected
	}
	if err != nil {
		securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(
			securechannel.GeneralFailure, securechannel.CodeInvalidParameter))
		in.finish(now, ex, nil, err)
	}
}

func (in *initiator) onSigma2(now time.Time, ex *exchange.Exchange, payload []byte) error {
	s2, err := DecodeSigma2(payload)
	if err != nil {
		return err
	}
	f := in.cfg.Fabric
	peerPub, err := p256.NewPublicKey(s2.ResponderEphPubKey[:])
	if err != nil {
		return err
	}
	if in.shared, err = in.eph.ECDH(peerPub); err != nil {
		return err
	}
	in.peerEph = append([]byte{}, s2.ResponderEphPubKey[:]...)
	s1Hash := in.tr.sum()
	s2k, err := sigmaKey(in.shared, cat(f.OperationalIPK[:], s2.ResponderRandom[:], in.peerEph, s1Hash), "Sigma2")
	if err != nil {
		return err
	}
	pt, err := open(s2k, nonceSigma2, s2.Encrypted2)
	if err != nil {
		return err
	}
	t, err := decodeTBEData(pt)
	if err != nil || len(t.resumptionID) != ResumptionIDSize {
		return errMessage
	}
	in.resumptionID = append([]byte{}, t.resumptionID...)
	id, err := credentials.ValidatePeerNOCChain(t.noc, t.icac, f.RCAC, &f.PeerCerts)
	if err != nil || id.FabricID != f.FabricID || id.NodeID != in.cfg.PeerNodeID {
		return ErrPeerCert
	}
	peerKey, err := p256.NewPublicKey(id.PublicKey)
	if err != nil {
		return ErrPeerCert
	}
	if !peerKey.VerifyMessage(tbsData(t.noc, t.icac, in.peerEph, in.ephPub), t.signature) {
		return ErrSignature
	}
	in.peerSessionID = s2.ResponderSessionID
	in.peerCATs = id.CATs
	if s2.SessionParams != nil {
		in.peerMRP = s2.SessionParams.MRP
		ex.Session().PeerMRP = in.peerMRP
	}
	in.tr.add(payload)

	sig, err := f.Key.SignMessage(in.cfg.Rand, tbsData(f.NOC, f.ICAC, in.ephPub, in.peerEph))
	if err != nil {
		return err
	}
	s3k, err := sigmaKey(in.shared, cat(f.OperationalIPK[:], in.tr.sum()), "Sigma3")
	if err != nil {
		return err
	}
	enc, err := seal(s3k, nonceSigma3, tbeData(f.NOC, f.ICAC, sig, nil))
	if err != nil {
		return err
	}
	b := EncodeSigma3(enc)
	in.tr.add(b)
	in.state = 1
	return ex.Send(now, message.ProtocolSecureChannel, securechannel.OpCASESigma3, b)
}

func (in *initiator) onStatus(now time.Time, ex *exchange.Exchange, payload []byte) {
	sr, err := securechannel.ParseStatusReport(payload)
	if err != nil {
		in.finish(now, ex, nil, err)
		return
	}
	if !sr.IsSuccess() || in.state != 1 {
		in.finish(now, ex, nil, &securechannel.StatusError{Report: sr})
		return
	}
	f := in.cfg.Fabric
	keys, err := securechannel.DeriveSessionKeys(in.shared, cat(f.OperationalIPK[:], in.tr.sum()), "SessionKeys")
	if err != nil {
		in.finish(now, ex, nil, err)
		return
	}
	s, err := in.m.NewSecureSession(now, exchange.SecureSessionParams{
		Peer:                 ex.Session().Peer,
		PeerMRP:              in.peerMRP,
		LocalSessionID:       in.localSessionID,
		PeerSessionID:        in.peerSessionID,
		LocalNodeID:          f.NodeID,
		PeerNodeID:           in.cfg.PeerNodeID,
		EncryptKey:           keys.I2R[:],
		DecryptKey:           keys.R2I[:],
		AuthMode:             exchange.AuthCASE,
		FabricIndex:          f.Index,
		PeerCATs:             in.peerCATs,
		AttestationChallenge: keys.AttestationChallenge,
	})
	if err == nil && in.cfg.Resumptions != nil {
		rec := &Resumption{Secret: append([]byte{}, in.shared...), FabricIndex: f.Index, LocalNodeID: f.NodeID,
			PeerNodeID: in.cfg.PeerNodeID, PeerCATs: in.peerCATs}
		copy(rec.ID[:], in.resumptionID)
		in.cfg.Resumptions.save(rec)
	}
	clear(in.shared)
	in.finish(now, ex, s, err)
}

// onSigma2Resume completes a resumption: it checks the responder's MIC,
// confirms with a status report and starts the session.
func (in *initiator) onSigma2Resume(now time.Time, ex *exchange.Exchange, payload []byte) error {
	m, err := DecodeSigma2Resume(payload)
	if err != nil {
		return err
	}
	rec, f := in.resume, in.cfg.Fabric
	if !checkResumeMIC(m.MIC[:], rec.Secret, in.initiatorRandom, m.ResumptionID[:], infoResume2, nonceResume2) {
		return ErrDecrypt
	}
	if m.SessionParams != nil {
		in.peerMRP = m.SessionParams.MRP
		ex.Session().PeerMRP = in.peerMRP
	}
	keys, err := securechannel.DeriveSessionKeys(rec.Secret, cat(in.initiatorRandom, rec.ID[:]), infoResumedKeys)
	if err != nil {
		return err
	}
	securechannel.SendStatus(now, ex, securechannel.SecureChannelStatus(
		securechannel.GeneralSuccess, securechannel.CodeSessionEstablishmentSuccess))
	s, err := in.m.NewSecureSession(now, exchange.SecureSessionParams{
		Peer:                 ex.Session().Peer,
		PeerMRP:              in.peerMRP,
		LocalSessionID:       in.localSessionID,
		PeerSessionID:        m.ResponderSessionID,
		LocalNodeID:          f.NodeID,
		PeerNodeID:           in.cfg.PeerNodeID,
		EncryptKey:           keys.I2R[:],
		DecryptKey:           keys.R2I[:],
		AuthMode:             exchange.AuthCASE,
		FabricIndex:          f.Index,
		PeerCATs:             rec.PeerCATs,
		AttestationChallenge: keys.AttestationChallenge,
		Resumed:              true,
	})
	if err == nil {
		next := *rec
		next.ID = m.ResumptionID
		in.cfg.Resumptions.save(&next)
	}
	in.finish(now, ex, s, err)
	return nil
}
