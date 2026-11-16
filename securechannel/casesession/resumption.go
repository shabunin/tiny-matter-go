package casesession

import (
	"crypto/subtle"
	"slices"

	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Resumption is what a node keeps of a CASE session to resume it later
// (spec 4.14.2.2): the resumption ID the responder chose, the shared
// secret, and who the peer is. Both roles keep the same record, and
// either may resume from it.
type Resumption struct {
	ID          [ResumptionIDSize]byte
	Secret      []byte // the ECDH shared secret of the full handshake
	FabricIndex uint8
	LocalNodeID uint64 // our node ID in the session: a record is used only under it
	PeerNodeID  uint64
	PeerCATs    []uint32
}

// ResumptionStore keeps one resumption record per peer node, used by the
// responder and the initiator alike. It is not safe for concurrent use;
// use it from the goroutine that drives the exchange manager.
type ResumptionStore struct {
	// Max is the number of records kept (default 10); the least recently
	// used are dropped.
	Max int
	// OnChange, if set, is called after a record is added or removed (to
	// persist the store).
	OnChange func()

	records []*Resumption // least recently used first
}

// DefaultMaxResumptions is ResumptionStore.Max when it is zero.
const DefaultMaxResumptions = 10

func (s *ResumptionStore) changed() {
	if s.OnChange != nil {
		s.OnChange()
	}
}

func (s *ResumptionStore) byID(id []byte) *Resumption {
	for _, r := range s.records {
		if subtle.ConstantTimeCompare(r.ID[:], id) == 1 {
			return r
		}
	}
	return nil
}

func (s *ResumptionStore) byPeer(fabricIndex uint8, local, node uint64) *Resumption {
	for _, r := range s.records {
		if r.FabricIndex == fabricIndex && r.LocalNodeID == local && r.PeerNodeID == node {
			return r
		}
	}
	return nil
}

// save records r, replacing the record of the same peer.
func (s *ResumptionStore) save(r *Resumption) {
	s.records = slices.DeleteFunc(s.records, func(x *Resumption) bool {
		return x.FabricIndex == r.FabricIndex && x.PeerNodeID == r.PeerNodeID
	})
	max := s.Max
	if max <= 0 {
		max = DefaultMaxResumptions
	}
	if len(s.records) >= max {
		s.records = s.records[len(s.records)-max+1:]
	}
	s.records = append(s.records, r)
	s.changed()
}

// Resumable reports whether a session from f's node to a peer can be
// resumed.
func (s *ResumptionStore) Resumable(f *fabric.Fabric, peer uint64) bool {
	return s.byPeer(f.Index, f.NodeID, peer) != nil
}

// Forget drops the records of a peer.
func (s *ResumptionStore) Forget(fabricIndex uint8, node uint64) {
	n := len(s.records)
	s.records = slices.DeleteFunc(s.records, func(x *Resumption) bool {
		return x.FabricIndex == fabricIndex && x.PeerNodeID == node
	})
	if len(s.records) != n {
		s.changed()
	}
}

// ForgetFabric drops the records of a fabric's peers (when the fabric is
// removed or its credentials change).
func (s *ResumptionStore) ForgetFabric(fabricIndex uint8) {
	n := len(s.records)
	s.records = slices.DeleteFunc(s.records, func(x *Resumption) bool { return x.FabricIndex == fabricIndex })
	if len(s.records) != n {
		s.changed()
	}
}

// Len returns the number of records.
func (s *ResumptionStore) Len() int { return len(s.records) }

// Resumption key derivation (spec 4.14.2.6): S1RK and S2RK authenticate the
// resume request and reply, as AES-CCM tags over nothing.
var (
	nonceResume1 = []byte("NCASE_SigmaS1")
	nonceResume2 = []byte("NCASE_SigmaS2")
)

const (
	infoResume1     = "Sigma1_Resume"
	infoResume2     = "Sigma2_Resume"
	infoResumedKeys = "SessionResumptionKeys"
)

// resumeMIC computes the MIC of Sigma1 (info Sigma1_Resume, the old
// resumption ID) or Sigma2_Resume (Sigma2_Resume, the new one).
func resumeMIC(secret, initiatorRandom, resumptionID []byte, info string, nonce []byte) ([]byte, error) {
	k, err := sigmaKey(secret, cat(initiatorRandom, resumptionID), info)
	if err != nil {
		return nil, err
	}
	return seal(k, nonce, nil)
}

func checkResumeMIC(mic, secret, initiatorRandom, resumptionID []byte, info string, nonce []byte) bool {
	want, err := resumeMIC(secret, initiatorRandom, resumptionID, info, nonce)
	return err == nil && subtle.ConstantTimeCompare(want, mic) == 1
}

// Sigma2Resume is the responder's reply to a Sigma1 it resumes.
type Sigma2Resume struct {
	ResumptionID       [ResumptionIDSize]byte // the new one
	MIC                [micSize]byte
	ResponderSessionID uint16
	SessionParams      *securechannel.SessionParams
}

// Encode returns the TLV encoding.
func (m *Sigma2Resume) Encode() []byte {
	w := tlv.NewWriter(make([]byte, 0, 96))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), m.ResumptionID[:])
	w.PutBytes(tlv.ContextTag(2), m.MIC[:])
	w.PutUint(tlv.ContextTag(3), uint64(m.ResponderSessionID))
	if m.SessionParams != nil {
		m.SessionParams.Encode(w, tlv.ContextTag(4))
	}
	w.EndContainer()
	return w.Bytes()
}

// DecodeSigma2Resume decodes Sigma2_Resume.
func DecodeSigma2Resume(b []byte) (*Sigma2Resume, error) {
	m := &Sigma2Resume{}
	var seen uint8
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		switch tag {
		case 1:
			err = fixed(r, m.ResumptionID[:])
		case 2:
			err = fixed(r, m.MIC[:])
		case 3:
			m.ResponderSessionID, err = r.Uint16()
		case 4:
			var p securechannel.SessionParams
			p, err = securechannel.DecodeSessionParams(r)
			m.SessionParams = &p
		default:
			return nil
		}
		seen |= 1 << tag
		return err
	})
	if err != nil {
		return nil, err
	}
	if seen&0b1110 != 0b1110 || m.ResponderSessionID == 0 {
		return nil, errMessage
	}
	return m, nil
}
