// Package casesession implements Certificate Authenticated Session
// Establishment (Matter Core Specification 4.14.2): the Sigma handshake
// that opens operational sessions between nodes of a fabric. Session
// resumption is not offered; resumption requests fall back to a full
// handshake.
package casesession

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const (
	RandomSize       = 32
	PubKeySize       = 65
	DestinationSize  = 32
	ResumptionIDSize = 16
	micSize          = 16
)

var (
	errMessage  = errors.New("case: malformed message")
	nonceSigma2 = []byte("NCASE_Sigma2N")
	nonceSigma3 = []byte("NCASE_Sigma3N")
)

// Sigma1 is the initiator's first message.
type Sigma1 struct {
	InitiatorRandom    [RandomSize]byte
	InitiatorSessionID uint16
	DestinationID      [DestinationSize]byte
	InitiatorEphPubKey [PubKeySize]byte
	SessionParams      *securechannel.SessionParams
	ResumptionID       []byte // optional
	ResumeMIC          []byte // optional
}

// Sigma2 is the responder's reply.
type Sigma2 struct {
	ResponderRandom    [RandomSize]byte
	ResponderSessionID uint16
	ResponderEphPubKey [PubKeySize]byte
	Encrypted2         []byte
	SessionParams      *securechannel.SessionParams
}

// Encode returns the TLV encoding.
func (m *Sigma1) Encode() []byte {
	w := tlv.NewWriter(make([]byte, 0, 200))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), m.InitiatorRandom[:])
	w.PutUint(tlv.ContextTag(2), uint64(m.InitiatorSessionID))
	w.PutBytes(tlv.ContextTag(3), m.DestinationID[:])
	w.PutBytes(tlv.ContextTag(4), m.InitiatorEphPubKey[:])
	if m.SessionParams != nil {
		m.SessionParams.Encode(w, tlv.ContextTag(5))
	}
	if m.ResumptionID != nil {
		w.PutBytes(tlv.ContextTag(6), m.ResumptionID)
		w.PutBytes(tlv.ContextTag(7), m.ResumeMIC)
	}
	w.EndContainer()
	return w.Bytes()
}

// Encode returns the TLV encoding.
func (m *Sigma2) Encode() []byte {
	w := tlv.NewWriter(make([]byte, 0, 160+len(m.Encrypted2)))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), m.ResponderRandom[:])
	w.PutUint(tlv.ContextTag(2), uint64(m.ResponderSessionID))
	w.PutBytes(tlv.ContextTag(3), m.ResponderEphPubKey[:])
	w.PutBytes(tlv.ContextTag(4), m.Encrypted2)
	if m.SessionParams != nil {
		m.SessionParams.Encode(w, tlv.ContextTag(5))
	}
	w.EndContainer()
	return w.Bytes()
}

// EncodeSigma3 encodes Sigma3 {encrypted3}.
func EncodeSigma3(encrypted3 []byte) []byte {
	w := tlv.NewWriter(make([]byte, 0, len(encrypted3)+8))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), encrypted3)
	w.EndContainer()
	return w.Bytes()
}

// fields iterates over the context-tagged fields of the top-level structure.
func fields(b []byte, f func(r *tlv.Reader, tag uint32) error) error {
	r := tlv.NewReader(b)
	if r.Next() != nil || r.Type() != tlv.TypeStruct || r.EnterContainer() != nil {
		return errMessage
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return err
		}
		if r.Tag().Kind != tlv.TagContext {
			continue
		}
		if err := f(r, r.Tag().Number); err != nil {
			return err
		}
	}
	return r.ExitContainer()
}

func fixed(r *tlv.Reader, dst []byte) error {
	b, err := r.Bytes()
	if err != nil || len(b) != len(dst) {
		return errMessage
	}
	copy(dst, b)
	return nil
}

// DecodeSigma1 decodes Sigma1. Byte fields alias b.
func DecodeSigma1(b []byte) (*Sigma1, error) {
	m := &Sigma1{}
	var seen uint8
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		switch tag {
		case 1:
			err = fixed(r, m.InitiatorRandom[:])
		case 2:
			m.InitiatorSessionID, err = r.Uint16()
		case 3:
			err = fixed(r, m.DestinationID[:])
		case 4:
			err = fixed(r, m.InitiatorEphPubKey[:])
		case 5:
			var p securechannel.SessionParams
			p, err = securechannel.DecodeSessionParams(r)
			m.SessionParams = &p
		case 6:
			m.ResumptionID, err = r.Bytes()
		case 7:
			m.ResumeMIC, err = r.Bytes()
		default:
			return nil
		}
		seen |= 1 << tag
		return err
	})
	if err != nil {
		return nil, err
	}
	if seen&0b11110 != 0b11110 {
		return nil, errMessage
	}
	return m, nil
}

// DecodeSigma2 decodes Sigma2. Encrypted2 aliases b.
func DecodeSigma2(b []byte) (*Sigma2, error) {
	m := &Sigma2{}
	var seen uint8
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		switch tag {
		case 1:
			err = fixed(r, m.ResponderRandom[:])
		case 2:
			m.ResponderSessionID, err = r.Uint16()
		case 3:
			err = fixed(r, m.ResponderEphPubKey[:])
		case 4:
			m.Encrypted2, err = r.Bytes()
			if err == nil && len(m.Encrypted2) <= micSize {
				err = errMessage
			}
		case 5:
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
	if seen&0b11110 != 0b11110 {
		return nil, errMessage
	}
	return m, nil
}

// DecodeSigma3 returns encrypted3.
func DecodeSigma3(b []byte) ([]byte, error) {
	var enc []byte
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		if tag == 1 {
			enc, err = r.Bytes()
		}
		return err
	})
	if err == nil && len(enc) <= micSize {
		err = errMessage
	}
	return enc, err
}

// tbsData encodes the signed data of Sigma2 and Sigma3: the sender's
// certificates and both ephemeral public keys.
func tbsData(noc, icac, senderPub, receiverPub []byte) []byte {
	w := tlv.NewWriter(make([]byte, 0, len(noc)+len(icac)+150))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), noc)
	if icac != nil {
		w.PutBytes(tlv.ContextTag(2), icac)
	}
	w.PutBytes(tlv.ContextTag(3), senderPub)
	w.PutBytes(tlv.ContextTag(4), receiverPub)
	w.EndContainer()
	return w.Bytes()
}

// tbeData encodes the encrypted payload of Sigma2 (with a resumption ID)
// and Sigma3 (without).
func tbeData(noc, icac, signature, resumptionID []byte) []byte {
	w := tlv.NewWriter(make([]byte, 0, len(noc)+len(icac)+120))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), noc)
	if icac != nil {
		w.PutBytes(tlv.ContextTag(2), icac)
	}
	w.PutBytes(tlv.ContextTag(3), signature)
	if resumptionID != nil {
		w.PutBytes(tlv.ContextTag(4), resumptionID)
	}
	w.EndContainer()
	return w.Bytes()
}

type tbe struct {
	noc, icac, signature, resumptionID []byte
}

func decodeTBEData(b []byte) (*tbe, error) {
	t := &tbe{}
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		var v []byte
		if tag >= 1 && tag <= 4 {
			v, err = r.Bytes()
		}
		switch tag {
		case 1:
			t.noc = v
		case 2:
			t.icac = v
		case 3:
			t.signature = v
		case 4:
			t.resumptionID = v
		}
		return err
	})
	if err != nil || t.noc == nil || len(t.signature) != 64 {
		return nil, errMessage
	}
	return t, nil
}

// DestinationID computes the Sigma1 destination identifier (spec 4.14.2.4).
func DestinationID(ipk, initiatorRandom, rootPub []byte, fabricID, nodeID uint64) [DestinationSize]byte {
	mac := hmac.New(sha256.New, ipk)
	mac.Write(initiatorRandom)
	mac.Write(rootPub)
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:], fabricID)
	binary.LittleEndian.PutUint64(b[8:], nodeID)
	mac.Write(b[:])
	var out [DestinationSize]byte
	mac.Sum(out[:0])
	return out
}

// sigmaKey derives S2K or S3K.
func sigmaKey(shared []byte, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, salt, info, 16)
}
