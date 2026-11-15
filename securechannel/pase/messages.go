// Package pase implements Passcode-Authenticated Session Establishment
// (Matter Core Specification 4.14.1): the device side (Responder) and the
// commissioner side (Initiator).
package pase

import (
	"errors"

	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/securechannel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// RandomSize is the size of the PBKDF parameter exchange random values.
const RandomSize = 32

// contextPrefix starts the PASE context hash.
const contextPrefix = "CHIP PAKE V1 Commissioning"

var errMessage = errors.New("pase: malformed message")

// PBKDFParamRequest is the commissioner's first message.
type PBKDFParamRequest struct {
	InitiatorRandom    [RandomSize]byte
	InitiatorSessionID uint16
	PasscodeID         uint16
	HasPBKDFParameters bool
	SessionParams      *securechannel.SessionParams
}

// PBKDFParamResponse is the device's reply carrying the PBKDF parameters.
type PBKDFParamResponse struct {
	InitiatorRandom    [RandomSize]byte
	ResponderRandom    [RandomSize]byte
	ResponderSessionID uint16
	Iterations         uint32 // 0 when omitted
	Salt               []byte // nil when omitted
	SessionParams      *securechannel.SessionParams
}

// Encode returns the TLV encoding of m.
func (m *PBKDFParamRequest) Encode() []byte {
	w := tlv.NewWriter(make([]byte, 0, 96))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), m.InitiatorRandom[:])
	w.PutUint(tlv.ContextTag(2), uint64(m.InitiatorSessionID))
	w.PutUint(tlv.ContextTag(3), uint64(m.PasscodeID))
	w.PutBool(tlv.ContextTag(4), m.HasPBKDFParameters)
	if m.SessionParams != nil {
		m.SessionParams.Encode(w, tlv.ContextTag(5))
	}
	w.EndContainer()
	return w.Bytes()
}

// Encode returns the TLV encoding of m.
func (m *PBKDFParamResponse) Encode() []byte {
	w := tlv.NewWriter(make([]byte, 0, 160))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), m.InitiatorRandom[:])
	w.PutBytes(tlv.ContextTag(2), m.ResponderRandom[:])
	w.PutUint(tlv.ContextTag(3), uint64(m.ResponderSessionID))
	if m.Salt != nil {
		w.StartStruct(tlv.ContextTag(4))
		w.PutUint(tlv.ContextTag(1), uint64(m.Iterations))
		w.PutBytes(tlv.ContextTag(2), m.Salt)
		w.EndContainer()
	}
	if m.SessionParams != nil {
		m.SessionParams.Encode(w, tlv.ContextTag(5))
	}
	w.EndContainer()
	return w.Bytes()
}

// fields iterates over the context-tagged fields of the top-level structure
// in b, calling f for each with the reader positioned on it.
func fields(b []byte, f func(r *tlv.Reader, tag uint32) error) error {
	r := tlv.NewReader(b)
	if err := r.Next(); err != nil {
		return err
	}
	if r.Type() != tlv.TypeStruct {
		return errMessage
	}
	if err := r.EnterContainer(); err != nil {
		return err
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

func fixedBytes(r *tlv.Reader, dst []byte) error {
	b, err := r.Bytes()
	if err != nil {
		return err
	}
	if len(b) != len(dst) {
		return errMessage
	}
	copy(dst, b)
	return nil
}

// DecodePBKDFParamRequest decodes a PBKDFParamRequest.
func DecodePBKDFParamRequest(b []byte) (*PBKDFParamRequest, error) {
	m := &PBKDFParamRequest{}
	var seen uint8
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		switch tag {
		case 1:
			err = fixedBytes(r, m.InitiatorRandom[:])
		case 2:
			m.InitiatorSessionID, err = r.Uint16()
		case 3:
			m.PasscodeID, err = r.Uint16()
		case 4:
			m.HasPBKDFParameters, err = r.Bool()
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
	if seen&0b11110 != 0b11110 || m.InitiatorSessionID == 0 {
		return nil, errMessage
	}
	return m, nil
}

// DecodePBKDFParamResponse decodes a PBKDFParamResponse.
func DecodePBKDFParamResponse(b []byte) (*PBKDFParamResponse, error) {
	m := &PBKDFParamResponse{}
	var seen uint8
	err := fields(b, func(r *tlv.Reader, tag uint32) (err error) {
		switch tag {
		case 1:
			err = fixedBytes(r, m.InitiatorRandom[:])
		case 2:
			err = fixedBytes(r, m.ResponderRandom[:])
		case 3:
			m.ResponderSessionID, err = r.Uint16()
		case 4:
			if r.Type() != tlv.TypeStruct {
				return errMessage
			}
			if err = r.EnterContainer(); err != nil {
				return err
			}
			for {
				if err = r.Next(); err == tlv.ErrEndOfContainer {
					break
				} else if err != nil {
					return err
				}
				switch {
				case r.Tag().IsContext(1):
					if m.Iterations, err = r.Uint32(); err != nil {
						return err
					}
				case r.Tag().IsContext(2):
					s, err := r.Bytes()
					if err != nil {
						return err
					}
					m.Salt = append([]byte{}, s...)
				}
			}
			if m.Iterations == 0 || m.Salt == nil {
				return errMessage
			}
			err = r.ExitContainer()
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
	if seen&0b1110 != 0b1110 || m.ResponderSessionID == 0 {
		return nil, errMessage
	}
	return m, nil
}

// encodeBytesStruct encodes a structure of byte-string fields tagged 1, 2...
func encodeBytesStruct(vals ...[]byte) []byte {
	w := tlv.NewWriter(make([]byte, 0, 112))
	w.StartStruct(tlv.Anonymous)
	for i, v := range vals {
		w.PutBytes(tlv.ContextTag(uint8(i+1)), v)
	}
	w.EndContainer()
	return w.Bytes()
}

// decodeBytesStruct decodes a structure of byte-string fields tagged 1..n
// with the given exact sizes.
func decodeBytesStruct(b []byte, sizes ...int) ([][]byte, error) {
	out := make([][]byte, len(sizes))
	err := fields(b, func(r *tlv.Reader, tag uint32) error {
		if tag < 1 || int(tag) > len(sizes) {
			return nil
		}
		v, err := r.Bytes()
		if err != nil {
			return err
		}
		if len(v) != sizes[tag-1] {
			return errMessage
		}
		out[tag-1] = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, v := range out {
		if v == nil {
			return nil, errMessage
		}
	}
	return out, nil
}

// EncodePake1 encodes Pake1 {pA}.
func EncodePake1(pA []byte) []byte { return encodeBytesStruct(pA) }

// EncodePake2 encodes Pake2 {pB, cB}.
func EncodePake2(pB, cB []byte) []byte { return encodeBytesStruct(pB, cB) }

// EncodePake3 encodes Pake3 {cA}.
func EncodePake3(cA []byte) []byte { return encodeBytesStruct(cA) }

// DecodePake1 returns pA.
func DecodePake1(b []byte) ([]byte, error) {
	v, err := decodeBytesStruct(b, spake2p.PointSize)
	if err != nil {
		return nil, err
	}
	return v[0], nil
}

// DecodePake2 returns pB and cB.
func DecodePake2(b []byte) (pB, cB []byte, err error) {
	v, err := decodeBytesStruct(b, spake2p.PointSize, spake2p.ConfirmSize)
	if err != nil {
		return nil, nil, err
	}
	return v[0], v[1], nil
}

// DecodePake3 returns cA.
func DecodePake3(b []byte) ([]byte, error) {
	v, err := decodeBytesStruct(b, spake2p.ConfirmSize)
	if err != nil {
		return nil, err
	}
	return v[0], nil
}
