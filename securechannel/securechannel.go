// Package securechannel holds what the Secure Channel protocol's
// sub-protocols (PASE, CASE) share: opcodes, status reports, session
// parameters and session key derivation (Matter Core Specification 4.11,
// 4.13).
package securechannel

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// Secure Channel protocol opcodes.
const (
	OpMsgCounterSyncReq  = 0x00
	OpMsgCounterSyncRsp  = 0x01
	OpStandaloneAck      = 0x10
	OpPBKDFParamRequest  = 0x20
	OpPBKDFParamResponse = 0x21
	OpPASEPake1          = 0x22
	OpPASEPake2          = 0x23
	OpPASEPake3          = 0x24
	OpCASESigma1         = 0x30
	OpCASESigma2         = 0x31
	OpCASESigma3         = 0x32
	OpCASESigma2Resume   = 0x33
	OpStatusReport       = 0x40
	OpICDCheckIn         = 0x50
)

// General status codes (spec Appendix D).
const (
	GeneralSuccess           = 0
	GeneralFailure           = 1
	GeneralBadPrecondition   = 2
	GeneralOutOfRange        = 3
	GeneralBadRequest        = 4
	GeneralUnsupported       = 5
	GeneralUnexpected        = 6
	GeneralResourceExhausted = 7
	GeneralBusy              = 8
	GeneralTimeout           = 9
)

// Secure Channel protocol codes.
const (
	CodeSessionEstablishmentSuccess = 0x0000
	CodeNoSharedTrustRoots          = 0x0001
	CodeInvalidParameter            = 0x0002
	CodeCloseSession                = 0x0003
	CodeBusy                        = 0x0004
	CodeGeneralFailure              = 0xFFFF
)

// StatusReport is a Secure Channel StatusReport message (spec Appendix D).
type StatusReport struct {
	GeneralCode  uint16
	ProtocolID   uint32 // vendor ID << 16 | protocol ID
	ProtocolCode uint16
	Data         []byte // protocol-specific data, aliasing the input
}

// SecureChannelStatus returns a status report for the Secure Channel
// protocol.
func SecureChannelStatus(general, code uint16) StatusReport {
	return StatusReport{GeneralCode: general, ProtocolID: uint32(message.ProtocolSecureChannel), ProtocolCode: code}
}

// AppendTo appends the encoded status report to b.
func (s *StatusReport) AppendTo(b []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, s.GeneralCode)
	b = binary.LittleEndian.AppendUint32(b, s.ProtocolID)
	b = binary.LittleEndian.AppendUint16(b, s.ProtocolCode)
	return append(b, s.Data...)
}

// ParseStatusReport decodes a status report.
func ParseStatusReport(b []byte) (StatusReport, error) {
	if len(b) < 8 {
		return StatusReport{}, errors.New("securechannel: status report too short")
	}
	s := StatusReport{
		GeneralCode:  binary.LittleEndian.Uint16(b),
		ProtocolID:   binary.LittleEndian.Uint32(b[2:]),
		ProtocolCode: binary.LittleEndian.Uint16(b[6:]),
	}
	if len(b) > 8 {
		s.Data = b[8:]
	}
	return s, nil
}

// IsSuccess reports whether s is the Secure Channel session establishment
// success status.
func (s *StatusReport) IsSuccess() bool {
	return s.GeneralCode == GeneralSuccess && s.ProtocolID == uint32(message.ProtocolSecureChannel) &&
		s.ProtocolCode == CodeSessionEstablishmentSuccess
}

// StatusError is a failure status report received from the peer.
type StatusError struct{ Report StatusReport }

func (e *StatusError) Error() string {
	return fmt.Sprintf("securechannel: peer reported status general=%d protocol=%#x code=%#x",
		e.Report.GeneralCode, e.Report.ProtocolID, e.Report.ProtocolCode)
}

// SessionParams are the session parameters exchanged in PASE and CASE
// (spec 4.13.1.1, session-parameter-struct).
type SessionParams struct {
	MRP                      exchange.MRPConfig
	DataModelRevision        uint16
	InteractionModelRevision uint16
	SpecificationVersion     uint32
	MaxPathsPerInvoke        uint16
}

// DefaultSessionParams are the parameters this stack advertises unless
// configured otherwise. The revisions are those of Matter 1.4.0
// (connectedhomeip v1.4.0.0, src/app/SpecificationDefinedRevisions.h).
var DefaultSessionParams = SessionParams{
	MRP:                      exchange.DefaultMRPConfig,
	DataModelRevision:        18,
	InteractionModelRevision: 11,
	SpecificationVersion:     0x01040000,
	MaxPathsPerInvoke:        1,
}

const (
	tagSessionIdleInterval      = 1
	tagSessionActiveInterval    = 2
	tagSessionActiveThreshold   = 3
	tagDataModelRevision        = 4
	tagInteractionModelRevision = 5
	tagSpecificationVersion     = 6
	tagMaxPathsPerInvoke        = 7
)

// Encode writes p as a structure with the given tag.
func (p *SessionParams) Encode(w *tlv.Writer, tag tlv.Tag) {
	w.StartStruct(tag)
	w.PutUint(tlv.ContextTag(tagSessionIdleInterval), uint64(p.MRP.IdleInterval/time.Millisecond))
	w.PutUint(tlv.ContextTag(tagSessionActiveInterval), uint64(p.MRP.ActiveInterval/time.Millisecond))
	w.PutUint(tlv.ContextTag(tagSessionActiveThreshold), uint64(p.MRP.ActiveThreshold/time.Millisecond))
	w.PutUint(tlv.ContextTag(tagDataModelRevision), uint64(p.DataModelRevision))
	w.PutUint(tlv.ContextTag(tagInteractionModelRevision), uint64(p.InteractionModelRevision))
	w.PutUint(tlv.ContextTag(tagSpecificationVersion), uint64(p.SpecificationVersion))
	w.PutUint(tlv.ContextTag(tagMaxPathsPerInvoke), uint64(p.MaxPathsPerInvoke))
	w.EndContainer()
}

const maxMRPIntervalMS = 3600_000 // spec 4.12.8: max 1 hour

// DecodeSessionParams decodes the session parameters structure the reader
// is positioned on. Absent fields take the spec defaults; unknown fields are
// ignored.
func DecodeSessionParams(r *tlv.Reader) (SessionParams, error) {
	p := SessionParams{MRP: exchange.DefaultMRPConfig, MaxPathsPerInvoke: 1}
	if r.Type() != tlv.TypeStruct {
		return p, tlv.ErrType
	}
	if err := r.EnterContainer(); err != nil {
		return p, err
	}
	for {
		err := r.Next()
		if err == tlv.ErrEndOfContainer {
			break
		}
		if err != nil {
			return p, err
		}
		if r.Tag().Kind != tlv.TagContext {
			continue
		}
		switch r.Tag().Number {
		case tagSessionIdleInterval:
			v, err := r.Uint32()
			if err != nil {
				return p, err
			}
			if v == 0 || v > maxMRPIntervalMS {
				return p, errors.New("securechannel: invalid idle interval")
			}
			p.MRP.IdleInterval = time.Duration(v) * time.Millisecond
		case tagSessionActiveInterval:
			v, err := r.Uint32()
			if err != nil {
				return p, err
			}
			if v == 0 || v > maxMRPIntervalMS {
				return p, errors.New("securechannel: invalid active interval")
			}
			p.MRP.ActiveInterval = time.Duration(v) * time.Millisecond
		case tagSessionActiveThreshold:
			v, err := r.Uint16()
			if err != nil {
				return p, err
			}
			p.MRP.ActiveThreshold = time.Duration(v) * time.Millisecond
		case tagDataModelRevision:
			if p.DataModelRevision, err = r.Uint16(); err != nil {
				return p, err
			}
		case tagInteractionModelRevision:
			if p.InteractionModelRevision, err = r.Uint16(); err != nil {
				return p, err
			}
		case tagSpecificationVersion:
			if p.SpecificationVersion, err = r.Uint32(); err != nil {
				return p, err
			}
		case tagMaxPathsPerInvoke:
			if p.MaxPathsPerInvoke, err = r.Uint16(); err != nil {
				return p, err
			}
			if p.MaxPathsPerInvoke == 0 {
				return p, errors.New("securechannel: invalid MaxPathsPerInvoke")
			}
		}
	}
	return p, r.ExitContainer()
}

// SessionKeys are the keys of a secure session (spec 4.13.2.6).
type SessionKeys struct {
	I2R, R2I             [16]byte
	AttestationChallenge [16]byte
}

// DeriveSessionKeys derives session keys from an established secret:
// HKDF-SHA256(secret, salt, info) split into I2RKey, R2IKey and the
// attestation challenge. info is "SessionKeys" for new sessions and
// "SessionResumptionKeys" for CASE resumption.
func DeriveSessionKeys(secret, salt []byte, info string) (SessionKeys, error) {
	var k SessionKeys
	b, err := hkdf.Key(sha256.New, secret, salt, info, 48)
	if err != nil {
		return k, err
	}
	copy(k.I2R[:], b[:16])
	copy(k.R2I[:], b[16:32])
	copy(k.AttestationChallenge[:], b[32:])
	clear(b)
	return k, nil
}

// SendStatus sends a status report on ex.
func SendStatus(now time.Time, ex *exchange.Exchange, s StatusReport) error {
	var buf [16]byte
	return ex.Send(now, message.ProtocolSecureChannel, OpStatusReport, s.AppendTo(buf[:0]))
}
