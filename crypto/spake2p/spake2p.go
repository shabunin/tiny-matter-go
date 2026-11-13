// Package spake2p implements SPAKE2+ with P-256, SHA-256, HKDF and HMAC
// (draft-bar-cfrg-spake2plus-01) as used by Matter's PASE (Matter Core
// Specification 3.10), including the Matter passcode verifier derivation.
//
// Roles: the commissioner is the prover (it knows the passcode, as w0 and
// w1); the device is the verifier (it stores only w0 and L = w1*G).
package spake2p

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
)

// Sizes of protocol values.
const (
	ScalarSize   = p256.ScalarSize // w0, w1, x, y
	PointSize    = p256.PointSize  // X, Y, L (uncompressed)
	ConfirmSize  = sha256.Size     // cA, cB
	KeySize      = 16              // Ke
	VerifierSize = ScalarSize + PointSize

	// PBKDF2 limits from the Matter specification (3.9, 5.1.1.6).
	MinIterations = 1000
	MaxIterations = 100000
	MinSaltSize   = 16
	MaxSaltSize   = 32
)

// M and N are the SPAKE2+ P-256 constants (uncompressed).
var (
	pointM = [PointSize]byte{
		0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99,
		0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f,
		0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b,
		0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20,
	}
	pointN = [PointSize]byte{
		0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07,
		0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07,
		0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b,
		0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
	}
)

var (
	ErrState   = errors.New("spake2p: operation out of order")
	ErrConfirm = errors.New("spake2p: key confirmation failed")
	ErrPoint   = errors.New("spake2p: invalid point")
	ErrParams  = errors.New("spake2p: invalid PBKDF parameters")
)

// W0W1 derives the prover's w0 and w1 from a Matter setup passcode
// (spec 3.10, Crypto_PBKDF over the 4-byte little-endian passcode).
func W0W1(passcode uint32, salt []byte, iterations int) (w0, w1 []byte, err error) {
	if iterations < MinIterations || iterations > MaxIterations ||
		len(salt) < MinSaltSize || len(salt) > MaxSaltSize {
		return nil, nil, ErrParams
	}
	var pw [4]byte
	binary.LittleEndian.PutUint32(pw[:], passcode)
	ws, err := pbkdf2.Key(sha256.New, string(pw[:]), salt, iterations, 80)
	if err != nil {
		return nil, nil, err
	}
	return p256.ReduceScalar(ws[:40]), p256.ReduceScalar(ws[40:]), nil
}

// Verifier is what a device stores instead of its passcode: w0 and L = w1*G.
// Its 97-byte serialization w0 || L is the "Spake2p verifier" of Matter
// tooling and factory data.
type Verifier struct {
	W0 [ScalarSize]byte
	L  [PointSize]byte
}

// NewVerifier computes the verifier for a passcode.
func NewVerifier(passcode uint32, salt []byte, iterations int) (*Verifier, error) {
	w0, w1, err := W0W1(passcode, salt, iterations)
	if err != nil {
		return nil, err
	}
	L, err := p256.NewPoint().ScalarBaseMult(w1)
	if err != nil {
		return nil, err
	}
	v := &Verifier{}
	copy(v.W0[:], w0)
	copy(v.L[:], L.Bytes())
	return v, nil
}

// ParseVerifier parses a serialized w0 || L verifier.
func ParseVerifier(b []byte) (*Verifier, error) {
	if len(b) != VerifierSize {
		return nil, errors.New("spake2p: verifier must be 97 bytes")
	}
	if _, err := p256.NewPoint().SetBytes(b[ScalarSize:]); err != nil {
		return nil, ErrPoint
	}
	v := &Verifier{}
	copy(v.W0[:], b[:ScalarSize])
	copy(v.L[:], b[ScalarSize:])
	return v, nil
}

// Bytes returns the serialized verifier w0 || L.
func (v *Verifier) Bytes() []byte {
	b := make([]byte, 0, VerifierSize)
	b = append(b, v.W0[:]...)
	return append(b, v.L[:]...)
}

type state uint8

const (
	stateStarted state = iota
	stateRoundOne
	stateRoundTwo
	stateConfirmed
	stateFailed
)

// Session is one run of SPAKE2+ as prover or verifier.
type Session struct {
	prover bool
	state  state
	tt     hash.Hash // transcript TT

	w0, w1 []byte // w1 is nil for the verifier
	L      []byte // verifier only

	xy     []byte          // our ephemeral scalar x or y
	share  [PointSize]byte // our share X or Y
	peer   [PointSize]byte // peer's share
	ka, ke [KeySize]byte
	kcA    [KeySize]byte
	kcB    [KeySize]byte
}

func newSession(prover bool, context, proverID, verifierID []byte) *Session {
	s := &Session{prover: prover, tt: sha256.New()}
	s.hash(context)
	s.hash(proverID)
	s.hash(verifierID)
	s.hash(pointM[:])
	s.hash(pointN[:])
	return s
}

// NewProver starts a prover session. context is the protocol context (for
// PASE, the hash of the PBKDF exchange); identities are empty in Matter.
func NewProver(context, proverID, verifierID, w0, w1 []byte) (*Session, error) {
	if len(w0) != ScalarSize || len(w1) != ScalarSize {
		return nil, errors.New("spake2p: w0 and w1 must be 32 bytes")
	}
	s := newSession(true, context, proverID, verifierID)
	s.w0, s.w1 = w0, w1
	return s, nil
}

// NewVerifierSession starts a verifier session from a stored Verifier.
func NewVerifierSession(context, proverID, verifierID []byte, v *Verifier) (*Session, error) {
	s := newSession(false, context, proverID, verifierID)
	s.w0, s.L = v.W0[:], v.L[:]
	return s, nil
}

// hash appends len(b) as 8 bytes little endian, then b, to the transcript.
func (s *Session) hash(b []byte) {
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(b)))
	s.tt.Write(l[:])
	s.tt.Write(b)
}

func point(b []byte) (*p256.Point, error) {
	p, err := p256.NewPoint().SetBytes(b)
	if err != nil {
		return nil, ErrPoint
	}
	return p, nil
}

// RoundOne picks a random ephemeral scalar and returns our share: X = x*G +
// w0*M for the prover (pA in Pake1), Y = y*G + w0*N for the verifier (pB in
// Pake2).
func (s *Session) RoundOne(rand io.Reader) ([]byte, error) {
	xy, err := p256.RandomScalar(rand)
	if err != nil {
		return nil, err
	}
	return s.RoundOneWithScalar(xy)
}

// RoundOneWithScalar is RoundOne with a given ephemeral scalar, for tests.
func (s *Session) RoundOneWithScalar(xy []byte) ([]byte, error) {
	if s.state != stateStarted || len(xy) != ScalarSize {
		return nil, ErrState
	}
	mn := pointN[:]
	if s.prover {
		mn = pointM[:]
	}
	MN, err := point(mn)
	if err != nil {
		return nil, err
	}
	if _, err := MN.ScalarMult(MN, s.w0); err != nil {
		return nil, err
	}
	P, err := p256.NewPoint().ScalarBaseMult(xy)
	if err != nil {
		return nil, err
	}
	s.xy = xy
	copy(s.share[:], P.Add(P, MN).Bytes())
	s.state = stateRoundOne
	return s.share[:], nil
}

// RoundTwo takes the peer's share and returns our key confirmation: cA =
// HMAC(KcA, Y) for the prover (Pake3), cB = HMAC(KcB, X) for the verifier
// (Pake2).
func (s *Session) RoundTwo(peerShare []byte) ([]byte, error) {
	if s.state != stateRoundOne {
		return nil, ErrState
	}
	s.state = stateFailed
	if len(peerShare) != PointSize || peerShare[0] != 4 {
		return nil, ErrPoint
	}
	peer, err := point(peerShare)
	if err != nil {
		return nil, err
	}
	copy(s.peer[:], peerShare)

	// T = peerShare - w0*(N for the prover, M for the verifier).
	mn := pointM[:]
	if s.prover {
		mn = pointN[:]
	}
	MN, err := point(mn)
	if err != nil {
		return nil, err
	}
	if _, err := MN.ScalarMult(MN, s.w0); err != nil {
		return nil, err
	}
	T := p256.NewPoint().Add(peer, p256.NewPoint().Negate(MN))

	// Z = xy*T; V = w1*T for the prover, y*L for the verifier. The P-256
	// cofactor is 1.
	Z, err := p256.NewPoint().ScalarMult(T, s.xy)
	if err != nil {
		return nil, err
	}
	var V *p256.Point
	if s.prover {
		V, err = p256.NewPoint().ScalarMult(T, s.w1)
	} else {
		L, perr := point(s.L)
		if perr != nil {
			return nil, perr
		}
		V, err = p256.NewPoint().ScalarMult(L, s.xy)
	}
	if err != nil {
		return nil, err
	}
	zb, vb := Z.Bytes(), V.Bytes()
	if len(zb) != PointSize || len(vb) != PointSize {
		return nil, ErrPoint // identity: a malicious share
	}

	if s.prover {
		s.hash(s.share[:])
		s.hash(s.peer[:])
	} else {
		s.hash(s.peer[:])
		s.hash(s.share[:])
	}
	s.hash(zb)
	s.hash(vb)
	s.hash(s.w0)
	kae := s.tt.Sum(nil)
	copy(s.ka[:], kae[:KeySize])
	copy(s.ke[:], kae[KeySize:])

	kc, err := hkdf.Key(sha256.New, s.ka[:], nil, "ConfirmationKeys", 2*KeySize)
	if err != nil {
		return nil, err
	}
	copy(s.kcA[:], kc[:KeySize])
	copy(s.kcB[:], kc[KeySize:])
	clear(kc)

	s.state = stateRoundTwo
	if s.prover {
		return mac(s.kcA[:], s.peer[:]), nil // cA = HMAC(KcA, Y)
	}
	return mac(s.kcB[:], s.peer[:]), nil // cB = HMAC(KcB, X)
}

// Confirm verifies the peer's key confirmation: cB from the verifier (in
// Pake2) or cA from the prover (in Pake3).
func (s *Session) Confirm(peerConfirm []byte) error {
	if s.state != stateRoundTwo {
		return ErrState
	}
	var want []byte
	if s.prover {
		want = mac(s.kcB[:], s.share[:]) // cB = HMAC(KcB, X)
	} else {
		want = mac(s.kcA[:], s.share[:]) // cA = HMAC(KcA, Y)
	}
	if subtle.ConstantTimeCompare(want, peerConfirm) != 1 {
		s.state = stateFailed
		return ErrConfirm
	}
	s.state = stateConfirmed
	return nil
}

// Ke returns the shared secret Ke, from which PASE derives its session keys.
// It is available only after Confirm succeeds.
func (s *Session) Ke() ([]byte, error) {
	if s.state != stateConfirmed {
		return nil, ErrState
	}
	k := s.ke
	return k[:], nil
}

func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}
