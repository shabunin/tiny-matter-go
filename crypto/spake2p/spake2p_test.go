package spake2p

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type rfcVector struct {
	Name       string `json:"_name"`
	Context    string `json:"context"`
	ProverID   string `json:"prover_identity"`
	VerifierID string `json:"verifier_identity"`
	W0, W1, L  string
	X          string `json:"X"`
	XScalar    string `json:"x"`
	Y          string `json:"Y"`
	YScalar    string `json:"y"`
	Z, V       string
	Ka, Ke     string
	KcA, KcB   string
	MACKcA     string `json:"MAC_KcA"`
	MACKcB     string `json:"MAC_KcB"`
}

func h(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from connectedhomeip src/crypto/tests/SPAKE2P_RFC_test_vectors.h
// (draft-bar-cfrg-spake2plus-01 Appendix B), converted with
// tools/chipvectors.py.
func TestRFCVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/spake2p_rfc.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []rfcVector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) != 4 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		ctx, pid, vid := h(t, v.Context), h(t, v.ProverID), h(t, v.VerifierID)
		ver := &Verifier{}
		copy(ver.W0[:], h(t, v.W0))
		copy(ver.L[:], h(t, v.L))

		p, err := NewProver(ctx, pid, vid, h(t, v.W0), h(t, v.W1))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := NewVerifierSession(ctx, pid, vid, ver)

		X, err := p.RoundOneWithScalar(h(t, v.XScalar))
		if err != nil || !bytes.Equal(X, h(t, v.X)) {
			t.Fatalf("%s: X = %x, %v", v.Name, X, err)
		}
		Y, err := s.RoundOneWithScalar(h(t, v.YScalar))
		if err != nil || !bytes.Equal(Y, h(t, v.Y)) {
			t.Fatalf("%s: Y = %x, %v", v.Name, Y, err)
		}
		cB, err := s.RoundTwo(X)
		if err != nil {
			t.Fatal(err)
		}
		cA, err := p.RoundTwo(Y)
		if err != nil {
			t.Fatal(err)
		}
		for _, sess := range []*Session{p, s} {
			if !bytes.Equal(sess.ka[:], h(t, v.Ka)) || !bytes.Equal(sess.ke[:], h(t, v.Ke)) {
				t.Errorf("%s (prover=%v): Ka %x Ke %x", v.Name, sess.prover, sess.ka, sess.ke)
			}
			if !bytes.Equal(sess.kcA[:], h(t, v.KcA)) || !bytes.Equal(sess.kcB[:], h(t, v.KcB)) {
				t.Errorf("%s (prover=%v): KcA %x KcB %x", v.Name, sess.prover, sess.kcA, sess.kcB)
			}
		}
		if !bytes.Equal(cA, h(t, v.MACKcA)) || !bytes.Equal(cB, h(t, v.MACKcB)) {
			t.Errorf("%s: cA %x cB %x", v.Name, cA, cB)
		}
		if err := p.Confirm(cB); err != nil {
			t.Errorf("%s: prover confirm: %v", v.Name, err)
		}
		if err := s.Confirm(cA); err != nil {
			t.Errorf("%s: verifier confirm: %v", v.Name, err)
		}
		k1, _ := p.Ke()
		k2, _ := s.Ke()
		if !bytes.Equal(k1, k2) || !bytes.Equal(k1, h(t, v.Ke)) {
			t.Errorf("%s: Ke mismatch", v.Name)
		}
	}
}

// The test verifier used by the Matter SDK examples (passcode 20202021,
// salt "SPAKE2P Key Salt", 1000 iterations), from
// CHIP_DEVICE_CONFIG_USE_TEST_SPAKE2P_VERIFIER in the SDK's
// src/include/platform/CHIPDeviceConfig.h.
const sdkTestVerifier = "b96170aae803346884724fe9a3b287c30330c2a660375d17bb205a8cf1aecb350457f8ab79ee253ab6a8e46bb09e543ae422736de501e3db37d441fe344920d09548e4c18240630c4ff4913c53513839b7c07fcc0627a1b8573a149fcd1fa466cf"

func TestSDKTestVerifier(t *testing.T) {
	v, err := NewVerifier(20202021, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(v.Bytes()); got != sdkTestVerifier {
		t.Fatalf("verifier =\n%s\nwant\n%s", got, sdkTestVerifier)
	}
	pv, err := ParseVerifier(h(t, sdkTestVerifier))
	if err != nil || *pv != *v {
		t.Fatalf("ParseVerifier: %v", err)
	}
}

func run(t *testing.T, proverPass, verifierPass uint32) (cA, cB []byte, p, s *Session) {
	salt := []byte("SPAKE2P Key Salt")
	ctx := []byte("context")
	w0, w1, err := W0W1(proverPass, salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	ver, _ := NewVerifier(verifierPass, salt, 1000)
	p, _ = NewProver(ctx, nil, nil, w0, w1)
	s, _ = NewVerifierSession(ctx, nil, nil, ver)
	X, _ := p.RoundOne(rand.Reader)
	Y, _ := s.RoundOne(rand.Reader)
	if cB, err = s.RoundTwo(X); err != nil {
		t.Fatal(err)
	}
	if cA, err = p.RoundTwo(Y); err != nil {
		t.Fatal(err)
	}
	return cA, cB, p, s
}

func TestRandomRunAndWrongPasscode(t *testing.T) {
	cA, cB, p, s := run(t, 20202021, 20202021)
	if p.Confirm(cB) != nil || s.Confirm(cA) != nil {
		t.Fatal("matching passcodes did not confirm")
	}
	cA, cB, p, s = run(t, 20202021, 20202022)
	if p.Confirm(cB) != ErrConfirm || s.Confirm(cA) != ErrConfirm {
		t.Fatal("wrong passcode confirmed")
	}
	if _, err := s.Ke(); err != ErrState {
		t.Fatal("Ke available after failed confirmation")
	}
}

func TestInvalidInputs(t *testing.T) {
	if _, _, err := W0W1(1, make([]byte, 15), 1000); err != ErrParams {
		t.Error("short salt accepted")
	}
	if _, _, err := W0W1(1, make([]byte, 16), 999); err != ErrParams {
		t.Error("low iteration count accepted")
	}
	ver, _ := NewVerifier(20202021, []byte("SPAKE2P Key Salt"), 1000)
	s, _ := NewVerifierSession(nil, nil, nil, ver)
	if _, err := s.RoundTwo(make([]byte, PointSize)); err != ErrState {
		t.Error("RoundTwo before RoundOne allowed")
	}
	s.RoundOne(rand.Reader)
	bad := bytes.Clone(ver.L[:])
	bad[64] ^= 1
	if _, err := s.RoundTwo(bad); err != ErrPoint {
		t.Errorf("off-curve share: %v", err)
	}
	// A share equal to w0*M makes T the identity; it must be rejected.
	s, _ = NewVerifierSession(nil, nil, nil, ver)
	s.RoundOne(rand.Reader)
	M, _ := point(pointM[:])
	M.ScalarMult(M, ver.W0[:])
	if _, err := s.RoundTwo(M.Bytes()); err != ErrPoint {
		t.Errorf("share w0*M: %v", err)
	}
}
