package ccm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Name   string `json:"_name"`
	TcID   int    `json:"tcId"`
	PT     string `json:"pt"`
	AAD    string `json:"aad"`
	Key    string `json:"key"`
	Nonce  string `json:"nonce"`
	CT     string `json:"ct"`
	Tag    string `json:"tag"`
	Result string `json:"result"`
}

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from connectedhomeip src/crypto/tests/AES_CCM_128_test_vectors.h
// (converted with tools/chipvectors.py).
func TestCHIPVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/aes_ccm_128.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 50 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		block, err := aes.NewCipher(h(t, v.Key))
		if err != nil {
			t.Fatal(err)
		}
		nonce, tag := h(t, v.Nonce), h(t, v.Tag)
		a, err := New(block, len(nonce), len(tag))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		pt, aad := h(t, v.PT), h(t, v.AAD)
		sealed := append(h(t, v.CT), tag...)
		valid := v.Result == "CHIP_NO_ERROR"

		got := a.Seal(nil, nonce, pt, aad)
		if valid != bytes.Equal(got, sealed) {
			t.Errorf("%s (tc %d): Seal = %x, want %x (valid=%v)", v.Name, v.TcID, got, sealed, valid)
		}
		opened, err := a.Open(nil, nonce, sealed, aad)
		if valid && (err != nil || !bytes.Equal(opened, pt)) {
			t.Errorf("%s (tc %d): Open = %x, %v", v.Name, v.TcID, opened, err)
		}
		if !valid && err == nil {
			t.Errorf("%s (tc %d): Open accepted an invalid vector", v.Name, v.TcID)
		}
	}
}

// NIST SP 800-38C Appendix C, Examples 1-3.
func TestSP80038C(t *testing.T) {
	key := h(t, "404142434445464748494a4b4c4d4e4f")
	block, _ := aes.NewCipher(key)
	for _, tc := range []struct{ nonce, aad, pt, ct string }{
		{"10111213141516", "0001020304050607", "20212223", "7162015b4dac255d"},
		{"1011121314151617", "000102030405060708090a0b0c0d0e0f", "202122232425262728292a2b2c2d2e2f",
			"d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd"},
		{"101112131415161718191a1b", "000102030405060708090a0b0c0d0e0f10111213",
			"202122232425262728292a2b2c2d2e2f3031323334353637",
			"e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"},
	} {
		ct := h(t, tc.ct)
		tagLen := len(ct) - len(h(t, tc.pt))
		a, err := New(block, len(h(t, tc.nonce)), tagLen)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Seal(nil, h(t, tc.nonce), h(t, tc.pt), h(t, tc.aad)); !bytes.Equal(got, ct) {
			t.Errorf("nonce %s: got %x want %x", tc.nonce, got, ct)
		}
	}
}

func TestTamperAndInPlace(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	a, _ := New(block, 13, 16)
	nonce := make([]byte, 13)
	aad := []byte("header")
	for _, n := range []int{0, 1, 15, 16, 17, 100, 1200} {
		pt := bytes.Repeat([]byte{0xAB}, n)
		buf := make([]byte, n, n+16)
		copy(buf, pt)
		sealed := a.Seal(buf[:0], nonce, buf, aad) // in place
		opened, err := a.Open(sealed[:0], nonce, sealed, aad)
		if err != nil || !bytes.Equal(opened, pt) {
			t.Fatalf("len %d: in-place round trip failed: %v", n, err)
		}
		sealed = a.Seal(nil, nonce, pt, aad)
		for _, i := range []int{0, len(sealed) / 2, len(sealed) - 1} {
			bad := bytes.Clone(sealed)
			bad[i] ^= 0x80
			if _, err := a.Open(nil, nonce, bad, aad); err == nil {
				t.Fatalf("len %d: tampered byte %d accepted", n, i)
			}
		}
		if _, err := a.Open(nil, nonce, sealed, []byte("Header")); err == nil {
			t.Fatalf("len %d: wrong AAD accepted", n)
		}
	}
	// Long AAD (>= 0xFF00) uses the 6-byte length encoding.
	long := make([]byte, 0x10000)
	s := a.Seal(nil, nonce, []byte("x"), long)
	if _, err := a.Open(nil, nonce, s, long); err != nil {
		t.Fatal(err)
	}
}
