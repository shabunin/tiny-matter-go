package message

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vectors from connectedhomeip src/crypto/tests/TestChipCryptoPAL.cpp.
func TestDeriveGroupKeys(t *testing.T) {
	for _, tc := range []struct {
		epoch, cfid, op, privacy string
		session                  uint16
	}{
		{"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "2906c908d115d362", "1f19ed3cef8a211baf306faeeee7aac6", "b8279f89621ed327a9c39f6a27247358", 0x6c80},
		{"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "2906c908d115d362", "aa979a48bd8cdf293a0709b9c1eb1930", "f72570c3c089a0fe28758357afffb8d2", 0x0c48},
		// The example in the spec.
		{"235bf7e62823d358dca4ba50b1535f4b", "87e1b004e235a130", "a6f5306baf6d050af23ba4bd6b9dd960", "01f8d1927126f194082572d49b1fdc73", 0},
	} {
		var cfid [8]byte
		copy(cfid[:], unhex(t, tc.cfid))
		k, err := DeriveGroupKeys(unhex(t, tc.epoch), cfid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(k.Encryption[:], unhex(t, tc.op)) {
			t.Errorf("operational key %x, want %s", k.Encryption, tc.op)
		}
		if !bytes.Equal(k.Privacy[:], unhex(t, tc.privacy)) {
			t.Errorf("privacy key %x, want %s", k.Privacy, tc.privacy)
		}
		if tc.session != 0 && k.SessionID != tc.session {
			t.Errorf("session ID %#04x, want %#04x", k.SessionID, tc.session)
		}
	}
	if _, err := DeriveGroupKeys(nil, [8]byte{}); err == nil {
		t.Error("accepted an empty epoch key")
	}
}

// The "private group message" vector of connectedhomeip
// src/transport/tests/TestSessionManagerDispatch.cpp: group 2, source
// node 1, counter 0x12345679, privacy on.
func TestPrivateGroupMessage(t *testing.T) {
	encKey := unhex(t, "ca92d7a0942d1a511a0e26ad074f4c2f")
	var op [KeySize]byte
	copy(op[:], encKey)
	keys, err := GroupKeysFromOperational(op)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "bfe9da016a765365f2dd97a9f939e425"); !bytes.Equal(keys.Privacy[:], want) {
		t.Fatalf("privacy key %x, want %x", keys.Privacy, want)
	}
	if keys.SessionID != 0xdb7d {
		t.Fatalf("session ID %#04x, want 0xdb7d", keys.SessionID)
	}
	wire := unhex(t, "067ddb81d926afce24c8a0981bdd44f4e7302b2f915a66c9596290ebe4408217b3c0c921a2fca4e1")
	encrypted := unhex(t, "067ddb817956341201000000000000000200"+"2b2f915a66c9596290ebe4408217b3c0c921a2fca4e1")
	plain := unhex(t, "067ddb81795634120100000000000000020001"+"64ee0e207d")

	// Receive: the flags are in the clear; deobfuscate, decode, open.
	pkt := bytes.Clone(wire)
	var h Header
	if _, err := h.Decode(pkt); err != nil {
		t.Fatal(err)
	}
	if !h.Privacy || h.SessionType != SessionGroup || h.SessionID != keys.SessionID {
		t.Fatalf("header %+v", h)
	}
	if err := Obfuscate(pkt, &h, keys.Privacy[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, encrypted) {
		t.Fatalf("deobfuscated\n%x, want\n%x", pkt, encrypted)
	}
	n, err := h.Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if h.MessageCounter != 0x12345679 || h.SourceNodeID != 1 || h.Dest != DestGroup || h.DestGroupID != 2 {
		t.Fatalf("decoded header %+v", h)
	}
	c, err := NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.OpenInPlace(pkt, &h, n, h.SourceNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, plain[n:]) {
		t.Fatalf("payload %x, want %x", payload, plain[n:])
	}

	// Send: seal in the clear, then obfuscate.
	out, err := c.AppendSealed(nil, &h, plain[n:], h.SourceNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Obfuscate(out, &h, keys.Privacy[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, wire) {
		t.Fatalf("sent\n%x, want\n%x", out, wire)
	}

	if err := Obfuscate(wire[:20], &h, keys.Privacy[:]); err == nil {
		t.Error("obfuscated a packet shorter than its header and MIC")
	}
}
