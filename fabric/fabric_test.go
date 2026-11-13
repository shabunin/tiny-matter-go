package fabric

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Spec 4.3.2.2 example: compressed fabric ID 87E1B004E235A130.
func TestCompressedFabricID(t *testing.T) {
	root, _ := hex.DecodeString("044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa")
	got, err := CompressedFabricID(root, 0x2906C908D115D362)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("87e1b004e235a130")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("got %x", got)
	}
}

// Vectors from connectedhomeip src/crypto/tests/TestChipCryptoPAL.cpp.
func TestOperationalGroupKey(t *testing.T) {
	for _, v := range []struct{ epoch, cfid, want string }{
		{"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "2906c908d115d362", "1f19ed3cef8a211baf306faeeee7aac6"},
		{"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "2906c908d115d362", "aa979a48bd8cdf293a0709b9c1eb1930"},
		{"235bf7e62823d358dca4ba50b1535f4b", "87e1b004e235a130", "a6f5306baf6d050af23ba4bd6b9dd960"},
	} {
		epoch, _ := hex.DecodeString(v.epoch)
		var c [8]byte
		hex.Decode(c[:], []byte(v.cfid))
		got, err := OperationalGroupKey(epoch, c)
		if err != nil || hex.EncodeToString(got[:]) != v.want {
			t.Errorf("epoch %s: got %x, want %s", v.epoch, got, v.want)
		}
	}
}
