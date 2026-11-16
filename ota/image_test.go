package ota

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shabunin/tiny-matter-go/tlv"
)

func testHeader() Header {
	return Header{VendorID: 0xFFF1, ProductID: 0x8001, SoftwareVersion: 2, SoftwareVersionString: "2.0",
		MinApplicableVersion: 1, MaxApplicableVersion: 1, HasMin: true, HasMax: true}
}

func TestCreateParse(t *testing.T) {
	payload := make([]byte, 3000)
	rand.Read(payload)
	img, err := Create(testHeader(), payload)
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := ParseHeader(img)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if h.VendorID != 0xFFF1 || h.ProductID != 0x8001 || h.SoftwareVersion != 2 || h.SoftwareVersionString != "2.0" ||
		h.PayloadSize != 3000 || !h.HasMin || !h.HasMax || h.DigestType != DigestSHA256 || !bytes.Equal(h.Digest, sum[:]) {
		t.Fatalf("header %+v", h)
	}
	if !bytes.Equal(img[n:], payload) {
		t.Fatal("payload does not follow the header")
	}
	if !h.Applies(1) || h.Applies(0) || h.Applies(2) {
		t.Fatal("Applies")
	}
	if _, _, err := ParseHeader(img[:n-1]); err != ErrShort {
		t.Fatalf("short header: %v", err)
	}
}

// TestSDKOrder parses a header laid out as ota_image_tool.py writes it:
// optional fields after the digest.
func TestSDKOrder(t *testing.T) {
	payload := []byte("hello")
	sum := sha256.Sum256(payload)
	w := tlv.NewWriter(nil)
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(0), 0xFFF1)
	w.PutUint(tlv.ContextTag(1), 0x8001)
	w.PutUint(tlv.ContextTag(2), 10)
	w.PutString(tlv.ContextTag(3), "1.0")
	w.PutUint(tlv.ContextTag(4), 5)
	w.PutUint(tlv.ContextTag(8), 1)
	w.PutBytes(tlv.ContextTag(9), sum[:])
	w.PutUint(tlv.ContextTag(5), 3)
	w.PutString(tlv.ContextTag(7), "https://example.com/notes")
	w.EndContainer()
	th := w.Bytes()
	img := binary.LittleEndian.AppendUint32(nil, FileIdentifier)
	img = binary.LittleEndian.AppendUint64(img, uint64(16+len(th)+len(payload)))
	img = binary.LittleEndian.AppendUint32(img, uint32(len(th)))
	img = append(append(img, th...), payload...)

	var got []byte
	r := &Reader{Payload: func(p []byte) error { got = append(got, p...); return nil }}
	for _, c := range img { // a byte at a time
		if err := r.Write([]byte{c}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	h := r.Header
	if h.SoftwareVersion != 10 || !h.HasMin || h.MinApplicableVersion != 3 || h.HasMax ||
		h.ReleaseNotesURL != "https://example.com/notes" || string(got) != "hello" {
		t.Fatalf("header %+v, payload %q", h, got)
	}
}

func TestReader(t *testing.T) {
	payload := make([]byte, 10000)
	rand.Read(payload)
	img, _ := Create(testHeader(), payload)

	// In blocks, rejecting in OnHeader.
	reject := errors.New("wrong product")
	r := &Reader{OnHeader: func(h *Header) error { return reject }}
	if err := r.Write(img[:1024]); err != reject {
		t.Fatalf("OnHeader error: %v", err)
	}

	// A corrupted payload fails at Close.
	bad := bytes.Clone(img)
	bad[len(bad)-1] ^= 1
	var got []byte
	r = &Reader{Payload: func(p []byte) error { got = append(got, p...); return nil }}
	for off := 0; off < len(bad); off += 1024 {
		if err := r.Write(bad[off:min(off+1024, len(bad))]); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err == nil {
		t.Fatal("corrupted payload accepted")
	}

	// Intact, then one byte too many.
	got = nil
	r = &Reader{Payload: func(p []byte) error { got = append(got, p...); return nil }}
	if err := r.Write(img); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil || !bytes.Equal(got, payload) || r.Received() != 10000 {
		t.Fatalf("intact image: %v", err)
	}
	if err := r.Write([]byte{0}); err == nil {
		t.Fatal("extra byte accepted")
	}

	// Truncated.
	r = &Reader{}
	r.Write(img[:len(img)-1])
	if err := r.Close(); err == nil {
		t.Fatal("truncated image accepted")
	}

	// Not an image.
	if err := (&Reader{}).Write(make([]byte, 64)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestCreateChecks(t *testing.T) {
	for _, h := range []Header{
		{ProductID: 1, SoftwareVersion: 1, SoftwareVersionString: "1"},
		{VendorID: 1, ProductID: 1, SoftwareVersion: 1},
		{VendorID: 1, ProductID: 1, SoftwareVersion: 1, SoftwareVersionString: "1", HasMax: true, MaxApplicableVersion: 1},
	} {
		if _, err := Create(h, nil); err == nil {
			t.Errorf("Create(%+v) accepted", h)
		}
	}
}
