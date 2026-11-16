// Package ota handles Matter OTA software update image files (core spec
// 11.21.3): a fixed header, a TLV header describing the image, and the
// payload, with a digest of the payload.
package ota

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// FileIdentifier starts every OTA image file.
const FileIdentifier = 0x1BEEF11E

// DigestSHA256 is the only digest type supported (IANA hash function
// registry: sha-256).
const DigestSHA256 = 1

// Limits.
const (
	fixedHeaderSize  = 16
	MaxHeaderSize    = 1024 // the SDK's cap on the TLV header
	maxVersionString = 64
	maxReleaseNotes  = 256
)

// Header describes an image.
type Header struct {
	VendorID              uint16
	ProductID             uint16
	SoftwareVersion       uint32
	SoftwareVersionString string
	PayloadSize           uint64
	// MinApplicableVersion and MaxApplicableVersion bound the versions
	// the image may update, when HasMin and HasMax are set.
	MinApplicableVersion uint32
	MaxApplicableVersion uint32
	HasMin, HasMax       bool
	ReleaseNotesURL      string
	DigestType           uint8
	Digest               []byte
}

// Applies reports whether the image may update a node running version.
func (h *Header) Applies(version uint32) bool {
	return (!h.HasMin || version >= h.MinApplicableVersion) && (!h.HasMax || version <= h.MaxApplicableVersion)
}

// appendTLV appends the TLV header.
func (h *Header) appendTLV(b []byte) []byte {
	w := tlv.NewWriter(b)
	w.StartStruct(tlv.Anonymous)
	w.PutUint(tlv.ContextTag(0), uint64(h.VendorID))
	w.PutUint(tlv.ContextTag(1), uint64(h.ProductID))
	w.PutUint(tlv.ContextTag(2), uint64(h.SoftwareVersion))
	w.PutString(tlv.ContextTag(3), h.SoftwareVersionString)
	w.PutUint(tlv.ContextTag(4), h.PayloadSize)
	if h.HasMin {
		w.PutUint(tlv.ContextTag(5), uint64(h.MinApplicableVersion))
	}
	if h.HasMax {
		w.PutUint(tlv.ContextTag(6), uint64(h.MaxApplicableVersion))
	}
	if h.ReleaseNotesURL != "" {
		w.PutString(tlv.ContextTag(7), h.ReleaseNotesURL)
	}
	w.PutUint(tlv.ContextTag(8), uint64(h.DigestType))
	w.PutBytes(tlv.ContextTag(9), h.Digest)
	w.EndContainer()
	return w.Bytes()
}

// Create returns an image file holding payload, filling in the payload
// size and its SHA-256 digest. As ota_image_tool.py, it requires non-zero
// vendor and product IDs, a version string of 1-64 characters and
// applicable versions below the image's version.
func Create(h Header, payload []byte) ([]byte, error) {
	switch {
	case h.VendorID == 0 || h.ProductID == 0:
		return nil, errors.New("ota: vendor and product IDs must not be zero")
	case len(h.SoftwareVersionString) == 0 || len(h.SoftwareVersionString) > maxVersionString:
		return nil, errors.New("ota: the version string must be 1-64 characters")
	case h.HasMin && h.MinApplicableVersion >= h.SoftwareVersion,
		h.HasMax && h.MaxApplicableVersion >= h.SoftwareVersion:
		return nil, errors.New("ota: applicable versions must be below the image's version")
	case len(h.ReleaseNotesURL) > maxReleaseNotes:
		return nil, errors.New("ota: release notes URL too long")
	}
	sum := sha256.Sum256(payload)
	h.PayloadSize, h.DigestType, h.Digest = uint64(len(payload)), DigestSHA256, sum[:]
	th := h.appendTLV(nil)
	out := make([]byte, fixedHeaderSize, fixedHeaderSize+len(th)+len(payload))
	binary.LittleEndian.PutUint32(out, FileIdentifier)
	binary.LittleEndian.PutUint64(out[4:], uint64(fixedHeaderSize+len(th)+len(payload)))
	binary.LittleEndian.PutUint32(out[12:], uint32(len(th)))
	out = append(out, th...)
	return append(out, payload...), nil
}

// ParseHeader decodes the fixed header and the TLV header at the start
// of an image, returning the header and its total length (where the
// payload starts). It returns ErrShort if b does not hold all of it yet.
func ParseHeader(b []byte) (h Header, n int, err error) {
	if len(b) < fixedHeaderSize {
		return h, 0, ErrShort
	}
	if binary.LittleEndian.Uint32(b) != FileIdentifier {
		return h, 0, errors.New("ota: not an OTA image (bad file identifier)")
	}
	total := binary.LittleEndian.Uint64(b[4:])
	hs := binary.LittleEndian.Uint32(b[12:])
	if hs == 0 || hs > MaxHeaderSize {
		return h, 0, fmt.Errorf("ota: header size %d", hs)
	}
	n = fixedHeaderSize + int(hs)
	if len(b) < n {
		return h, 0, ErrShort
	}
	seen := 0
	r := tlv.NewReader(b[fixedHeaderSize:n])
	if err := r.Next(); err != nil {
		return h, 0, err
	}
	err = im.ForEachField(r, func(r *tlv.Reader, tag uint8) error {
		var v uint64
		var err error
		switch tag {
		case 0, 1, 2, 4, 5, 6, 8:
			if v, err = r.Uint(); err != nil {
				return err
			}
		}
		switch tag {
		case 0:
			h.VendorID = uint16(v)
		case 1:
			h.ProductID = uint16(v)
		case 2:
			h.SoftwareVersion = uint32(v)
		case 3:
			var s []byte
			s, err = r.UTF8()
			h.SoftwareVersionString = string(s)
		case 4:
			h.PayloadSize = v
		case 5:
			h.MinApplicableVersion, h.HasMin = uint32(v), true
		case 6:
			h.MaxApplicableVersion, h.HasMax = uint32(v), true
		case 7:
			var s []byte
			s, err = r.UTF8()
			h.ReleaseNotesURL = string(s)
		case 8:
			h.DigestType = uint8(v)
		case 9:
			var d []byte
			d, err = r.Bytes()
			h.Digest = append([]byte(nil), d...)
		}
		if tag <= 9 {
			seen |= 1 << tag
		}
		return err
	})
	const required = 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<8 | 1<<9
	switch {
	case err != nil:
		return h, 0, fmt.Errorf("ota: bad header: %w", err)
	case seen&required != required:
		return h, 0, errors.New("ota: header misses required fields")
	case total != uint64(n)+h.PayloadSize:
		return h, 0, errors.New("ota: total size does not match the header")
	}
	return h, n, nil
}

// ErrShort means more of the image is needed.
var ErrShort = errors.New("ota: image too short")

// Reader takes an image as it arrives, a piece at a time: it parses the
// header, then passes the payload on while computing its digest.
type Reader struct {
	// OnHeader, if set, is called once the header is known; an error
	// rejects the image.
	OnHeader func(h *Header) error
	// Payload takes the payload in order.
	Payload func(p []byte) error

	Header   Header
	head     []byte // the header so far
	headLen  int    // 0 until parsed
	received uint64 // payload bytes
	sum      hash.Hash
}

// HeaderParsed reports whether the header has arrived.
func (r *Reader) HeaderParsed() bool { return r.headLen > 0 }

// Received returns the payload bytes received.
func (r *Reader) Received() uint64 { return r.received }

// Write takes the next piece of the image.
func (r *Reader) Write(p []byte) error {
	if r.headLen == 0 {
		need := fixedHeaderSize
		if len(r.head) >= fixedHeaderSize {
			need = fixedHeaderSize + int(binary.LittleEndian.Uint32(r.head[12:]))
			if need > fixedHeaderSize+MaxHeaderSize {
				need = fixedHeaderSize + MaxHeaderSize + 1 // ParseHeader rejects it
			}
		}
		take := min(len(p), need-len(r.head))
		r.head = append(r.head, p[:take]...)
		p = p[take:]
		h, n, err := ParseHeader(r.head)
		if err == ErrShort {
			if len(p) > 0 {
				return r.Write(p)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if h.DigestType != DigestSHA256 || len(h.Digest) != sha256.Size {
			return fmt.Errorf("ota: digest type %d not supported", h.DigestType)
		}
		r.Header, r.headLen, r.head = h, n, nil
		r.sum = sha256.New()
		if r.OnHeader != nil {
			if err := r.OnHeader(&r.Header); err != nil {
				return err
			}
		}
	}
	if len(p) == 0 {
		return nil
	}
	if r.received+uint64(len(p)) > r.Header.PayloadSize {
		return errors.New("ota: image longer than its header says")
	}
	r.received += uint64(len(p))
	r.sum.Write(p)
	if r.Payload != nil {
		return r.Payload(p)
	}
	return nil
}

// Close checks that the whole payload arrived and matches the digest.
func (r *Reader) Close() error {
	if r.headLen == 0 || r.received != r.Header.PayloadSize {
		return errors.New("ota: image incomplete")
	}
	var sum [sha256.Size]byte
	if subtle.ConstantTimeCompare(r.sum.Sum(sum[:0]), r.Header.Digest) != 1 {
		return errors.New("ota: payload digest mismatch")
	}
	return nil
}
