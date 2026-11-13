package message

import "encoding/binary"

// Protocol IDs in the Matter common vendor namespace.
const (
	ProtocolSecureChannel    uint16 = 0x0000
	ProtocolInteractionModel uint16 = 0x0001
	ProtocolBDX              uint16 = 0x0002
	ProtocolUDC              uint16 = 0x0003
)

// Exchange flag bits.
const (
	exInitiator  = 0x01
	exAck        = 0x02
	exReliable   = 0x04
	exSecuredExt = 0x08
	exVendor     = 0x10
)

// ProtocolHeader is the exchange-layer header at the start of the
// (possibly encrypted) message payload (spec 4.4.3).
type ProtocolHeader struct {
	Initiator bool // I: sent by the exchange initiator
	NeedsAck  bool // R: reliable delivery requested
	HasAck    bool // A: AckCounter is valid

	Opcode     uint8
	ExchangeID uint16
	VendorID   uint16 // 0 is the common namespace and is not encoded
	ProtocolID uint16
	AckCounter uint32

	// SecuredExtensions holds the secured extensions block (SX) of a decoded
	// header, aliasing the input. Encoding writes it if non-nil.
	SecuredExtensions []byte
}

// Size returns the encoded size of the protocol header.
func (p *ProtocolHeader) Size() int {
	n := 6
	if p.VendorID != 0 {
		n += 2
	}
	if p.HasAck {
		n += 4
	}
	if p.SecuredExtensions != nil {
		n += 2 + len(p.SecuredExtensions)
	}
	return n
}

// AppendTo appends the encoded protocol header to b.
func (p *ProtocolHeader) AppendTo(b []byte) []byte {
	var f byte
	if p.Initiator {
		f |= exInitiator
	}
	if p.HasAck {
		f |= exAck
	}
	if p.NeedsAck {
		f |= exReliable
	}
	if p.SecuredExtensions != nil {
		f |= exSecuredExt
	}
	if p.VendorID != 0 {
		f |= exVendor
	}
	b = append(b, f, p.Opcode)
	b = binary.LittleEndian.AppendUint16(b, p.ExchangeID)
	if p.VendorID != 0 {
		b = binary.LittleEndian.AppendUint16(b, p.VendorID)
	}
	b = binary.LittleEndian.AppendUint16(b, p.ProtocolID)
	if p.HasAck {
		b = binary.LittleEndian.AppendUint32(b, p.AckCounter)
	}
	if p.SecuredExtensions != nil {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(p.SecuredExtensions)))
		b = append(b, p.SecuredExtensions...)
	}
	return b
}

// Decode parses a protocol header from the start of b and returns its
// encoded size; the application payload follows.
func (p *ProtocolHeader) Decode(b []byte) (int, error) {
	*p = ProtocolHeader{}
	if len(b) < 6 {
		return 0, ErrTruncated
	}
	f := b[0]
	p.Initiator = f&exInitiator != 0
	p.HasAck = f&exAck != 0
	p.NeedsAck = f&exReliable != 0
	p.Opcode = b[1]
	p.ExchangeID = binary.LittleEndian.Uint16(b[2:])
	n := 4
	if f&exVendor != 0 {
		if len(b) < n+2 {
			return 0, ErrTruncated
		}
		p.VendorID = binary.LittleEndian.Uint16(b[n:])
		n += 2
	}
	if len(b) < n+2 {
		return 0, ErrTruncated
	}
	p.ProtocolID = binary.LittleEndian.Uint16(b[n:])
	n += 2
	if p.HasAck {
		if len(b) < n+4 {
			return 0, ErrTruncated
		}
		p.AckCounter = binary.LittleEndian.Uint32(b[n:])
		n += 4
	}
	if f&exSecuredExt != 0 {
		if len(b) < n+2 {
			return 0, ErrTruncated
		}
		l := int(binary.LittleEndian.Uint16(b[n:]))
		n += 2
		if len(b)-n < l {
			return 0, ErrTruncated
		}
		p.SecuredExtensions = b[n : n+l : n+l]
		n += l
	}
	return n, nil
}
