// Package bdx implements the Bulk Data Exchange protocol (Matter core
// spec 11.22) as OTA software updates use it: synchronous, receiver
// drive, one exchange per transfer. Download receives a file; Sender
// serves files.
package bdx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

// Message types.
const (
	OpSendInit           = 0x01
	OpSendAccept         = 0x02
	OpReceiveInit        = 0x04
	OpReceiveAccept      = 0x05
	OpBlockQuery         = 0x10
	OpBlock              = 0x11
	OpBlockEOF           = 0x12
	OpBlockAck           = 0x13
	OpBlockAckEOF        = 0x14
	OpBlockQueryWithSkip = 0x15
)

// Transfer control flags (with the version in the low nibble) and range
// control flags.
const (
	Version       = 0
	SenderDrive   = 0x10
	ReceiverDrive = 0x20
	Async         = 0x40
	rangeDefLen   = 0x01
	rangeStart    = 0x02
	rangeWide     = 0x10
)

// Status codes, sent in a failure StatusReport for the BDX protocol.
const (
	StatusLengthTooLarge             = 0x12
	StatusLengthTooShort             = 0x13
	StatusLengthMismatch             = 0x14
	StatusLengthRequired             = 0x15
	StatusBadMessageContents         = 0x16
	StatusBadBlockCounter            = 0x17
	StatusUnexpectedMessage          = 0x18
	StatusResponderBusy              = 0x19
	StatusTransferFailedUnknownError = 0x1F
	StatusTransferMethodNotSupported = 0x50
	StatusFileDesignatorUnknown      = 0x51
	StatusStartOffsetNotSupported    = 0x52
	StatusVersionNotSupported        = 0x53
	StatusUnknown                    = 0x5F
)

// MaxFileDesignator is the longest file designator.
const MaxFileDesignator = 255

var errShort = errors.New("bdx: message too short")

// Error is a BDX failure: a status code sent or received.
type Error struct {
	Code     uint16
	Received bool // the peer reported it
}

func (e *Error) Error() string {
	if e.Received {
		return "bdx: peer reported status 0x" + strconv.FormatUint(uint64(e.Code), 16)
	}
	return "bdx: transfer failed with status 0x" + strconv.FormatUint(uint64(e.Code), 16)
}

// Status returns the StatusReport for a BDX failure code.
func Status(code uint16) securechannel.StatusReport {
	return securechannel.StatusReport{GeneralCode: securechannel.GeneralFailure,
		ProtocolID: uint32(message.ProtocolBDX), ProtocolCode: code}
}

// TransferInit is a SendInit or ReceiveInit message.
type TransferInit struct {
	Control        uint8 // proposed modes (SenderDrive, ReceiverDrive, Async) and version
	MaxBlockSize   uint16
	StartOffset    uint64 // 0: from the start
	MaxLength      uint64 // 0: indefinite
	FileDesignator []byte
	Metadata       []byte // TLV
}

// AppendTo appends the encoded message to b.
func (t *TransferInit) AppendTo(b []byte) []byte {
	var rc uint8
	wide := t.StartOffset > 0xFFFFFFFF || t.MaxLength > 0xFFFFFFFF
	if t.StartOffset > 0 {
		rc |= rangeStart
	}
	if t.MaxLength > 0 {
		rc |= rangeDefLen
	}
	if wide {
		rc |= rangeWide
	}
	b = append(b, t.Control, rc)
	b = binary.LittleEndian.AppendUint16(b, t.MaxBlockSize)
	b = appendLen(b, t.StartOffset, rc&rangeStart != 0, wide)
	b = appendLen(b, t.MaxLength, rc&rangeDefLen != 0, wide)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(t.FileDesignator)))
	b = append(b, t.FileDesignator...)
	return append(b, t.Metadata...)
}

func appendLen(b []byte, v uint64, present, wide bool) []byte {
	switch {
	case !present:
		return b
	case wide:
		return binary.LittleEndian.AppendUint64(b, v)
	}
	return binary.LittleEndian.AppendUint32(b, uint32(v))
}

// readLen reads a 4 or 8 byte length if present.
func readLen(b []byte, present, wide bool) (uint64, []byte, error) {
	switch {
	case !present:
		return 0, b, nil
	case wide:
		if len(b) < 8 {
			return 0, nil, errShort
		}
		return binary.LittleEndian.Uint64(b), b[8:], nil
	}
	if len(b) < 4 {
		return 0, nil, errShort
	}
	return uint64(binary.LittleEndian.Uint32(b)), b[4:], nil
}

// ParseTransferInit decodes a SendInit or ReceiveInit. The designator and
// metadata alias b.
func ParseTransferInit(b []byte) (t TransferInit, err error) {
	if len(b) < 4 {
		return t, errShort
	}
	t.Control, t.MaxBlockSize = b[0], binary.LittleEndian.Uint16(b[2:])
	rc := b[1]
	b = b[4:]
	wide := rc&rangeWide != 0
	if t.StartOffset, b, err = readLen(b, rc&rangeStart != 0, wide); err != nil {
		return t, err
	}
	if t.MaxLength, b, err = readLen(b, rc&rangeDefLen != 0, wide); err != nil {
		return t, err
	}
	if len(b) < 2 {
		return t, errShort
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	if n > MaxFileDesignator || len(b) < n {
		return t, fmt.Errorf("bdx: bad file designator length %d", n)
	}
	t.FileDesignator, t.Metadata = b[:n], b[n:]
	return t, nil
}

// ReceiveAccept is a ReceiveAccept message.
type ReceiveAccept struct {
	Control      uint8 // the chosen mode and version
	MaxBlockSize uint16
	Length       uint64 // 0: indefinite
	Metadata     []byte
}

// AppendTo appends the encoded message to b.
func (a *ReceiveAccept) AppendTo(b []byte) []byte {
	var rc uint8
	wide := a.Length > 0xFFFFFFFF
	if a.Length > 0 {
		rc |= rangeDefLen
	}
	if wide {
		rc |= rangeWide
	}
	b = append(b, a.Control, rc)
	b = binary.LittleEndian.AppendUint16(b, a.MaxBlockSize)
	b = appendLen(b, a.Length, a.Length > 0, wide)
	return append(b, a.Metadata...)
}

// ParseReceiveAccept decodes a ReceiveAccept, skipping the start offset
// older senders included.
func ParseReceiveAccept(b []byte) (a ReceiveAccept, err error) {
	if len(b) < 4 {
		return a, errShort
	}
	a.Control, a.MaxBlockSize = b[0], binary.LittleEndian.Uint16(b[2:])
	rc := b[1]
	b = b[4:]
	wide := rc&rangeWide != 0
	if _, b, err = readLen(b, rc&rangeStart != 0, wide); err != nil {
		return a, err
	}
	if a.Length, b, err = readLen(b, rc&rangeDefLen != 0, wide); err != nil {
		return a, err
	}
	a.Metadata = b
	return a, nil
}

// AppendCounter appends a BlockQuery, BlockAck or BlockAckEOF, or the
// start of a Block or BlockEOF.
func AppendCounter(b []byte, counter uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, counter)
}

// ParseCounter decodes the block counter that starts every block message;
// rest is a block's data.
func ParseCounter(b []byte) (counter uint32, rest []byte, err error) {
	if len(b) < 4 {
		return 0, nil, errShort
	}
	return binary.LittleEndian.Uint32(b), b[4:], nil
}

// modes masks the mode flags of a transfer control byte.
const modes = SenderDrive | ReceiverDrive | Async
