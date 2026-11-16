package bdx

import (
	"errors"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

// Sender serves files to receivers that drive synchronous transfers
// (ReceiveInit). Register Accept for the BDX protocol on an
// exchange.Manager.
type Sender struct {
	// Open returns the file a peer asks for on ex, and its size, or a
	// status code (StatusFileDesignatorUnknown, StatusResponderBusy, ...)
	// to refuse.
	Open func(ex *exchange.Exchange, designator []byte) (f io.ReaderAt, size int64, status uint16)
	// MaxBlockSize caps the block size (DefaultBlockSize if zero).
	MaxBlockSize uint16
	// Done, if set, is called when a transfer ends: err is nil once the
	// receiver acknowledged the last block.
	Done func(now time.Time, ex *exchange.Exchange, err error)
}

// Accept takes an exchange a receiver starts (exchange.Factory).
func (s *Sender) Accept(ex *exchange.Exchange) exchange.Delegate {
	return &sending{s: s}
}

type sending struct {
	s         *Sender
	f         io.ReaderAt
	offset    int64 // of the next block
	end       int64
	blockSize int
	next      uint32 // the counter of the block to send next
	eofSent   bool
	ended     bool
	buf       []byte
}

func (t *sending) finish(now time.Time, ex *exchange.Exchange, err error) {
	if t.ended {
		return
	}
	t.ended = true
	ex.Close(now)
	if t.s.Done != nil {
		t.s.Done(now, ex, err)
	}
}

func (t *sending) fail(now time.Time, ex *exchange.Exchange, code uint16) {
	if !t.ended {
		securechannel.SendStatus(now, ex, Status(code))
	}
	t.finish(now, ex, &Error{Code: code})
}

func (t *sending) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if t.ended {
		return
	}
	if msg.ProtocolID == message.ProtocolSecureChannel && msg.Opcode == securechannel.OpStatusReport {
		sr, err := securechannel.ParseStatusReport(msg.Payload)
		code := uint16(StatusUnknown)
		if err == nil && sr.ProtocolID == uint32(message.ProtocolBDX) {
			code = sr.ProtocolCode
		}
		t.finish(now, ex, &Error{Code: code, Received: true})
		return
	}
	if msg.ProtocolID != message.ProtocolBDX {
		t.fail(now, ex, StatusUnexpectedMessage)
		return
	}
	switch {
	case msg.Opcode == OpReceiveInit && t.f == nil:
		t.init(now, ex, msg.Payload)

	case (msg.Opcode == OpBlockQuery || msg.Opcode == OpBlockQueryWithSkip) && t.f != nil && !t.eofSent:
		counter, rest, err := ParseCounter(msg.Payload)
		switch {
		case err != nil || (msg.Opcode == OpBlockQueryWithSkip && len(rest) < 8):
			t.fail(now, ex, StatusBadMessageContents)
			return
		case counter != t.next:
			t.fail(now, ex, StatusBadBlockCounter)
			return
		}
		if msg.Opcode == OpBlockQueryWithSkip {
			skip := uint64(rest[0]) | uint64(rest[1])<<8 | uint64(rest[2])<<16 | uint64(rest[3])<<24 |
				uint64(rest[4])<<32 | uint64(rest[5])<<40 | uint64(rest[6])<<48 | uint64(rest[7])<<56
			if skip > uint64(t.end-t.offset) {
				skip = uint64(t.end - t.offset)
			}
			t.offset += int64(skip)
		}
		t.sendBlock(now, ex)

	case msg.Opcode == OpBlockAck && t.f != nil:
		// Optional in receiver drive: the next query follows.

	case msg.Opcode == OpBlockAckEOF && t.eofSent:
		counter, _, err := ParseCounter(msg.Payload)
		if err != nil || counter != t.next-1 {
			t.fail(now, ex, StatusBadBlockCounter)
			return
		}
		t.finish(now, ex, nil)

	default:
		t.fail(now, ex, StatusUnexpectedMessage)
	}
}

func (t *sending) init(now time.Time, ex *exchange.Exchange, payload []byte) {
	ti, err := ParseTransferInit(payload)
	switch {
	case err != nil:
		t.fail(now, ex, StatusBadMessageContents)
		return
	case ti.Control&ReceiverDrive == 0:
		t.fail(now, ex, StatusTransferMethodNotSupported)
		return
	case ti.MaxBlockSize == 0:
		t.fail(now, ex, StatusBadMessageContents)
		return
	}
	f, size, status := t.s.Open(ex, ti.FileDesignator)
	if f == nil {
		if status == 0 {
			status = StatusFileDesignatorUnknown
		}
		t.fail(now, ex, status)
		return
	}
	if ti.StartOffset > uint64(size) {
		t.fail(now, ex, StatusLengthTooLarge)
		return
	}
	t.f, t.offset, t.end = f, int64(ti.StartOffset), size
	if ti.MaxLength > 0 && ti.MaxLength < uint64(t.end-t.offset) {
		t.end = t.offset + int64(ti.MaxLength)
	}
	bs := t.s.MaxBlockSize
	if bs == 0 {
		bs = DefaultBlockSize
	}
	bs = min(bs, ti.MaxBlockSize)
	if max := ex.MaxPayload() - 4; int(bs) > max {
		bs = uint16(max)
	}
	t.blockSize = int(bs)
	t.buf = make([]byte, 4+t.blockSize)
	a := ReceiveAccept{Control: Version | ReceiverDrive, MaxBlockSize: bs, Length: uint64(t.end - t.offset)}
	if err := ex.Send(now, message.ProtocolBDX, OpReceiveAccept, a.AppendTo(t.buf[:0])); err != nil {
		t.finish(now, ex, err)
	}
}

func (t *sending) sendBlock(now time.Time, ex *exchange.Exchange) {
	n := min(int64(t.blockSize), t.end-t.offset)
	b := AppendCounter(t.buf[:0], t.next)
	b = b[:4+n]
	if n > 0 {
		if _, err := t.f.ReadAt(b[4:], t.offset); err != nil && !errors.Is(err, io.EOF) {
			t.fail(now, ex, StatusTransferFailedUnknownError)
			return
		}
	}
	t.offset += n
	op := uint8(OpBlock)
	if t.offset == t.end {
		op, t.eofSent = OpBlockEOF, true
	}
	t.next++
	if err := ex.Send(now, message.ProtocolBDX, op, b); err != nil {
		t.finish(now, ex, err)
	}
}

func (t *sending) OnError(now time.Time, ex *exchange.Exchange, err error) {
	if !t.ended {
		t.ended = true
		if t.s.Done != nil {
			t.s.Done(now, ex, err)
		}
	}
}
