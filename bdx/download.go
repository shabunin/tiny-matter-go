package bdx

import (
	"errors"
	"time"

	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/securechannel"
)

// DefaultBlockSize is the block size OTA downloads propose (UDP).
const DefaultBlockSize = 1024

// Download receives one file as the receiver driving a synchronous
// transfer: it sends ReceiveInit, then a BlockQuery for each block, and
// BlockAckEOF after the last.
type Download struct {
	// Write takes each block's data in order. An error ends the transfer:
	// the sender is told with the error's BDX status (an *Error's code, or
	// TransferFailedUnknownError).
	Write func(now time.Time, p []byte) error
	// Done is called once when the transfer ends: err is nil after the
	// last block was written and acknowledged.
	Done func(now time.Time, err error)

	ex        *exchange.Exchange
	blockSize uint16
	length    uint64 // announced by the sender, 0 if indefinite
	received  uint64
	counter   uint32 // the block queried last
	accepted  bool
	ended     bool
	buf       [MaxFileDesignator + 16]byte
}

// Received returns the bytes received so far.
func (d *Download) Received() uint64 { return d.received }

// Length returns the file length the sender announced, 0 if it did not.
func (d *Download) Length() uint64 { return d.length }

// Start opens an exchange on s and asks for the file with ReceiveInit,
// proposing blockSize (DefaultBlockSize if zero, less if the session's
// messages cannot carry it).
func (d *Download) Start(now time.Time, m *exchange.Manager, s *exchange.Session, designator []byte, blockSize uint16) error {
	if len(designator) == 0 || len(designator) > MaxFileDesignator {
		return errors.New("bdx: bad file designator")
	}
	ex, err := m.NewExchange(s, d)
	if err != nil {
		return err
	}
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	if max := ex.MaxPayload() - 4; int(blockSize) > max {
		blockSize = uint16(max)
	}
	d.ex, d.blockSize = ex, blockSize
	init := TransferInit{Control: Version | ReceiverDrive, MaxBlockSize: blockSize, FileDesignator: designator}
	if err := ex.Send(now, message.ProtocolBDX, OpReceiveInit, init.AppendTo(d.buf[:0])); err != nil {
		ex.Close(now)
		return err
	}
	return nil
}

// Abort ends the transfer, telling the sender with a status code.
func (d *Download) Abort(now time.Time, code uint16) {
	d.fail(now, &Error{Code: code})
}

func (d *Download) finish(now time.Time, err error) {
	if d.ended {
		return
	}
	d.ended = true
	if d.Done != nil {
		d.Done(now, err)
	}
}

// fail sends a failure status (unless the peer reported one) and ends.
func (d *Download) fail(now time.Time, err error) {
	if d.ended {
		return
	}
	var e *Error
	if errors.As(err, &e) && !e.Received {
		securechannel.SendStatus(now, d.ex, Status(e.Code))
	}
	d.ex.Close(now)
	d.finish(now, err)
}

func (d *Download) query(now time.Time) {
	if err := d.ex.Send(now, message.ProtocolBDX, OpBlockQuery, AppendCounter(d.buf[:0], d.counter)); err != nil {
		d.ex.Close(now)
		d.finish(now, err)
	}
}

// OnMessage handles the sender's messages (exchange.Delegate).
func (d *Download) OnMessage(now time.Time, ex *exchange.Exchange, msg exchange.Message) {
	if d.ended {
		return
	}
	if msg.ProtocolID == message.ProtocolSecureChannel && msg.Opcode == securechannel.OpStatusReport {
		sr, err := securechannel.ParseStatusReport(msg.Payload)
		code := uint16(StatusUnknown)
		if err == nil && sr.ProtocolID == uint32(message.ProtocolBDX) {
			code = sr.ProtocolCode
		}
		d.ex.Close(now)
		d.finish(now, &Error{Code: code, Received: true})
		return
	}
	if msg.ProtocolID != message.ProtocolBDX {
		d.fail(now, &Error{Code: StatusUnexpectedMessage})
		return
	}
	switch {
	case msg.Opcode == OpReceiveAccept && !d.accepted:
		a, err := ParseReceiveAccept(msg.Payload)
		if err != nil || a.Control&modes != ReceiverDrive || a.MaxBlockSize == 0 || a.MaxBlockSize > d.blockSize {
			d.fail(now, &Error{Code: StatusBadMessageContents})
			return
		}
		d.accepted, d.blockSize, d.length = true, a.MaxBlockSize, a.Length
		d.query(now)

	case (msg.Opcode == OpBlock || msg.Opcode == OpBlockEOF) && d.accepted:
		counter, data, err := ParseCounter(msg.Payload)
		switch {
		case err != nil || len(data) > int(d.blockSize) || (msg.Opcode == OpBlock && len(data) == 0):
			d.fail(now, &Error{Code: StatusBadMessageContents})
			return
		case counter != d.counter:
			d.fail(now, &Error{Code: StatusBadBlockCounter})
			return
		case d.length > 0 && d.received+uint64(len(data)) > d.length:
			d.fail(now, &Error{Code: StatusLengthMismatch})
			return
		}
		if len(data) > 0 && d.Write != nil {
			if err := d.Write(now, data); err != nil {
				var e *Error
				if !errors.As(err, &e) {
					err = &Error{Code: StatusTransferFailedUnknownError}
				}
				d.fail(now, err)
				return
			}
		}
		d.received += uint64(len(data))
		if msg.Opcode == OpBlock {
			d.counter++
			d.query(now)
			return
		}
		if d.length > 0 && d.received != d.length {
			d.fail(now, &Error{Code: StatusLengthMismatch})
			return
		}
		// The sender closes on BlockAckEOF; it is retransmitted until
		// acknowledged.
		d.ex.Send(now, message.ProtocolBDX, OpBlockAckEOF, AppendCounter(d.buf[:0], counter))
		d.ex.Close(now)
		d.finish(now, nil)

	default:
		d.fail(now, &Error{Code: StatusUnexpectedMessage})
	}
}

// OnError ends the transfer when the exchange fails (exchange.Delegate).
func (d *Download) OnError(now time.Time, ex *exchange.Exchange, err error) {
	d.finish(now, err)
}
