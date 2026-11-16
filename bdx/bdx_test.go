package bdx_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/bdx"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/internal/simnet"
	"github.com/shabunin/tiny-matter-go/message"
)

func TestCodecs(t *testing.T) {
	ti := bdx.TransferInit{Control: bdx.ReceiverDrive, MaxBlockSize: 1024, FileDesignator: []byte("test.bin")}
	want := []byte{0x20, 0x00, 0x00, 0x04, 0x08, 0x00, 't', 'e', 's', 't', '.', 'b', 'i', 'n'}
	if got := ti.AppendTo(nil); !bytes.Equal(got, want) {
		t.Fatalf("ReceiveInit %x, want %x (SDK)", got, want)
	}
	wide := bdx.TransferInit{Control: bdx.SenderDrive, MaxBlockSize: 512, StartOffset: 7, MaxLength: 1 << 33,
		FileDesignator: []byte("f"), Metadata: []byte{0x15, 0x18}}
	got, err := bdx.ParseTransferInit(wide.AppendTo(nil))
	if err != nil || got.StartOffset != 7 || got.MaxLength != 1<<33 || string(got.FileDesignator) != "f" || !bytes.Equal(got.Metadata, wide.Metadata) {
		t.Fatalf("wide TransferInit round trip: %+v %v", got, err)
	}
	a := bdx.ReceiveAccept{Control: bdx.ReceiverDrive, MaxBlockSize: 1024}
	if b := a.AppendTo(nil); !bytes.Equal(b, []byte{0x20, 0x00, 0x00, 0x04}) {
		t.Fatalf("ReceiveAccept %x", b)
	}
	// A legacy start offset is skipped.
	ra, err := bdx.ParseReceiveAccept([]byte{0x20, 0x03, 0x00, 0x02, 1, 0, 0, 0, 0x10, 0, 0, 0})
	if err != nil || ra.Length != 16 || ra.MaxBlockSize != 512 {
		t.Fatalf("ReceiveAccept with a start offset: %+v %v", ra, err)
	}
}

type pair struct {
	w      *simnet.World
	rx, tx *simnet.Node
	rs, ts *exchange.Session
	sender *bdx.Sender
	sent   []error
	files  map[string][]byte
}

func newPair(t *testing.T) *pair {
	p := &pair{w: simnet.New(t), files: map[string][]byte{}}
	p.rx, p.tx = p.w.Node(1), p.w.Node(2)
	k1, k2 := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	ia, _ := p.rx.M.AllocateSessionID()
	ib, _ := p.tx.M.AllocateSessionID()
	var err error
	p.rs, err = p.rx.M.NewSecureSession(p.w.Now, exchange.SecureSessionParams{Peer: p.tx.Addr, LocalSessionID: ia,
		PeerSessionID: ib, LocalNodeID: 1, PeerNodeID: 2, EncryptKey: k1, DecryptKey: k2, AuthMode: exchange.AuthCASE, FabricIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.ts, err = p.tx.M.NewSecureSession(p.w.Now, exchange.SecureSessionParams{Peer: p.rx.Addr, LocalSessionID: ib,
		PeerSessionID: ia, LocalNodeID: 2, PeerNodeID: 1, EncryptKey: k2, DecryptKey: k1, AuthMode: exchange.AuthCASE, FabricIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.sender = &bdx.Sender{
		Open: func(ex *exchange.Exchange, d []byte) (io.ReaderAt, int64, uint16) {
			f, ok := p.files[string(d)]
			if !ok {
				return nil, 0, bdx.StatusFileDesignatorUnknown
			}
			return bytes.NewReader(f), int64(len(f)), 0
		},
		Done: func(now time.Time, ex *exchange.Exchange, err error) { p.sent = append(p.sent, err) },
	}
	p.tx.M.Register(message.ProtocolBDX, p.sender.Accept)
	return p
}

// get downloads a file, returning its contents and the result.
func (p *pair) get(t *testing.T, name string, write func(b []byte) error) ([]byte, error) {
	t.Helper()
	var got []byte
	var result error
	done := false
	d := &bdx.Download{
		Write: func(now time.Time, b []byte) error {
			if write != nil {
				if err := write(b); err != nil {
					return err
				}
			}
			got = append(got, b...)
			return nil
		},
		Done: func(now time.Time, err error) { result, done = err, true },
	}
	if err := d.Start(p.w.Now, p.rx.M, p.rs, []byte(name), 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600 && !done; i++ {
		p.w.Advance(time.Second)
	}
	if !done {
		t.Fatal("transfer did not end")
	}
	p.w.Advance(10 * time.Second) // the last acknowledgements
	return got, result
}

func TestTransfers(t *testing.T) {
	p := newPair(t)
	for _, n := range []int{0, 1, 1023, 1024, 2048, 5000} {
		f := make([]byte, n)
		rand.Read(f)
		p.files["f"] = f
		p.sent = nil
		got, err := p.get(t, "f", nil)
		if err != nil || !bytes.Equal(got, f) {
			t.Fatalf("%d bytes: got %d bytes, %v", n, len(got), err)
		}
		if len(p.sent) != 1 || p.sent[0] != nil {
			t.Fatalf("%d bytes: sender ended with %v", n, p.sent)
		}
	}
}

func TestUnknownFile(t *testing.T) {
	p := newPair(t)
	_, err := p.get(t, "missing", nil)
	var e *bdx.Error
	if !errors.As(err, &e) || !e.Received || e.Code != bdx.StatusFileDesignatorUnknown {
		t.Fatalf("got %v, want FileDesignatorUnknown from the sender", err)
	}
}

func TestWriteFailure(t *testing.T) {
	p := newPair(t)
	p.files["f"] = make([]byte, 4000)
	n := 0
	_, err := p.get(t, "f", func(b []byte) error {
		if n++; n == 2 {
			return errors.New("flash full")
		}
		return nil
	})
	var e *bdx.Error
	if !errors.As(err, &e) || e.Received || e.Code != bdx.StatusTransferFailedUnknownError {
		t.Fatalf("got %v, want a local TransferFailedUnknownError", err)
	}
	if len(p.sent) != 1 {
		t.Fatalf("sender results %v", p.sent)
	}
	if !errors.As(p.sent[0], &e) || !e.Received || e.Code != bdx.StatusTransferFailedUnknownError {
		t.Fatalf("sender ended with %v, want the receiver's status", p.sent[0])
	}
}

func TestPacketLoss(t *testing.T) {
	p := newPair(t)
	f := make([]byte, 20000)
	rand.Read(f)
	p.files["f"] = f
	n := 0
	p.w.Drop = func(simnet.Packet) bool { n++; return n%5 == 0 }
	got, err := p.get(t, "f", nil)
	if err != nil || !bytes.Equal(got, f) {
		t.Fatalf("with loss: %d bytes, %v", len(got), err)
	}
}
