// Command onchip runs a complete Matter commissioning on the
// microcontroller itself: a device and a controller exchange real
// encrypted messages over an in-memory loopback (PASE, attestation, CSR,
// AddNOC, CASE, CommissioningComplete, OnOff toggle). It reports timings
// and heap use over the serial console. No radio is used.
package main

import (
	"bytes"
	"net/netip"
	"runtime"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/credentials"
	"github.com/shabunin/tiny-matter-go/credentials/devcreds"
	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/crypto/spake2p"
	"github.com/shabunin/tiny-matter-go/device"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/fabric"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/securechannel/casesession"
	"github.com/shabunin/tiny-matter-go/securechannel/pase"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// xorshift stands in for the hardware RNG in this test.
type xorshift uint64

func (x *xorshift) Read(b []byte) (int, error) {
	for i := range b {
		*x ^= *x << 13
		*x ^= *x >> 7
		*x ^= *x << 17
		b[i] = byte(*x)
	}
	return len(b), nil
}

var rng = xorshift(0x9E3779B97F4A7C15)

type pkt struct {
	from, to exchange.Addr
	data     []byte
}

var queue []pkt

type port exchange.Addr

func (p port) Send(to exchange.Addr, b []byte) error {
	queue = append(queue, pkt{exchange.Addr(p), to, append([]byte(nil), b...)})
	return nil
}

var (
	devAddr = netip.AddrPortFrom(netip.IPv6Loopback(), 5540)
	ctlAddr = netip.AddrPortFrom(netip.IPv6Loopback(), 5550)
	dev     *device.Device
	ctl     *exchange.Manager
	now     = time.Unix(1000, 0)
)

// run delivers packets and fires timers until quiet.
func run() {
	for i := 0; i < 1000; i++ {
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			if p.to == devAddr {
				dev.HandlePacket(now, p.from, p.data)
			} else {
				ctl.HandlePacket(now, p.from, p.data)
			}
		}
		next := dev.Poll(now)
		if t := ctl.Poll(now); !t.IsZero() && (next.IsZero() || t.Before(next)) {
			next = t
		}
		if len(queue) == 0 && (next.IsZero() || next.Sub(now) > 300*time.Millisecond) {
			return
		}
		if next.After(now) {
			now = next
		}
	}
}

type delegate func(ex *exchange.Exchange, msg exchange.Message)

func (d delegate) OnMessage(n time.Time, ex *exchange.Exchange, msg exchange.Message) { d(ex, msg) }
func (delegate) OnError(time.Time, *exchange.Exchange, error)                         {}

func invoke(s *exchange.Session, p im.CommandPath, fields func(w *tlv.Writer)) []byte {
	var got []byte
	ex, _ := ctl.NewExchange(s, delegate(func(ex *exchange.Exchange, msg exchange.Message) {
		got = append([]byte(nil), msg.Payload...)
		ex.Close(now)
	}))
	ex.Send(now, 1, im.OpInvokeRequest, im.EncodeInvokeRequest(p, false, fields))
	run()
	res, err := im.DecodeInvokeResponse(got)
	if err != nil || len(res) != 1 {
		fail("invoke response")
	}
	if res[0].Fields == nil && res[0].Status != 0 {
		println("  status", res[0].Status)
	}
	return res[0].Fields
}

func field(raw []byte, tag uint8) *tlv.Reader {
	r := tlv.NewReader(raw)
	r.Next()
	r.EnterContainer()
	for r.Next() == nil {
		if r.Tag().IsContext(tag) {
			return r
		}
	}
	fail("missing field")
	return nil
}

func fail(msg string) {
	for {
		println("FAIL:", msg)
		time.Sleep(2 * time.Second)
	}
}

var t0 time.Time

func step(name string) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	println(" ", name, "ms:", time.Since(t0).Milliseconds(), "heap in use:", ms.HeapInuse, "sys:", ms.HeapSys)
	t0 = time.Now()
}

func main() {
	time.Sleep(3 * time.Second) // let the USB console attach
	for round := 1; ; round++ {
		println("=== tiny-matter-go on-chip commissioning, round", round)
		commission()
		time.Sleep(10 * time.Second)
	}
}

func commission() {
	start := time.Now()
	t0 = start
	queue = nil
	salt := []byte("SPAKE2P Key Salt")
	v, err := spake2p.NewVerifier(20202021, salt, 1000)
	if err != nil {
		fail(err.Error())
	}
	step("verifier (PBKDF2 1000)")
	dacKey, _ := p256.NewPrivateKey(devcreds.DACPrivateKey)
	dev, err = device.New(device.Config{
		Transport: port(devAddr), Rand: &rng,
		Verifier: v, Salt: salt, Iterations: 1000, Discriminator: 3840,
		Attestation: &clusters.Attestation{DACKey: dacKey, DACCert: devcreds.DACCert, PAICert: devcreds.PAICert,
			CertificationDeclaration: devcreds.CertificationDeclaration},
		Basic: &clusters.BasicInformation{VendorName: "tiny-matter-go", VendorID: 0xFFF1, ProductName: "Cardputer", ProductID: 0x8000},
	})
	if err != nil {
		fail(err.Error())
	}
	light := &clusters.OnOff{}
	ep := dev.Node.AddEndpoint(1, clusters.DeviceTypeOnOffLight)
	dev.Node.AddCluster(ep, clusters.Descriptor{}, light)
	dev.OpenCommissioningWindow()
	ctl, _ = exchange.NewManager(exchange.Config{Transport: port(ctlAddr), Rand: &rng})
	step("device up")

	var paseS *exchange.Session
	pase.Pair(now, ctl, devAddr, pase.InitiatorConfig{Passcode: 20202021, Rand: &rng,
		Done: func(n time.Time, s *exchange.Session, err error) { paseS = s }})
	run()
	if paseS == nil {
		fail("PASE")
	}
	step("PASE (both sides)")

	gc := func(c uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDGeneralCommissioning, Command: c}
	}
	oc := func(c uint32) im.CommandPath {
		return im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: c}
	}
	invoke(paseS, gc(0), func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 60); w.PutUint(tlv.ContextTag(1), 1) })
	step("ArmFailSafe")

	nonce := make([]byte, 32)
	rng.Read(nonce)
	f := invoke(paseS, oc(0), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) })
	elems, _ := field(f, 0).Bytes()
	sig, _ := field(f, 1).Bytes()
	dacPub, _ := p256.NewPublicKey(devcreds.DACPublicKey)
	if !dacPub.VerifyMessage(append(append([]byte(nil), elems...), paseS.AttestationChallenge[:]...), sig) {
		fail("attestation signature")
	}
	step("attestation (sign + verify)")

	f = invoke(paseS, oc(4), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), nonce) })
	nocsr, _ := field(f, 0).Bytes()
	csr, _ := field(nocsr, 1).Bytes()
	i := bytes.Index(csr, []byte{0x03, 0x42, 0x00, 0x04})
	if i < 0 {
		fail("CSR public key")
	}
	nodePub := csr[i+3 : i+3+65]
	step("CSR (keygen + sign)")

	rootKey, _ := p256.GenerateKey(&rng)
	root, _ := credentials.IssueRoot(rootKey, 1)
	devNOC, _ := credentials.IssueNOC(root, rootKey, nodePub, 0xFAB, 1)
	ctlKey, _ := p256.GenerateKey(&rng)
	ctlNOC, _ := credentials.IssueNOC(root, rootKey, ctlKey.PublicKey().Bytes(), 0xFAB, 0x1B669)
	ipk := []byte("temporary ipk 01")
	step("controller issues certs")

	invoke(paseS, oc(0x0B), func(w *tlv.Writer) { w.PutBytes(tlv.ContextTag(0), root.Encode()) })
	f = invoke(paseS, oc(6), func(w *tlv.Writer) {
		w.PutBytes(tlv.ContextTag(0), devNOC.Encode())
		w.PutBytes(tlv.ContextTag(2), ipk)
		w.PutUint(tlv.ContextTag(3), 0x1B669)
		w.PutUint(tlv.ContextTag(4), 0xFFF1)
	})
	if code, _ := field(f, 0).Uint(); code != 0 {
		fail("AddNOC")
	}
	step("AddTrustedRoot + AddNOC (chain validation)")

	table := &fabric.Table{}
	ctlF, err := table.Add(root.Encode(), nil, ctlNOC.Encode(), ctlKey, ipk, 0xFFF1)
	if err != nil {
		fail(err.Error())
	}
	var caseS *exchange.Session
	casesession.Connect(now, ctl, devAddr, casesession.InitiatorConfig{Fabric: ctlF, PeerNodeID: 1, Rand: &rng,
		Done: func(n time.Time, s *exchange.Session, err error) { caseS = s }})
	run()
	if caseS == nil {
		fail("CASE")
	}
	step("CASE (both sides)")

	f = invoke(caseS, gc(4), nil)
	if code, _ := field(f, 0).Uint(); code != 0 {
		fail("CommissioningComplete")
	}
	invoke(caseS, im.CommandPath{Endpoint: 1, Cluster: clusters.IDOnOff, Command: 2}, nil)
	if !light.On {
		fail("toggle")
	}
	step("CommissioningComplete + OnOff toggle")
	println("PASS: commissioned and toggled in", time.Since(start).Milliseconds(), "ms")
}
