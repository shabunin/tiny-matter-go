package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/shabunin/tiny-matter-go/bdx"
	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/dnssd"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/message"
	"github.com/shabunin/tiny-matter-go/ota"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// OTAProvider makes the controller an OTA software update provider for its
// nodes: it answers their queries with one image and serves it over BDX.
// The callbacks run on the controller's network goroutine and must not
// block or call the controller.
type OTAProvider struct {
	// Image is a whole OTA image file (see package ota).
	Image []byte
	// OnQuery is called for each QueryImage, with whether the image was
	// offered.
	OnQuery func(node uint64, q *clusters.QueryImage, offered bool)
	// OnProgress is called as a node downloads the image.
	OnProgress func(node uint64, sent, total int64)
	// OnTransfer is called when a download ends; err is nil once the node
	// acknowledged the last block.
	OnTransfer func(node uint64, err error)
	// OnApply is called when a node asks to apply the downloaded version.
	OnApply func(node uint64, version uint32)
	// OnApplied is called when a node reports that it runs the version.
	OnApplied func(node uint64, version uint32)

	header     ota.Header
	self       uint64 // the controller's node ID
	designator string
	tokens     map[uint64][]byte
}

// ServeOTA starts serving p, replacing an earlier provider.
func (c *Controller) ServeOTA(p *OTAProvider) error {
	h, n, err := ota.ParseHeader(p.Image)
	if err != nil {
		return err
	}
	if uint64(len(p.Image)) != uint64(n)+h.PayloadSize {
		return errors.New("controller: OTA image length does not match its header")
	}
	p.header, p.self = h, c.fab.NodeID
	p.designator = fmt.Sprintf("%04X-%04X-%d.ota", h.VendorID, h.ProductID, h.SoftwareVersion)
	p.tokens = map[uint64][]byte{}
	node := im.NewNode(1)
	ep := node.AddEndpoint(0, clusters.DeviceTypeOTAProvider)
	node.AddCluster(ep, &clusters.OTAProvider{
		QueryImage:          p.query,
		ApplyUpdate:         p.apply,
		NotifyUpdateApplied: p.applied,
	})
	sender := &bdx.Sender{
		Open: p.open,
		Done: func(now time.Time, ex *exchange.Exchange, err error) {
			if p.OnTransfer != nil {
				p.OnTransfer(ex.Session().PeerNodeID(), err)
			}
		},
	}
	return c.do(func(now time.Time) {
		// im.NewServer registers itself for the Interaction Model; the
		// controller routes to it instead.
		c.server = im.NewServer(c.m, node)
		c.m.Register(message.ProtocolInteractionModel, c.imFactory)
		c.m.Register(message.ProtocolBDX, sender.Accept)
	})
}

func (p *OTAProvider) query(ctx *im.Context, q *clusters.QueryImage) clusters.QueryImageResponse {
	node := ctx.Session.PeerNodeID()
	h := &p.header
	bdxSync := false
	for _, proto := range q.Protocols {
		bdxSync = bdxSync || proto == clusters.OTAProtocolBDXSynchronous
	}
	res := clusters.QueryImageResponse{Status: clusters.OTANotAvailable}
	switch {
	case !bdxSync:
		res.Status = clusters.OTADownloadProtocolNotSupported
	case q.VendorID == h.VendorID && q.ProductID == h.ProductID && q.SoftwareVersion < h.SoftwareVersion && h.Applies(q.SoftwareVersion):
		token := make([]byte, 32)
		rand.Read(token)
		p.tokens[node] = token
		res = clusters.QueryImageResponse{
			Status:                clusters.OTAUpdateAvailable,
			ImageURI:              clusters.BDXURI(p.self, p.designator),
			SoftwareVersion:       h.SoftwareVersion,
			SoftwareVersionString: h.SoftwareVersionString,
			UpdateToken:           token,
		}
	}
	if p.OnQuery != nil {
		p.OnQuery(node, q, res.Status == clusters.OTAUpdateAvailable)
	}
	return res
}

func (p *OTAProvider) apply(ctx *im.Context, token []byte, version uint32) (uint8, uint32) {
	node := ctx.Session.PeerNodeID()
	if !bytes.Equal(token, p.tokens[node]) || version != p.header.SoftwareVersion {
		return clusters.OTAApplyDiscontinue, 0
	}
	if p.OnApply != nil {
		p.OnApply(node, version)
	}
	return clusters.OTAApplyProceed, 0
}

func (p *OTAProvider) applied(ctx *im.Context, token []byte, version uint32) {
	node := ctx.Session.PeerNodeID()
	if bytes.Equal(token, p.tokens[node]) && p.OnApplied != nil {
		p.OnApplied(node, version)
	}
}

func (p *OTAProvider) open(ex *exchange.Exchange, designator []byte) (io.ReaderAt, int64, uint16) {
	node := ex.Session().PeerNodeID()
	if string(designator) != p.designator || p.tokens[node] == nil {
		return nil, 0, bdx.StatusFileDesignatorUnknown
	}
	total := int64(len(p.Image))
	return &progressReader{r: bytes.NewReader(p.Image), f: func(end int64) {
		if p.OnProgress != nil {
			p.OnProgress(node, end, total)
		}
	}}, total, 0
}

type progressReader struct {
	r io.ReaderAt
	f func(end int64)
}

func (r *progressReader) ReadAt(b []byte, off int64) (int, error) {
	n, err := r.r.ReadAt(b, off)
	r.f(off + int64(n))
	return n, err
}

// AnnounceOTA tells a node that the controller is an OTA provider with an
// update for it (AnnounceOTAProvider); the node then queries it.
func (c *Controller) AnnounceOTA(ctx context.Context, node uint64) error {
	vendor := c.fab.VendorID
	_, err := c.Invoke(ctx, node, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOTARequestor, Command: clusters.CmdAnnounceOTAProvider}, 0,
		func(w *tlv.Writer) {
			w.PutUint(tlv.ContextTag(0), c.fab.NodeID)
			w.PutUint(tlv.ContextTag(1), uint64(vendor))
			w.PutUint(tlv.ContextTag(2), clusters.OTAAnnounceUpdateAvailable)
			w.PutUint(tlv.ContextTag(4), 0)
		})
	return err
}

// SetDefaultOTAProvider makes the controller the node's default OTA
// provider on its fabric (DefaultOTAProviders), which the node queries
// periodically. Only this run of the controller answers as that node ID,
// and the node finds it with DNS-SD: advertise OperationalService.
func (c *Controller) SetDefaultOTAProvider(ctx context.Context, node uint64) error {
	return c.Write(ctx, node, im.AttributePath{Endpoint: 0, Cluster: clusters.IDOTARequestor, Attribute: 0}, 0,
		func(w *tlv.Writer, tag tlv.Tag) {
			w.StartArray(tag)
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(1), c.fab.NodeID)
			w.PutUint(tlv.ContextTag(2), 0) // endpoint
			w.EndContainer()
			w.EndContainer()
		})
}

// OperationalService is the controller's operational DNS-SD service
// (_matter._tcp), for nodes that open sessions to it, such as OTA
// requestors looking up their provider.
func (c *Controller) OperationalService() dnssd.Service {
	o := dnssd.Operational{CompressedFabricID: c.fab.CompressedFabricID, NodeID: c.fab.NodeID, Port: c.LocalAddr().Port()}
	return o.Service()
}
