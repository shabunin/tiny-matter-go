package im_test

import (
	"fmt"
	"testing"

	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const listClusterID = 0xFFF1FC02

// listCluster has a list too large for one message (0), a status-only
// attribute with a cluster-specific status (1), and a small list (2).
type listCluster struct {
	im.ClusterBase
	items int
}

func (*listCluster) ID() uint32           { return listClusterID }
func (*listCluster) Revision() uint16     { return 1 }
func (*listCluster) Attributes() []uint32 { return []uint32{0, 1, 2} }

func (c *listCluster) ReadAttribute(ctx *im.Context, attr uint32, w *tlv.Writer, tag tlv.Tag) im.Status {
	switch attr {
	case 0:
		w.StartArray(tag)
		for i := range c.items {
			w.PutString(tlv.Anonymous, fmt.Sprintf("%03d-%097d", i, 0))
		}
		w.EndContainer()
	case 1:
		return ctx.ClusterStatus(17)
	case 2:
		w.StartArray(tag)
		w.PutUint(tlv.Anonymous, 7)
		w.EndContainer()
	default:
		return im.UnsupportedAttribute
	}
	return im.Success
}

func (c *listCluster) WriteAttribute(ctx *im.Context, attr uint32, appendItem bool, r *tlv.Reader) im.Status {
	if attr == 1 {
		return ctx.ClusterStatus(18)
	}
	return im.UnsupportedWrite
}

// TestReadListChunked reads a list attribute larger than a message: the
// first report holds the items that fit, the rest come as list appends,
// in order, and the attributes around it are reported whole.
func TestReadListChunked(t *testing.T) {
	f := newFixture(t)
	c := &listCluster{items: 40} // ~4 kB
	f.node.AddCluster(f.node.Endpoint(2), c)
	reps := f.read(path(2, listClusterID, 2), path(2, listClusterID, 0), path(2, listClusterID, 2))
	if len(reps) < 4 {
		t.Fatalf("%d reports", len(reps))
	}
	if reps[0].Path.Attribute != 2 || reps[len(reps)-1].Path.Attribute != 2 {
		t.Fatal("the small lists around the large one are missing")
	}
	var got []string
	for i, rep := range reps[1 : len(reps)-1] {
		if rep.Status != im.Success || rep.Path.Attribute != 0 || rep.Path.ListAppend != (i > 0) {
			t.Fatalf("report %d: %+v", i, rep)
		}
		r := value(t, rep.Data)
		if i == 0 {
			r.EnterContainer()
			for r.Next() == nil {
				s, _ := r.String()
				got = append(got, s)
			}
			continue
		}
		s, err := r.String()
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		got = append(got, s)
	}
	if len(got) != c.items {
		t.Fatalf("%d items, want %d", len(got), c.items)
	}
	for i, s := range got {
		if s[:4] != fmt.Sprintf("%03d-", i) {
			t.Fatalf("item %d is %q", i, s[:4])
		}
	}
	if len(reps[1].Data) < 1000 {
		t.Error("the first report should carry the items that fit")
	}
}

func TestAttributeClusterStatus(t *testing.T) {
	f := newFixture(t)
	f.node.AddCluster(f.node.Endpoint(2), &listCluster{})
	reps := f.read(path(2, listClusterID, 1))
	if len(reps) != 1 || reps[0].Status != im.Failure || !reps[0].HasClusterStatus || reps[0].ClusterStatus != 17 {
		t.Fatalf("read: %+v", reps)
	}
	msgs := f.request(im.OpWriteRequest, im.EncodeWriteRequest(path(2, listClusterID, 1), false,
		func(w *tlv.Writer, tag tlv.Tag) { w.PutBool(tag, true) }))
	ws, err := im.DecodeWriteResponse(msgs[0].Payload)
	if err != nil || len(ws) != 1 || ws[0].Status != im.Failure || !ws[0].HasClusterStatus || ws[0].ClusterStatus != 18 {
		t.Fatalf("write: %+v %v", ws, err)
	}
	// The status does not leak into the next attribute's report.
	reps = f.read(path(2, listClusterID, 1), path(2, listClusterID, 0x99))
	if len(reps) != 2 || reps[1].HasClusterStatus {
		t.Fatalf("read: %+v", reps)
	}
}
