package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

func TestUpdateNOC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := startDevice(t)
	dir := t.TempDir()
	c := openController(t, dir)
	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}

	// The same node ID with a new key, then a new node ID.
	if _, err := c.UpdateNOC(ctx, n.ID, 0); err != nil {
		t.Fatal(err)
	}
	readOnOff(t, ctx, c, n.ID)
	m, err := c.UpdateNOC(ctx, n.ID, 77)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 77 || m.Label != n.Label {
		t.Fatalf("node after UpdateNOC: %+v", m)
	}
	if _, ok := c.Node(n.ID); ok {
		t.Fatal("old node ID still known")
	}
	var nodeID uint64
	var updating bool
	d.do(func() {
		f := d.dev.Fabrics.Fabrics()[0]
		nodeID, updating = f.NodeID, f.Updating()
	})
	if nodeID != 77 || updating {
		t.Fatalf("device fabric node %d, updating %v", nodeID, updating)
	}
	readOnOff(t, ctx, c, 77)

	// The new ID is saved.
	c.Close()
	c = openController(t, dir)
	defer c.Close()
	readOnOff(t, ctx, c, 77)
}
