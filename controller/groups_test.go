package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

func TestGroups(t *testing.T) {
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
	c.SetGroupDestination(d.addr())

	if err := c.JoinGroup(ctx, n.ID, 1, 7); err != controller.ErrUnknownGroup {
		t.Fatalf("joining an unknown group: %v", err)
	}
	if _, err := c.AddGroup(0, ""); err == nil {
		t.Fatal("created group 0")
	}
	if _, err := c.AddGroup(7, "lights"); err != nil {
		t.Fatal(err)
	}
	// Joining twice adds no second key mapping or ACL entry.
	for i := 0; i < 2; i++ {
		if err := c.JoinGroup(ctx, n.ID, 1, 7); err != nil {
			t.Fatal(err)
		}
	}
	var acl, maps int
	d.do(func() {
		acl, maps = len(d.dev.ACL.Entries), len(d.dev.Groups.KeyMap)
	})
	if acl != 2 || maps != 1 {
		t.Fatalf("%d ACL entries, %d key mappings after joining twice", acl, maps)
	}

	on := func() bool {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		return readOnOff(t, ctx, c, n.ID)
	}
	if err := c.GroupInvoke(ctx, 7, 0x0006, 0x01, nil); err != nil {
		t.Fatal(err)
	}
	if !on() {
		t.Fatal("group On not applied")
	}

	// A new controller on the same state continues the counter.
	c.Close()
	c = openController(t, dir)
	defer c.Close()
	c.SetGroupDestination(d.addr())
	if err := c.GroupInvoke(ctx, 7, 0x0006, 0x00, nil); err != nil {
		t.Fatal(err)
	}
	if on() {
		t.Fatal("group Off from a reopened controller not applied")
	}

	// Binding to a group gives the node the group's key, not membership,
	// and keeps the node targets.
	if _, err := c.AddGroup(8, "kitchen"); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(ctx, n.ID, 1, n.ID, 1, 0x0006); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := c.BindGroup(ctx, n.ID, 1, 8, 0x0006); err != nil {
			t.Fatal(err)
		}
	}
	d.do(func() {
		acl, maps = len(d.dev.ACL.Entries), len(d.dev.Groups.KeyMap)
	})
	if acl != 3 || maps != 2 { // admin, group 7, the node's own binding entry
		t.Fatalf("%d ACL entries, %d key mappings after binding to a group", acl, maps)
	}
	bs, err := c.Bindings(ctx, n.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs[0].Node != n.ID || bs[0].Group != 0 || bs[1].Group != 8 || bs[1].Cluster != 0x0006 {
		t.Fatalf("bindings %+v", bs)
	}
	if err := c.UnbindGroup(ctx, n.ID, 1, 8, 0); err != nil {
		t.Fatal(err)
	}
	if bs, err = c.Bindings(ctx, n.ID, 1); err != nil || len(bs) != 1 || bs[0].Group != 0 {
		t.Fatalf("bindings after UnbindGroup %+v %v", bs, err)
	}
	if err := c.DeleteGroup(8); err != nil {
		t.Fatal(err)
	}

	if err := c.LeaveGroup(ctx, n.ID, 1, 7); err != nil {
		t.Fatal(err)
	}
	c.GroupInvoke(ctx, 7, 0x0006, 0x01, nil)
	if on() {
		t.Fatal("group On applied after LeaveGroup")
	}
	if err := c.DeleteGroup(7); err != nil || len(c.Groups()) != 0 {
		t.Fatalf("DeleteGroup: %v, %d groups left", err, len(c.Groups()))
	}
}
