package main

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/internal/datamodel"
	"github.com/shabunin/tiny-matter-go/tlv"
)

// groupArg resolves a group by ID or name.
func groupArg(c *controller.Controller, s string) (uint16, error) {
	if id, err := strconv.ParseUint(s, 0, 16); err == nil {
		return uint16(id), nil
	}
	var found []uint16
	for _, g := range c.Groups() {
		if g.Name == s {
			found = append(found, g.ID)
		}
	}
	switch len(found) {
	case 0:
		return 0, fmt.Errorf("no group named %q", s)
	case 1:
		return found[0], nil
	}
	return 0, fmt.Errorf("%d groups named %q", len(found), s)
}

func cmdGroups(args []string) error {
	if len(args) != 0 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	groups := c.Groups()
	if len(groups) == 0 {
		fmt.Println("no groups")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tNAME\tKEY SET")
	for _, g := range groups {
		fmt.Fprintf(tw, "0x%04X\t%s\t0x%04X\n", g.ID, g.Name, g.KeySetID)
	}
	return tw.Flush()
}

func cmdGroupAdd(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return usageError{}
	}
	id, err := strconv.ParseUint(args[0], 0, 16)
	if err != nil {
		return fmt.Errorf("group %q: want a number", args[0])
	}
	name := ""
	if len(args) == 2 {
		name = args[1]
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.AddGroup(uint16(id), name)
	return err
}

func cmdGroupDelete(args []string) error {
	if len(args) != 1 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	id, err := groupArg(c, args[0])
	if err != nil {
		return err
	}
	return c.DeleteGroup(id)
}

// groupMember runs JoinGroup or LeaveGroup with <node> <endpoint> <group>.
func groupMember(args []string, join bool) error {
	if len(args) != 3 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	node, err := nodeArg(c, args[0])
	if err != nil {
		return err
	}
	ep, anyEP, err := endpointArg(args[1])
	if err != nil || anyEP {
		return fmt.Errorf("endpoint %q: want a number", args[1])
	}
	group, err := groupArg(c, args[2])
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	if join {
		err = c.JoinGroup(ctx, node, ep, group)
	} else {
		err = c.LeaveGroup(ctx, node, ep, group)
	}
	return describe(err)
}

func cmdGroupJoin(args []string) error  { return groupMember(args, true) }
func cmdGroupLeave(args []string) error { return groupMember(args, false) }

func cmdGroupInvoke(args []string) error {
	if len(args) < 3 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	group, err := groupArg(c, args[0])
	if err != nil {
		return err
	}
	cluster, cl, anyCl, err := clusterArg(args[1])
	if err != nil {
		return err
	}
	if anyCl {
		return fmt.Errorf("a group command names its cluster")
	}
	var cmd *datamodel.Command
	id, err := memberID("command", args[2], cl, func(s string) (uint32, bool) {
		if cmd = cl.Command(s); cmd != nil {
			return cmd.ID, true
		}
		return 0, false
	})
	if err != nil {
		return err
	}
	if cmd != nil && cmd.Timed {
		return fmt.Errorf("%s needs a timed invoke, which groups cannot do", cmd.Name)
	}
	var req *datamodel.Type
	if cmd != nil {
		req = cmd.Request
	}
	w := tlv.NewWriter(nil)
	if err := datamodel.EncodeFields(w, req, args[3:]); err != nil {
		return err
	}
	fields := w.Bytes()
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	return c.GroupInvoke(ctx, group, cluster, id, func(w *tlv.Writer) { w.PutRaw(fields) })
}
