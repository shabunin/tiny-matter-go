package main

import (
	"fmt"
)

// bind <node> <endpoint> <target> <target-endpoint> <cluster>
func cmdBind(args []string) error   { return bindCmd(args, true) }
func cmdUnbind(args []string) error { return bindCmd(args, false) }

func bindCmd(args []string, bind bool) error {
	if len(args) != 5 {
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
	target, err := nodeArg(c, args[2])
	if err != nil {
		return err
	}
	targetEP, anyEP, err := endpointArg(args[3])
	if err != nil || anyEP {
		return fmt.Errorf("endpoint %q: want a number", args[3])
	}
	cluster, _, anyCl, err := clusterArg(args[4])
	if err != nil {
		return err
	}
	if anyCl {
		return fmt.Errorf("a binding names its cluster")
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	if bind {
		err = c.Bind(ctx, node, ep, target, targetEP, cluster)
	} else {
		err = c.Unbind(ctx, node, ep, target, targetEP, cluster)
	}
	return describe(err)
}

// bindings <node> <endpoint>
func cmdBindings(args []string) error {
	if len(args) != 2 {
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
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	bs, err := c.Bindings(ctx, node, ep)
	if err != nil {
		return describe(err)
	}
	if len(bs) == 0 {
		fmt.Println("no bindings")
	}
	for _, b := range bs {
		cl := "any cluster"
		if b.HasCluster {
			cl = fmt.Sprintf("cluster %#06x", b.Cluster)
		}
		if b.Group != 0 {
			fmt.Printf("group %#x, %s\n", b.Group, cl)
			continue
		}
		fmt.Printf("node %d endpoint %d, %s\n", b.Node, b.Endpoint, cl)
	}
	return nil
}

// group-bind <node> <endpoint> <group> <cluster>
func cmdGroupBind(args []string) error   { return groupBindCmd(args, true) }
func cmdGroupUnbind(args []string) error { return groupBindCmd(args, false) }

func groupBindCmd(args []string, bind bool) error {
	if len(args) != 4 {
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
	cluster, _, anyCl, err := clusterArg(args[3])
	if err != nil {
		return err
	}
	if anyCl {
		return fmt.Errorf("a binding names its cluster")
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	if bind {
		err = c.BindGroup(ctx, node, ep, group, cluster)
	} else {
		err = c.UnbindGroup(ctx, node, ep, group, cluster)
	}
	return describe(err)
}
