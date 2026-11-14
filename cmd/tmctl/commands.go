package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/internal/datamodel"
	"github.com/shabunin/tiny-matter-go/onboarding"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func cmdInfo(args []string) error {
	if len(args) != 0 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Printf("state:                %s\n", *stateDir)
	fmt.Printf("fabric ID:            %016X\n", c.FabricID())
	fmt.Printf("compressed fabric ID: %X\n", c.CompressedFabricID())
	fmt.Printf("administrator CAT:    %08X (ACL subject %016X)\n", c.AdminCAT(), 0xFFFFFFFD_00000000|uint64(c.AdminCAT()))
	fmt.Printf("node ID (this run):   %016X\n", c.NodeID())
	fmt.Printf("nodes:                %d\n", len(c.Nodes()))
	return nil
}

func cmdDiscover(args []string) error {
	wait := 3 * time.Second
	switch len(args) {
	case 0:
	case 1:
		s, err := strconv.ParseFloat(args[0], 64)
		if err != nil {
			return usageError{}
		}
		wait = time.Duration(s * float64(time.Second))
	default:
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := withTimeout(wait)
	defer cancel()
	found, err := c.Discover(ctx)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		fmt.Println("no devices in commissioning mode")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INSTANCE\tDISCRIMINATOR\tVENDOR\tPRODUCT\tMODE\tNAME\tADDRESSES")
	for _, d := range found {
		var addrs []string
		for _, a := range d.Addrs {
			addrs = append(addrs, netip.AddrPortFrom(a, d.Port).String())
		}
		fmt.Fprintf(tw, "%s\t%d\t0x%04X\t0x%04X\t%d\t%s\t%v\n", d.Name, d.Discriminator, d.VendorID, d.ProductID,
			d.Mode, d.DeviceName, addrs)
	}
	return tw.Flush()
}

func cmdCommission(args []string) error {
	fs := flagSet("commission")
	id := fs.Uint64("id", 0, "node ID to give the device")
	label := fs.String("label", "", "label for the node")
	skip := fs.Bool("skip-attestation", false, "commission even if device attestation fails")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 1 || len(pos) > 2 {
		return usageError{}
	}
	p, err := onboarding.Parse(pos[0])
	if err != nil {
		return err
	}
	opts := controller.CommissionOptions{NodeID: *id, Label: *label, SkipAttestation: *skip}
	if len(pos) == 2 {
		if opts.Addr, err = addrArg(pos[1]); err != nil {
			return err
		}
	}
	c, err := open(true)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := withTimeout(max(*timeout, 3*time.Minute))
	defer cancel()
	n, err := c.Commission(ctx, p, opts)
	if err != nil {
		return err
	}
	fmt.Printf("commissioned node %d (%s)\n", n.ID, n.Label)
	return nil
}

// addrArg parses host:port, or an address with the default port 5540.
func addrArg(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a, 5540), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, "5540"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("address %q: %v", s, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q: bad port", s)
	}
	a, _ := netip.AddrFromSlice(ips[0])
	return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
}

func cmdNodes(args []string) error {
	if len(args) != 0 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	nodes := c.Nodes()
	if len(nodes) == 0 {
		fmt.Println("no nodes")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tLABEL\tVENDOR\tPRODUCT\tADDRESS\tADDED")
	for _, n := range nodes {
		fmt.Fprintf(tw, "%d\t%s\t0x%04X\t0x%04X\t%s\t%s\n", n.ID, n.Label, n.VendorID, n.ProductID, n.Addr,
			n.Added.Local().Format("2006-01-02 15:04"))
	}
	return tw.Flush()
}

func cmdLabel(args []string) error {
	if len(args) != 2 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	id, err := nodeArg(c, args[0])
	if err != nil {
		return err
	}
	return c.SetLabel(id, args[1])
}

// target is the node, endpoint and cluster arguments most commands start
// with.
type target struct {
	node    uint64
	ep      uint16
	anyEP   bool
	cluster uint32
	cl      *datamodel.Cluster
	anyCl   bool
}

func targetArgs(c *controller.Controller, pos []string, wildcards bool) (t target, err error) {
	if t.node, err = nodeArg(c, pos[0]); err != nil {
		return t, err
	}
	if t.ep, t.anyEP, err = endpointArg(pos[1]); err != nil {
		return t, err
	}
	if t.cluster, t.cl, t.anyCl, err = clusterArg(pos[2]); err != nil {
		return t, err
	}
	if !wildcards && (t.anyEP || t.anyCl) {
		return t, fmt.Errorf("wildcards are only for reads and subscriptions")
	}
	return t, nil
}

func attributeID(cl *datamodel.Cluster, s string) (uint32, error) {
	return memberID("attribute", s, cl, func(s string) (uint32, bool) {
		if a := cl.Attribute(s); a != nil {
			return a.ID, true
		}
		return 0, false
	})
}

func attributePaths(t target, names []string) ([]im.AttributePath, error) {
	if len(names) == 0 {
		names = []string{"*"}
	}
	var paths []im.AttributePath
	for _, s := range names {
		p := im.AttributePath{Endpoint: t.ep, AnyEndpoint: t.anyEP, Cluster: t.cluster, AnyCluster: t.anyCl}
		if s == "*" {
			p.AnyAttribute = true
		} else {
			id, err := attributeID(t.cl, s)
			if err != nil {
				return nil, err
			}
			p.Attribute = id
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func eventPaths(t target, names []string) ([]im.EventPath, error) {
	if len(names) == 0 {
		names = []string{"*"}
	}
	var paths []im.EventPath
	for _, s := range names {
		p := im.EventPath{Endpoint: t.ep, AnyEndpoint: t.anyEP, Cluster: t.cluster, AnyCluster: t.anyCl}
		if s == "*" {
			p.AnyEvent = true
		} else {
			id, err := memberID("event", s, t.cl, func(s string) (uint32, bool) {
				if e := t.cl.Event(s); e != nil {
					return e.ID, true
				}
				return 0, false
			})
			if err != nil {
				return nil, err
			}
			p.Event = id
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func cmdRead(args []string) error {
	fs := flagSet("read")
	all := fs.Bool("all-fabrics", false, "read fabric-scoped lists unfiltered")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 3 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	t, err := targetArgs(c, pos, true)
	if err != nil {
		return err
	}
	paths, err := attributePaths(t, pos[3:])
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	rep, err := c.Read(ctx, t.node, im.Request{Attributes: paths, FabricFiltered: !*all})
	if err != nil {
		return err
	}
	for _, line := range attributeLines(rep.Attributes) {
		fmt.Println(line)
	}
	return nil
}

func cmdWrite(args []string) error {
	fs := flagSet("write")
	timed := fs.Uint("timed", 0, "timed write window in `ms`")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 5 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	t, err := targetArgs(c, pos, false)
	if err != nil {
		return err
	}
	id, err := attributeID(t.cl, pos[3])
	if err != nil {
		return err
	}
	var f *datamodel.Field
	if t.cl != nil {
		if a := t.cl.AttributeByID(id); a != nil {
			f = &a.Field
		}
	}
	value := pos[4]
	if err := datamodel.Encode(tlv.NewWriter(nil), tlv.Anonymous, f, value); err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	err = c.Write(ctx, t.node, im.AttributePath{Endpoint: t.ep, Cluster: t.cluster, Attribute: id}, uint16(*timed),
		func(w *tlv.Writer, tag tlv.Tag) { datamodel.Encode(w, tag, f, value) })
	if err != nil {
		return describe(err)
	}
	fmt.Println("OK")
	return nil
}

func cmdInvoke(args []string) error {
	fs := flagSet("invoke")
	timed := fs.Int("timed", -1, "timed invoke window in `ms` (default: 5000 if the command requires one)")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 4 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	t, err := targetArgs(c, pos, false)
	if err != nil {
		return err
	}
	var cmd *datamodel.Command
	id, err := memberID("command", pos[3], t.cl, func(s string) (uint32, bool) {
		if cmd = t.cl.Command(s); cmd != nil {
			return cmd.ID, true
		}
		return 0, false
	})
	if err != nil {
		return err
	}
	var req *datamodel.Type
	if cmd != nil {
		req = cmd.Request
	}
	w := tlv.NewWriter(nil)
	if err := datamodel.EncodeFields(w, req, pos[4:]); err != nil {
		return err
	}
	fields := w.Bytes()
	window := uint16(0)
	switch {
	case *timed >= 0:
		window = uint16(*timed)
	case cmd != nil && cmd.Timed:
		window = 5000
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	res, err := c.Invoke(ctx, t.node, im.CommandPath{Endpoint: t.ep, Cluster: t.cluster, Command: id}, window,
		func(w *tlv.Writer) { w.PutRaw(fields) })
	if err != nil {
		return describe(err)
	}
	if res.Fields == nil {
		fmt.Println("OK")
		return nil
	}
	name := fmt.Sprintf("command %#x", res.Path.Command)
	var rf []*datamodel.Field
	if t.cl != nil {
		if r := t.cl.Response(res.Path.Command); r != nil {
			name, rf = r.Response.Name, r.Response.Fields
		}
	}
	fmt.Printf("%s %s\n", name, datamodel.FormatFields(res.Fields, rf))
	return nil
}

func cmdEvents(args []string) error {
	fs := flagSet("events")
	since := fs.Uint64("since", 0, "read events numbered from `n` on")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 3 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	t, err := targetArgs(c, pos, true)
	if err != nil {
		return err
	}
	paths, err := eventPaths(t, pos[3:])
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	rep, err := c.Read(ctx, t.node, im.Request{Events: paths, EventMin: *since, FabricFiltered: true})
	if err != nil {
		return err
	}
	for _, line := range eventLines(rep.Events) {
		fmt.Println(line)
	}
	return nil
}

func cmdSubscribe(args []string) error {
	fs := flagSet("subscribe")
	events := fs.Bool("events", false, "also subscribe to the events of the endpoint and cluster")
	urgent := fs.Bool("urgent", false, "with -events: report events at once, not with the next report")
	minI := fs.Uint("min", 0, "minimum reporting interval in `seconds`")
	maxI := fs.Uint("max", 60, "maximum reporting interval in `seconds`")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 3 || *minI > *maxI || *maxI > 0xFFFF {
		return usageError{}
	}
	c, err := open(*verbose)
	if err != nil {
		return err
	}
	defer c.Close()
	t, err := targetArgs(c, pos, true)
	if err != nil {
		return err
	}
	q := im.Request{FabricFiltered: true}
	if q.Attributes, err = attributePaths(t, pos[3:]); err != nil {
		return err
	}
	if *events {
		q.Events, _ = eventPaths(t, nil)
		for i := range q.Events {
			q.Events[i].IsUrgent = *urgent
		}
	}
	stop, cancelStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelStop()
	ctx, cancel := context.WithTimeout(stop, *timeout)
	defer cancel()
	stamp := func() string { return time.Now().Format("15:04:05.000") }
	sub, err := c.Subscribe(ctx, t.node, q, controller.SubscribeOptions{
		MinInterval: uint16(*minI), MaxInterval: uint16(*maxI),
		OnReport: func(rd *im.ReportData) {
			for _, line := range attributeLines(rd.Reports) {
				fmt.Println(stamp(), line)
			}
			for _, line := range eventLines(rd.Events) {
				fmt.Println(stamp(), "event", line)
			}
		},
		OnStatus: func(err error) {
			if err != nil {
				fmt.Println(stamp(), "lost:", err)
			} else {
				fmt.Println(stamp(), "subscribed again")
			}
		},
	})
	if err != nil {
		return err
	}
	<-stop.Done()
	sub.Close()
	return nil
}

func cmdOpenWindow(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return usageError{}
	}
	minutes := 10.0
	if len(args) == 2 {
		var err error
		if minutes, err = strconv.ParseFloat(args[1], 64); err != nil {
			return usageError{}
		}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	id, err := nodeArg(c, args[0])
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	w, err := c.OpenWindow(ctx, id, time.Duration(minutes*float64(time.Minute)))
	if err != nil {
		return describe(err)
	}
	manual, _ := w.Payload.ManualCode()
	qr, _ := w.Payload.QRCode()
	fmt.Printf("manual code:   %s\n", manual)
	fmt.Printf("QR code:       %s\n", qr)
	fmt.Printf("discriminator: %d\n", w.Payload.Discriminator)
	fmt.Printf("open until:    %s\n", w.Deadline.Local().Format("15:04:05"))
	return nil
}

func cmdCloseWindow(args []string) error {
	return withNode(args, func(ctx context.Context, c *controller.Controller, id uint64) error {
		return describe(c.CloseWindow(ctx, id))
	})
}

func cmdRemove(args []string) error {
	return withNode(args, func(ctx context.Context, c *controller.Controller, id uint64) error {
		if err := c.RemoveNode(ctx, id); err != nil {
			return describe(err)
		}
		fmt.Printf("node %d removed\n", id)
		return nil
	})
}

func cmdForget(args []string) error {
	return withNode(args, func(ctx context.Context, c *controller.Controller, id uint64) error {
		return c.ForgetNode(id)
	})
}

func withNode(args []string, f func(ctx context.Context, c *controller.Controller, id uint64) error) error {
	if len(args) != 1 {
		return usageError{}
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	id, err := nodeArg(c, args[0])
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	return f(ctx, c, id)
}

func cmdPayload(args []string) error {
	if len(args) != 1 {
		return usageError{}
	}
	p, err := onboarding.Parse(args[0])
	if err != nil {
		return err
	}
	if p.ShortOnly {
		fmt.Printf("discriminator: %d (short: upper 4 bits only)\n", p.ShortDiscriminator())
	} else {
		fmt.Printf("discriminator: %d\n", p.Discriminator)
	}
	fmt.Printf("passcode:      %08d\n", p.Passcode)
	if p.VendorID != 0 || p.ProductID != 0 {
		fmt.Printf("vendor:        0x%04X\nproduct:       0x%04X\n", p.VendorID, p.ProductID)
	}
	fmt.Printf("flow:          %d\n", p.Flow)
	if p.Discovery != 0 {
		fmt.Printf("discovery:     %#x\n", p.Discovery)
	}
	if manual, err := p.ManualCode(); err == nil {
		fmt.Printf("manual code:   %s\n", manual)
	}
	return nil
}

func cmdClusters(args []string) error {
	switch len(args) {
	case 0:
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, c := range model().Clusters {
			fmt.Fprintf(tw, "0x%04X\t%s\n", c.ID, c.Name)
		}
		return tw.Flush()
	case 1:
	default:
		return usageError{}
	}
	c := model().Cluster(args[0])
	if c == nil {
		return fmt.Errorf("unknown cluster %q", args[0])
	}
	fmt.Printf("%s (0x%04X), revision %d\n", c.Name, c.ID, c.Revision)
	if c.Doc != "" {
		fmt.Printf("  %s\n", c.Doc)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nattributes:")
	for _, a := range c.Attributes {
		rw := "read-only"
		if a.Writable {
			rw = "writable"
		}
		fmt.Fprintf(tw, "  0x%04X\t%s\t%s\t%s\n", a.ID, a.Name, a.TypeString(), rw)
	}
	if len(c.Commands) > 0 {
		fmt.Fprintln(tw, "\ncommands:")
		for _, cmd := range c.Commands {
			args := ""
			if cmd.Request != nil {
				for i, f := range cmd.Request.Fields {
					if i > 0 {
						args += ", "
					}
					args += f.Name + " " + f.TypeString()
				}
			}
			extra := ""
			if cmd.Response != nil {
				extra = " -> " + cmd.Response.Name
			}
			if cmd.Timed {
				extra += " (timed)"
			}
			fmt.Fprintf(tw, "  0x%02X\t%s(%s)%s\n", cmd.ID, cmd.Name, args, extra)
		}
	}
	if len(c.Events) > 0 {
		fmt.Fprintln(tw, "\nevents:")
		for _, e := range c.Events {
			var fields string
			for i, f := range e.Fields {
				if i > 0 {
					fields += ", "
				}
				fields += f.Name + " " + f.TypeString()
			}
			fmt.Fprintf(tw, "  0x%02X\t%s\t%s\t{%s}\n", e.ID, e.Name, e.Priority, fields)
		}
	}
	return tw.Flush()
}
