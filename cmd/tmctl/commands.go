package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	fs := flagSet("discover")
	ble := fs.Bool("ble", false, "look over Bluetooth LE too")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) > 1 {
		return usageError{}
	}
	wait := 3 * time.Second
	if *ble {
		wait = 10 * time.Second
	}
	if len(pos) == 1 {
		s, err := strconv.ParseFloat(pos[0], 64)
		if err != nil {
			return usageError{}
		}
		wait = time.Duration(s * float64(time.Second))
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := withTimeout(wait)
	defer cancel()
	var bleFound []controller.BLECommissionable
	bleErr := make(chan error, 1)
	if *ble {
		go func() {
			bleErr <- c.DiscoverBLE(ctx, func(d controller.BLECommissionable) { bleFound = append(bleFound, d) })
		}()
	}
	found, err := c.Discover(ctx)
	if err != nil {
		return err
	}
	if *ble {
		if err := <-bleErr; err != nil {
			return err
		}
		if len(bleFound) > 0 {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "BLE ADDRESS\tDISCRIMINATOR\tVENDOR\tPRODUCT\tNAME")
			for _, d := range bleFound {
				fmt.Fprintf(tw, "%s\t%d\t0x%04X\t0x%04X\t%s\n", d.Address, d.Discriminator, d.VendorID, d.ProductID, d.Name)
			}
			tw.Flush()
			if len(found) > 0 {
				fmt.Println()
			}
		}
	}
	if len(found) == 0 {
		if len(bleFound) == 0 {
			fmt.Println("no devices in commissioning mode")
		}
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

// reachFlags are the flags that say how to reach a device in
// commissioning mode, and the network to give it.
type reachFlags struct {
	ble              *bool
	ssid, password   *string
	thread           *bool
	dataset          *string
	withNetworkFlags bool
}

func addReachFlags(fs *flag.FlagSet, network bool) *reachFlags {
	f := &reachFlags{ble: fs.Bool("ble", false, "reach the device over Bluetooth LE only"), withNetworkFlags: network}
	if network {
		f.ssid = fs.String("ssid", "", "Wi-Fi network to give a device commissioned over BLE")
		f.password = fs.String("password", "", "the Wi-Fi password (default $TMCTL_WIFI_PASSWORD)")
		f.thread = fs.Bool("thread", false, "give a device commissioned over BLE the Thread network of -dataset")
		f.dataset = fs.String("dataset", "", "the Thread operational dataset, in hex as `ot-ctl dataset active -x` prints it (default $TMCTL_THREAD_DATASET)")
	}
	return f
}

// options turns the flags and the optional address argument into
// commissioning options.
func (f *reachFlags) options(pos []string) (controller.CommissionOptions, error) {
	opts := controller.CommissionOptions{BLE: *f.ble}
	if len(pos) > 0 {
		var err error
		if opts.Addr, err = addrArg(pos[0]); err != nil {
			return opts, err
		}
	}
	if !f.withNetworkFlags {
		return opts, nil
	}
	switch {
	case *f.ssid != "" && *f.thread:
		return opts, errors.New("-ssid or -thread, not both")
	case *f.ssid != "":
		pw := *f.password
		if pw == "" {
			pw = os.Getenv("TMCTL_WIFI_PASSWORD")
		}
		opts.WiFi = &controller.WiFiNetwork{SSID: []byte(*f.ssid), Password: []byte(pw)}
	case *f.password != "":
		return opts, errors.New("-password without -ssid")
	case *f.thread:
		ds := *f.dataset
		if ds == "" {
			ds = os.Getenv("TMCTL_THREAD_DATASET")
		}
		if ds == "" {
			return opts, errors.New("-thread needs -dataset or $TMCTL_THREAD_DATASET")
		}
		b, err := hex.DecodeString(strings.TrimSpace(ds))
		if err != nil {
			return opts, fmt.Errorf("Thread dataset: %v", err)
		}
		opts.Thread = b
	case *f.dataset != "":
		return opts, errors.New("-dataset without -thread")
	}
	if (opts.WiFi != nil || opts.Thread != nil) && opts.Addr.IsValid() && !opts.BLE {
		return opts, errors.New("a network is given to a device commissioned over BLE: drop the address, or add -ble to reach the device there once it has joined")
	}
	return opts, nil
}

func cmdCommission(args []string) error {
	fs := flagSet("commission")
	id := fs.Uint64("id", 0, "node ID to give the device")
	label := fs.String("label", "", "label for the node")
	skip := fs.Bool("skip-attestation", false, "commission even if device attestation fails")
	rf := addReachFlags(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 1 || len(pos) > 2 {
		return usageError{}
	}
	p, err := onboarding.Parse(pos[0])
	if err != nil {
		return err
	}
	opts, err := rf.options(pos[1:])
	if err != nil {
		return err
	}
	opts.NodeID, opts.Label, opts.SkipAttestation = *id, *label, *skip
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

func cmdScan(args []string) error {
	fs := flagSet("scan")
	rf := addReachFlags(fs, false)
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) < 1 || len(pos) > 2 {
		return usageError{}
	}
	p, err := onboarding.Parse(pos[0])
	if err != nil {
		return err
	}
	opts, err := rf.options(pos[1:])
	if err != nil {
		return err
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := withTimeout(max(*timeout, 2*time.Minute))
	defer cancel()
	scan, err := c.ScanNetworks(ctx, p, opts)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	switch {
	case scan.Interface == "Thread" && len(scan.Thread) > 0:
		fmt.Fprintln(tw, "NETWORK\tEXTENDED PAN ID\tPAN ID\tCHANNEL\tRSSI\tLQI")
		for _, n := range scan.Thread {
			fmt.Fprintf(tw, "%s\t%016X\t0x%04X\t%d\t%d\t%d\n", n.NetworkName, n.ExtendedPANID, n.PANID, n.Channel, n.RSSI, n.LQI)
		}
	case len(scan.WiFi) > 0:
		fmt.Fprintln(tw, "SSID\tSECURITY\tCHANNEL\tBAND\tRSSI")
		for _, n := range scan.WiFi {
			ch := "?"
			if n.Channel != 0 {
				ch = fmt.Sprint(n.Channel)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", n.SSID, wifiSecurity(n.Security), ch, wifiBand(n.Band), n.RSSI)
		}
	default:
		fmt.Printf("the device sees no %s networks\n", scan.Interface)
	}
	return nil
}

func wifiSecurity(s uint8) string {
	var names []string
	for i, n := range []string{"open", "WEP", "WPA", "WPA2", "WPA3"} {
		if s&(1<<i) != 0 {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "?"
	}
	return strings.Join(names, "/")
}

func wifiBand(b uint8) string {
	if int(b) < len(wifiBands) {
		return wifiBands[b]
	}
	return fmt.Sprint(b)
}

var wifiBands = []string{"2.4 GHz", "3.65 GHz", "5 GHz", "6 GHz", "60 GHz", "1 GHz"}

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
