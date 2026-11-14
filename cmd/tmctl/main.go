// Command tmctl is a Matter controller for the command line. It keeps its
// own fabric, commissions devices onto it over the IP network, and reads,
// writes, invokes and subscribes on them.
//
//	tmctl discover
//	tmctl commission 34970112332
//	tmctl invoke 1 1 OnOff Toggle
//	tmctl read 1 1 OnOff
//	tmctl subscribe 1 '*' '*' -events
//
// Clusters, attributes, commands and events are named as in the Matter
// SDK's IDL (case does not matter) or numbered; tmctl clusters lists them.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/credentials/attestation"
	"github.com/shabunin/tiny-matter-go/internal/datamodel"
)

var (
	stateDir = flag.String("dir", defaultDir(), "controller state `directory` (fabric keys and nodes)")
	paaDir   = flag.String("paa", "", "`directory` of trusted production PAA certificates (default <dir>/paa)")
	strict   = flag.Bool("strict", false, "trust production PAAs and certification declarations only, not test ones")
	verbose  = flag.Bool("v", false, "log progress")
	timeout  = flag.Duration("timeout", 30*time.Second, "time limit for an operation")
)

type command struct {
	name, args, help string
	run              func(args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"info", "", "show the controller's fabric", cmdInfo},
		{"discover", "[seconds]", "list devices in commissioning mode", cmdDiscover},
		{"commission", "<code> [address] [-id n] [-label text] [-skip-attestation]",
			"commission a device by its QR or manual pairing code", cmdCommission},
		{"nodes", "", "list commissioned nodes", cmdNodes},
		{"label", "<node> <label>", "name a node", cmdLabel},
		{"read", "<node> <endpoint|*> <cluster|*> [attribute|*]... [-all-fabrics]", "read attributes", cmdRead},
		{"write", "<node> <endpoint> <cluster> <attribute> <value> [-timed ms]", "write an attribute", cmdWrite},
		{"invoke", "<node> <endpoint> <cluster> <command> [field=value|value]... [-timed ms]", "invoke a command", cmdInvoke},
		{"events", "<node> <endpoint|*> <cluster|*> [event|*]... [-since n]", "read events", cmdEvents},
		{"subscribe", "<node> <endpoint|*> <cluster|*> [attribute|*]... [-events [-urgent]] [-min s] [-max s]",
			"print reports until interrupted", cmdSubscribe},
		{"open-window", "<node> [minutes]", "open a commissioning window for another administrator", cmdOpenWindow},
		{"close-window", "<node>", "close an open commissioning window", cmdCloseWindow},
		{"remove", "<node>", "remove the controller's fabric from a node, and forget it", cmdRemove},
		{"forget", "<node>", "forget a node without telling it", cmdForget},
		{"clusters", "[cluster]", "list known clusters, or a cluster's attributes, commands and events", cmdClusters},
		{"payload", "<code>", "decode a QR or manual pairing code", cmdPayload},
	}
}

func defaultDir() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "tmctl"
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "tiny-matter-go", "controller")
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, "usage: tmctl [flags] <command> [arguments]\n\ncommands:\n")
	for _, c := range commands {
		fmt.Fprintf(w, "  %s\n    \t%s\n", strings.TrimSpace(c.name+" "+c.args), c.help)
	}
	fmt.Fprintf(w, "\nNodes are numbers or labels. Values are numbers, true/false, text, enum\n"+
		"and bitmap names (A|B), hex for octet strings, null, or JSON for lists and\n"+
		"structs. Command flags may come anywhere; nothing after -- is a flag.\n\nflags:\n")
	flag.PrintDefaults()
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	name := flag.Arg(0)
	for _, c := range commands {
		if c.name == name {
			if err := c.run(flag.Args()[1:]); err != nil {
				var u usageError
				if errors.As(err, &u) {
					fmt.Fprintf(os.Stderr, "usage: tmctl %s %s\n", c.name, c.args)
					os.Exit(2)
				}
				fmt.Fprintln(os.Stderr, "tmctl:", err)
				os.Exit(1)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "tmctl: unknown command %q\n", name)
	usage()
	os.Exit(2)
}

type usageError struct{}

func (usageError) Error() string { return "usage" }

// parseArgs parses a command's flags, which may come before, between or
// after its arguments. A negative number is an argument.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--":
			return append(pos, args[1:]...), nil
		case len(a) > 1 && a[0] == '-' && !isNumber(a):
			if err := fs.Parse(args); err != nil {
				return nil, err
			}
			args = fs.Args()
		default:
			pos = append(pos, a)
			args = args[1:]
		}
	}
	return pos, nil
}

func isNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {}
	return fs
}

// open opens the controller with the configured trust store.
func open(logAlways bool) (*controller.Controller, error) {
	var paas []*x509.Certificate
	if !*strict {
		paas = attestation.TestPAAs()
	}
	dir := *paaDir
	if dir == "" {
		dir = filepath.Join(*stateDir, "paa")
	}
	prod, err := attestation.LoadPAAs(dir)
	switch {
	case err == nil:
		paas = append(paas, prod...)
	case *paaDir != "" || !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("PAA certificates: %w", err)
	}
	opts := controller.Options{Dir: *stateDir, PAAs: paas, AllowTestCD: !*strict}
	if *verbose || logAlways {
		opts.Log = func(msg string) { log.Print(msg) }
	}
	return controller.Open(opts)
}

func withTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// nodeArg resolves a node by ID or label.
func nodeArg(c *controller.Controller, s string) (uint64, error) {
	if id, err := strconv.ParseUint(s, 0, 64); err == nil {
		if _, ok := c.Node(id); !ok {
			return 0, fmt.Errorf("no node %d", id)
		}
		return id, nil
	}
	var found []uint64
	for _, n := range c.Nodes() {
		if strings.EqualFold(n.Label, s) {
			found = append(found, n.ID)
		}
	}
	switch len(found) {
	case 0:
		return 0, fmt.Errorf("no node labelled %q", s)
	case 1:
		return found[0], nil
	}
	return 0, fmt.Errorf("%d nodes labelled %q", len(found), s)
}

var model = datamodel.Default

// endpointArg parses an endpoint number or *.
func endpointArg(s string) (ep uint16, any bool, err error) {
	if s == "*" {
		return 0, true, nil
	}
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return 0, false, fmt.Errorf("endpoint %q: want a number or *", s)
	}
	return uint16(n), false, nil
}

// clusterArg parses a cluster name, number or *.
func clusterArg(s string) (id uint32, c *datamodel.Cluster, any bool, err error) {
	if s == "*" {
		return 0, nil, true, nil
	}
	if c = model().Cluster(s); c != nil {
		return c.ID, c, false, nil
	}
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, nil, false, fmt.Errorf("unknown cluster %q (see tmctl clusters)", s)
	}
	return uint32(n), nil, false, nil
}

// memberID resolves an attribute, command or event of a cluster by name
// or number.
func memberID(kind, s string, c *datamodel.Cluster, find func(string) (uint32, bool)) (uint32, error) {
	if c != nil {
		if id, ok := find(s); ok {
			return id, nil
		}
	}
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		if c == nil {
			return 0, fmt.Errorf("%s %q: want a number", kind, s)
		}
		return 0, fmt.Errorf("cluster %s has no %s %q (see tmctl clusters %s)", c.Name, kind, s, c.Name)
	}
	return uint32(n), nil
}
