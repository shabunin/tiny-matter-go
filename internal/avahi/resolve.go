package avahi

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver finds operational Matter nodes (device.Config.Resolve) with
// avahi-browse. A lookup runs in the background: Resolve answers from what
// the last one found, and starts another when that is missing or old, so
// callers poll it.
type Resolver struct {
	mu    sync.Mutex
	found map[string]resolved
	busy  bool
}

type resolved struct {
	addr netip.AddrPort
	at   time.Time
}

// resolveFresh is how long a lookup's answers are used.
const resolveFresh = time.Minute

// Resolve returns the address of a node of a fabric, if known.
func (r *Resolver) Resolve(now time.Time, cfid [8]byte, node uint64) (netip.AddrPort, bool) {
	name := fmt.Sprintf("%016X-%016X", cfid, node)
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.found[name]
	if ok && now.Sub(f.at) < resolveFresh {
		return f.addr, true
	}
	if !r.busy {
		r.busy = true
		go r.browse()
	}
	return netip.AddrPort{}, false
}

// browse lists the _matter._tcp services avahi resolves.
func (r *Resolver) browse() {
	out, _ := exec.Command("avahi-browse", "--resolve", "--parsable", "--terminate", "_matter._tcp").Output()
	found := parseBrowse(out, time.Now())
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy = false
	if r.found == nil {
		r.found = map[string]resolved{}
	}
	for name, f := range found {
		r.found[name] = f
	}
}

// parseBrowse reads avahi-browse's resolved lines
// (=;iface;proto;name;type;domain;host;address;port;txt), preferring an
// IPv4 address, then a routable IPv6 one, then a link-local one (zoned).
func parseBrowse(out []byte, now time.Time) map[string]resolved {
	rank := func(a netip.Addr) int {
		switch {
		case a.Is4():
			return 3
		case !a.IsLinkLocalUnicast():
			return 2
		}
		return 1
	}
	found := map[string]resolved{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ";")
		if len(f) < 9 || f[0] != "=" {
			continue
		}
		a, err := netip.ParseAddr(f[7])
		port, perr := strconv.ParseUint(f[8], 10, 16)
		if err != nil || perr != nil {
			continue
		}
		if a.IsLinkLocalUnicast() && a.Is6() {
			a = a.WithZone(f[1])
		}
		ap := netip.AddrPortFrom(a, uint16(port))
		name := strings.ToUpper(f[3])
		if old, ok := found[name]; ok && rank(old.addr.Addr()) >= rank(a) {
			continue
		}
		found[name] = resolved{ap, now}
	}
	return found
}
