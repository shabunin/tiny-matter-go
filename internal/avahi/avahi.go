// Package avahi advertises DNS-SD services on Linux through avahi-publish
// processes, one per service.
package avahi

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

// Advertiser implements dnssd.Advertiser. Its processes end with the
// program (or with Advertise(nil)).
type Advertiser struct {
	// Log, if set, hears what is advertised and failures.
	Log func(msg string)

	procs map[string]*exec.Cmd // keyed by service description
}

func key(s dnssd.Service) string {
	return s.Instance + "|" + s.Type + "|" + strings.Join(s.Subtypes, ",") + "|" + strings.Join(s.TXT, ",")
}

func (a *Advertiser) log(msg string) {
	if a.Log != nil {
		a.Log(msg)
	}
}

// Advertise publishes exactly svcs, withdrawing the others.
func (a *Advertiser) Advertise(svcs []dnssd.Service) {
	if a.procs == nil {
		a.procs = map[string]*exec.Cmd{}
	}
	want := map[string]dnssd.Service{}
	for _, s := range svcs {
		want[key(s)] = s
	}
	for k, p := range a.procs {
		if _, ok := want[k]; !ok {
			p.Process.Kill()
			p.Wait()
			delete(a.procs, k)
		}
	}
	for k, s := range want {
		if a.procs[k] != nil {
			continue
		}
		args := []string{"-s"}
		for _, st := range s.Subtypes {
			args = append(args, "--subtype="+st+"._sub."+s.Type)
		}
		args = append(args, s.Instance, s.Type, strconv.Itoa(int(s.Port)))
		args = append(args, s.TXT...)
		cmd := exec.Command("avahi-publish", args...)
		setPdeathsig(cmd)
		if err := cmd.Start(); err != nil {
			a.log("avahi-publish: " + err.Error())
			continue
		}
		a.log("advertising " + s.Instance + "." + s.Type)
		a.procs[k] = cmd
	}
}
