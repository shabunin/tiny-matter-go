package main

import (
	"log"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/shabunin/tiny-matter-go/dnssd"
)

// avahiAdvertiser publishes services through avahi-publish processes.
type avahiAdvertiser struct {
	procs map[string]*exec.Cmd // keyed by service description
}

func key(s dnssd.Service) string {
	return s.Instance + "|" + s.Type + "|" + strings.Join(s.Subtypes, ",") + "|" + strings.Join(s.TXT, ",")
}

func (a *avahiAdvertiser) Advertise(svcs []dnssd.Service) {
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
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err := cmd.Start(); err != nil {
			log.Printf("avahi-publish: %v", err)
			continue
		}
		log.Printf("advertising %s.%s", s.Instance, s.Type)
		a.procs[k] = cmd
	}
}
