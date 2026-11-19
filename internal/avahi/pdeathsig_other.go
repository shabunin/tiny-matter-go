//go:build !linux

package avahi

import "os/exec"

func setPdeathsig(*exec.Cmd) {}
