//go:build unix

package main

import (
	"os"
	"syscall"
)

func execSelf(path string, args []string) error {
	return syscall.Exec(path, append([]string{path}, args...), os.Environ())
}
