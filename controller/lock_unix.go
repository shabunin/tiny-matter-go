//go:build unix

package controller

import (
	"os"
	"syscall"
)

// tryLock takes an exclusive lock on f without waiting; closing f
// releases it.
func tryLock(f *os.File) bool {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}
