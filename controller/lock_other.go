//go:build !unix

package controller

import "os"

// tryLock reports false: without file locks, identities are not shared
// between runs.
func tryLock(f *os.File) bool { return false }
