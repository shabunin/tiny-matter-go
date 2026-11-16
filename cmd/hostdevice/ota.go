package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/shabunin/tiny-matter-go/ota"
)

// Build-time software version: go build -ldflags "-X main.softwareVersion=2".
var softwareVersion = "1"

// binaryUpdates stores an OTA image's payload, a new hostdevice binary, in
// a directory, and applies it by executing it in place of this process
// with the same arguments.
type binaryUpdates struct {
	dir     string
	f       *os.File
	version uint32
	ready   string // the complete binary
	// beforeExec releases what the new process needs (advertisements).
	beforeExec func()
}

func (b *binaryUpdates) Begin(h *ota.Header) error {
	b.Abort()
	if err := os.MkdirAll(b.dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(b.dir, "download-*")
	if err != nil {
		return err
	}
	b.f, b.version = f, h.SoftwareVersion
	log.Printf("ota: receiving version %d (%d bytes) into %s", h.SoftwareVersion, h.PayloadSize, f.Name())
	return nil
}

func (b *binaryUpdates) Write(p []byte) error {
	if b.f == nil {
		return errors.New("ota: no download")
	}
	_, err := b.f.Write(p)
	return err
}

func (b *binaryUpdates) Finish() error {
	f := b.f
	b.f = nil
	if err := f.Chmod(0o755); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	b.ready = filepath.Join(b.dir, "hostdevice-v"+strconv.FormatUint(uint64(b.version), 10))
	return os.Rename(f.Name(), b.ready)
}

func (b *binaryUpdates) Abort() {
	if b.f != nil {
		b.f.Close()
		os.Remove(b.f.Name())
		b.f = nil
	}
	if b.ready != "" {
		os.Remove(b.ready)
		b.ready = ""
	}
}

func (b *binaryUpdates) Apply() error {
	if b.ready == "" {
		return errors.New("ota: no image")
	}
	log.Printf("ota: restarting into %s", b.ready)
	if b.beforeExec != nil {
		b.beforeExec()
	}
	return syscall.Exec(b.ready, append([]string{b.ready}, os.Args[1:]...), os.Environ())
}
