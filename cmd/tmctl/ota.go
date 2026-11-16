package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/ota"
	"github.com/shabunin/tiny-matter-go/tlv"
)

func cmdOTAImage(args []string) error {
	fs := flagSet("ota-image")
	vendor := fs.String("vendor", "", "vendor ID")
	product := fs.String("product", "", "product ID")
	version := fs.Uint("version", 0, "software version (a number)")
	versionString := fs.String("version-string", "", "software version string (default: the version)")
	minVersion := fs.Int64("min", -1, "oldest version the image may update")
	maxVersion := fs.Int64("max", -1, "newest version the image may update")
	notes := fs.String("notes", "", "release notes URL")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 2 || *vendor == "" || *product == "" || *version == 0 {
		return usageError{}
	}
	vid, err := strconv.ParseUint(*vendor, 0, 16)
	if err != nil {
		return fmt.Errorf("vendor %q: %w", *vendor, err)
	}
	pid, err := strconv.ParseUint(*product, 0, 16)
	if err != nil {
		return fmt.Errorf("product %q: %w", *product, err)
	}
	h := ota.Header{VendorID: uint16(vid), ProductID: uint16(pid), SoftwareVersion: uint32(*version),
		SoftwareVersionString: *versionString, ReleaseNotesURL: *notes}
	if h.SoftwareVersionString == "" {
		h.SoftwareVersionString = strconv.FormatUint(uint64(h.SoftwareVersion), 10)
	}
	if *minVersion >= 0 {
		h.MinApplicableVersion, h.HasMin = uint32(*minVersion), true
	}
	if *maxVersion >= 0 {
		h.MaxApplicableVersion, h.HasMax = uint32(*maxVersion), true
	}
	payload, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	img, err := ota.Create(h, payload)
	if err != nil {
		return err
	}
	return os.WriteFile(pos[1], img, 0o644)
}

// readImage reads and checks an OTA image file.
func readImage(name string) ([]byte, ota.Header, error) {
	img, err := os.ReadFile(name)
	if err != nil {
		return nil, ota.Header{}, err
	}
	r := &ota.Reader{}
	if err := r.Write(img); err != nil {
		return nil, ota.Header{}, err
	}
	if err := r.Close(); err != nil {
		return nil, ota.Header{}, err
	}
	return img, r.Header, nil
}

func cmdOTAInfo(args []string) error {
	if len(args) != 1 {
		return usageError{}
	}
	_, h, err := readImage(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("vendor 0x%04X, product 0x%04X\n", h.VendorID, h.ProductID)
	fmt.Printf("version %d (%s)\n", h.SoftwareVersion, h.SoftwareVersionString)
	fmt.Printf("payload %d bytes, sha256 %x (verified)\n", h.PayloadSize, h.Digest)
	if h.HasMin || h.HasMax {
		lo, hi := "any", "any"
		if h.HasMin {
			lo = strconv.FormatUint(uint64(h.MinApplicableVersion), 10)
		}
		if h.HasMax {
			hi = strconv.FormatUint(uint64(h.MaxApplicableVersion), 10)
		}
		fmt.Printf("updates versions %s to %s\n", lo, hi)
	}
	if h.ReleaseNotesURL != "" {
		fmt.Println("release notes", h.ReleaseNotesURL)
	}
	return nil
}

// otaEvent is something the provider saw, passed from the network
// goroutine.
type otaEvent struct {
	kind    string
	version uint32
	sent    int64
	total   int64
	offered bool
	err     error
}

func cmdOTAUpdate(args []string) error {
	fs := flagSet("ota-update")
	wait := fs.Duration("wait", 3*time.Minute, "how long to wait for the node to restart with the new version")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 2 {
		return usageError{}
	}
	img, h, err := readImage(pos[1])
	if err != nil {
		return err
	}
	c, err := open(false)
	if err != nil {
		return err
	}
	defer c.Close()
	id, err := nodeArg(c, pos[0])
	if err != nil {
		return err
	}
	events := make(chan otaEvent, 64)
	send := func(e otaEvent) {
		select {
		case events <- e:
		default: // progress may be dropped
		}
	}
	lastPercent := int64(-1)
	err = c.ServeOTA(&controller.OTAProvider{
		Image: img,
		OnQuery: func(node uint64, q *clusters.QueryImage, offered bool) {
			if node == id {
				send(otaEvent{kind: "query", version: q.SoftwareVersion, offered: offered})
			}
		},
		OnProgress: func(node uint64, sent, total int64) {
			if p := sent * 10 / total; node == id && p != lastPercent {
				lastPercent = p
				send(otaEvent{kind: "progress", sent: sent, total: total})
			}
		},
		OnTransfer: func(node uint64, err error) {
			if node == id {
				send(otaEvent{kind: "transfer", err: err})
			}
		},
		OnApply: func(node uint64, version uint32) {
			if node == id {
				send(otaEvent{kind: "apply", version: version})
			}
		},
		OnApplied: func(node uint64, version uint32) {
			if node == id {
				send(otaEvent{kind: "applied", version: version})
			}
		},
	})
	if err != nil {
		return err
	}
	ctx, cancel := withTimeout(*timeout)
	err = c.AnnounceOTA(ctx, id)
	cancel()
	if err != nil {
		return fmt.Errorf("announcing the update: %w", describe(err))
	}
	fmt.Printf("offering version %d (%s) to node %d\n", h.SoftwareVersion, h.SoftwareVersionString, id)
	start := time.Now()
	idle := time.NewTimer(*timeout)
	defer idle.Stop()
	var restart <-chan time.Time
	for {
		select {
		case e := <-events:
			idle.Reset(*timeout)
			switch e.kind {
			case "query":
				if !e.offered {
					return fmt.Errorf("node runs version %d; the image does not apply to it", e.version)
				}
				fmt.Printf("node runs version %d; downloading\n", e.version)
			case "progress":
				fmt.Printf("  %3d%%  %d of %d bytes\n", e.sent*100/e.total, e.sent, e.total)
			case "transfer":
				if e.err != nil {
					return fmt.Errorf("download failed: %w", e.err)
				}
				fmt.Printf("downloaded in %v\n", time.Since(start).Round(100*time.Millisecond))
			case "apply":
				fmt.Println("node verified the image and is applying it")
				idle.Stop()
				restart = time.After(*wait)
			case "applied":
				fmt.Printf("node restarted with version %d\n", e.version)
				return confirmVersion(c, id, h.SoftwareVersion)
			}
		case <-idle.C:
			return errors.New("the node stopped responding")
		case <-restart:
			return errors.New("the node did not report the new version in time; it may have rolled back")
		}
	}
}

// confirmVersion reads the node's SoftwareVersion.
func confirmVersion(c *controller.Controller, id uint64, want uint32) error {
	ctx, cancel := withTimeout(*timeout)
	defer cancel()
	rep, err := c.Read(ctx, id, im.Request{Attributes: []im.AttributePath{{Endpoint: 0, Cluster: clusters.IDBasicInformation, Attribute: 0x0009}}})
	if err != nil {
		return describe(err)
	}
	if len(rep.Attributes) != 1 || rep.Attributes[0].Status != im.Success {
		return errors.New("reading SoftwareVersion failed")
	}
	r := tlv.NewReader(rep.Attributes[0].Data)
	r.Next()
	v, err := r.Uint32()
	if err != nil {
		return err
	}
	if v != want {
		return fmt.Errorf("node reports SoftwareVersion %d, want %d", v, want)
	}
	fmt.Printf("SoftwareVersion %d confirmed\n", v)
	return nil
}
