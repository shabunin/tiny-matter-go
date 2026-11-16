package controller_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/controller"
	"github.com/shabunin/tiny-matter-go/credentials/attestation"
	"github.com/shabunin/tiny-matter-go/onboarding"
)

func TestCASEResumes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := startDevice(t)
	var mu sync.Mutex
	var logs []string
	c, err := controller.Open(controller.Options{Dir: t.TempDir(), PAAs: attestation.TestPAAs(), NoDiscovery: true,
		Log: func(msg string) { mu.Lock(); logs = append(logs, msg); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n, err := c.Commission(ctx, &onboarding.Payload{Passcode: passcode, Discriminator: 3840},
		controller.CommissionOptions{Addr: d.addr()})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c.CloseSessions(n.ID)
		readOnOff(t, ctx, c, n.ID)
	}
	mu.Lock()
	defer mu.Unlock()
	resumed := 0
	for _, l := range logs {
		if strings.HasPrefix(l, "CASE with") && strings.HasSuffix(l, "(resuming)") {
			resumed++
		}
	}
	var records int
	d.do(func() { records = d.dev.Resumptions.Len() })
	if resumed != 2 || records != 1 {
		t.Fatalf("%d resumptions, device has %d records; log:\n%s", resumed, records, strings.Join(logs, "\n"))
	}
}
