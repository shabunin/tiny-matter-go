package clusters

import (
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/im"
)

// TestMoveToHueSaturation checks the application's hue move: it reaches
// the target over the transition, the shortest way round the circle.
func TestMoveToHueSaturation(t *testing.T) {
	n := im.NewNode(1)
	on := &OnOff{On: true}
	c := NewColorControl(ColorAllFeatures, on, nil)
	n.AddCluster(n.AddEndpoint(1), on, c)
	now := time.Unix(1000, 0)
	c.MoveToHueSaturation(n, 1, now, 240, 254, 0)
	if h, s := c.HueSaturation(); h != 240 || s != 254 || c.Mode() != colorModeHS {
		t.Fatalf("hue %d sat %d mode %d, want 240 254 hue/sat", h, s, c.Mode())
	}
	// From 240 to 10 the short way crosses 254/0, not back through 120.
	c.MoveToHueSaturation(n, 1, now, 10, 254, time.Second)
	now = now.Add(500 * time.Millisecond)
	c.Poll(n, 1, now)
	if h, _ := c.HueSaturation(); h > 10 && h < 240 {
		t.Fatalf("hue %d halfway: went the long way round", h)
	}
	now = now.Add(time.Second)
	c.Poll(n, 1, now)
	if h, _ := c.HueSaturation(); h != 10 {
		t.Fatalf("hue %d after the transition, want 10", h)
	}
}
