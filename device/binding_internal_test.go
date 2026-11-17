package device

import (
	"fmt"
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
)

// TestBoundQueueOrder checks coalescing: at most one waiting command per
// endpoint and cluster, in the order they were last given.
func TestBoundQueueOrder(t *testing.T) {
	b := &binder{peers: map[peerKey]*boundPeer{}}
	k := peerKey{1, 2}
	call := func(cluster, cmd uint32) *boundCall { return &boundCall{endpoint: 1, cluster: cluster, cmd: cmd} }
	var now time.Time
	b.queue(now, k, call(clusters.IDLevelControl, 1)) // in flight
	b.peers[k].busy = true
	b.queue(now, k, call(clusters.IDLevelControl, 2)) // waits behind the one in flight
	b.queue(now, k, call(clusters.IDLevelControl, 3)) // replaces 2
	b.queue(now, k, call(clusters.IDOnOff, 4))
	b.queue(now, k, call(clusters.IDLevelControl, 5)) // replaces 3, after the Off
	b.queue(now, k, call(clusters.IDColorControl, 6))
	b.queue(now, k, call(clusters.IDLevelControl, 7)) // replaces 5, after the colour
	b.queue(now, k, call(clusters.IDColorControl, 8)) // replaces 6, after the level
	var got []uint32
	for _, c := range b.peers[k].calls {
		got = append(got, c.cmd)
	}
	if fmt.Sprint(got) != "[1 4 7 8]" {
		t.Errorf("queue %v, want [1 4 7 8]", got)
	}
}
