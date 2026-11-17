package im

import (
	"slices"
	"testing"
)

func TestEndpointTree(t *testing.T) {
	n := NewNode(1)
	for _, id := range []uint16{0, 5, 1, 3, 4} {
		n.AddEndpoint(id)
	}
	var ids []uint16
	for _, e := range n.Endpoints() {
		ids = append(ids, e.ID)
	}
	if !slices.Equal(ids, []uint16{0, 1, 3, 4, 5}) {
		t.Fatalf("endpoints not in order: %v", ids)
	}
	// 1 aggregates 3 and 4; 5 is a part of 4 (a composed bridged device).
	n.Endpoint(3).Parent = 1
	n.Endpoint(4).Parent = 1
	n.Endpoint(5).Parent = 4
	for _, c := range []struct {
		id   uint16
		want []uint16
	}{
		{0, []uint16{1, 3, 4, 5}},
		{1, []uint16{3, 4, 5}},
		{4, []uint16{5}},
		{3, nil},
	} {
		if got := n.Parts(c.id, nil); !slices.Equal(got, c.want) {
			t.Errorf("Parts(%d) = %v, want %v", c.id, got, c.want)
		}
	}

	var changed []ConcretePath
	n.OnChange = func(p ConcretePath) { changed = append(changed, p) }
	n.RemoveEndpoint(4) // and its part, 5
	if got := n.Parts(0, nil); !slices.Equal(got, []uint16{1, 3}) {
		t.Errorf("after removal: %v", got)
	}
	parts := func(ep uint16) ConcretePath { return ConcretePath{ep, descriptorID, partsListID} }
	if !slices.Contains(changed, parts(1)) || !slices.Contains(changed, parts(0)) {
		t.Errorf("removal reported %v", changed)
	}

	// A cycle of parents does not hang the walks.
	n.Endpoint(1).Parent = 3
	n.Endpoint(3).Parent = 1
	n.Parts(1, nil)
	n.EndpointAdded(3)
	n.RemoveEndpoint(1)
}
