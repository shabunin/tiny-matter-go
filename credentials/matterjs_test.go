package credentials

import (
	"encoding/hex"
	"testing"
)

// Certificates issued by the matter.js 0.18 controller during
// commissioning: an RCAC with rcac-id 0 and a NOC (no ICAC) whose subject
// lists the fabric ID before the node ID.
const (
	matterjsRCAC = "15300101002402013703241400182604de3ea93026055e75564537062414001824070124080130094104cf2623cf112f1b10a76a60c3ead877f9071d4007602c2ba9968809ce3d047cb4ed55e82bde841a2d8357e99e8457e38f9e926af5868e8e096b530272debb60ea370a3501290118240260300414e6ae4d8583427dc4ab9c1287bd91eaccaf8d9253300514e6ae4d8583427dc4ab9c1287bd91eaccaf8d925318300b40c48ca04ab6888e75f6ac54f0edec76c6ab6d4e99fc15d6c887774a4038a817f72fc398a8477cb8394ac281ba4087dd8664eacdd522030f1ea0289711f35f417e18"
	matterjsNOC  = "15300101032402013703241400182604e53ea930260565755645370627158f98d121a77bc3d2241101182407012408013009410474fb38bb6350b7b3189d49cfc739ff327d76e3a70ef06bb3006075c0169e75268c72ae4cbb90ceda8878be7c759d029490a555d40b6a00e71a7448f3386851dd370a350128011824020136030402040118300414b02c294c51b83a9bdc686f43250887beeb1fdfbd300514e6ae4d8583427dc4ab9c1287bd91eaccaf8d925318300b40dee05fc83ddb1b2c2dd72220b3897e01578e4ef0dac51dcb54b2e1f4a678052327904bd77e6d37223199d79b362651a01964b7e274f424e0f400a6c64954ec9818"
)

func TestMatterJSChain(t *testing.T) {
	rcac, _ := hex.DecodeString(matterjsRCAC)
	noc, _ := hex.DecodeString(matterjsNOC)
	id, err := ValidateNOCChain(noc, nil, rcac)
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID != 1 || id.FabricID != 0xD2C37BA721D1988F {
		t.Fatalf("identity: node %x fabric %x", id.NodeID, id.FabricID)
	}
}
