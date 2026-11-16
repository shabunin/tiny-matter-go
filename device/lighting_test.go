package device_test

import (
	"testing"
	"time"

	"github.com/shabunin/tiny-matter-go/clusters"
	"github.com/shabunin/tiny-matter-go/exchange"
	"github.com/shabunin/tiny-matter-go/im"
	"github.com/shabunin/tiny-matter-go/storage"
	"github.com/shabunin/tiny-matter-go/tlv"
)

const lightEP = 2

// light is an Extended Color Light on endpoint 2.
type light struct {
	id     *clusters.Identify
	onOff  *clusters.OnOff
	level  *clusters.LevelControl
	color  *clusters.ColorControl
	scenes *clusters.ScenesManagement
}

func (h *harness) addLight() *light {
	l := &light{id: &clusters.Identify{Type: clusters.IdentifyLightOutput, Effects: true},
		onOff: &clusters.OnOff{Lighting: true}}
	l.level = clusters.NewLevelControl(l.onOff, true)
	l.color = clusters.NewColorControl(clusters.ColorAllFeatures, l.onOff, l.level)
	l.scenes = h.dev.NewScenes()
	l.onOff.Scenes = l.scenes
	g := h.dev.NewGroups(l.id)
	g.Scenes = l.scenes
	ep := h.dev.Node.AddEndpoint(lightEP, clusters.DeviceTypeExtendedColorLight)
	h.dev.Node.AddCluster(ep, clusters.Descriptor{}, l.id, g, l.scenes, l.onOff, l.level, l.color)
	return l
}

// cmd invokes a command on the light with fields 0, 1, ... (nil is null;
// int values are signed).
func (h *harness) cmd(s *exchange.Session, cluster, command uint32, vals ...any) im.InvokeResult {
	h.t.Helper()
	return h.invoke(s, im.CommandPath{Endpoint: lightEP, Cluster: cluster, Command: command}, func(w *tlv.Writer) {
		for i, v := range vals {
			tag := tlv.ContextTag(uint8(i))
			switch v := v.(type) {
			case nil:
				w.PutNull(tag)
			case int:
				w.PutInt(tag, int64(v))
			case uint:
				w.PutUint(tag, uint64(v))
			case string:
				w.PutString(tag, v)
			case func(w *tlv.Writer, tag tlv.Tag):
				v(w, tag)
			}
		}
	})
}

func (h *harness) cmdOK(s *exchange.Session, cluster, command uint32, vals ...any) {
	h.t.Helper()
	if res := h.cmd(s, cluster, command, vals...); res.Status != im.Success {
		h.t.Fatalf("command %#x/%#x: status %#x", cluster, command, res.Status)
	}
}

func (h *harness) writeLight(s *exchange.Session, cluster, attr uint32, v uint64) im.Status {
	h.t.Helper()
	return h.write(s, im.AttributePath{Endpoint: lightEP, Cluster: cluster, Attribute: attr},
		func(w *tlv.Writer, tag tlv.Tag) { w.PutUint(tag, v) })
}

func (h *harness) readUint(s *exchange.Session, cluster, attr uint32) uint64 {
	h.t.Helper()
	r := h.attr(s, lightEP, cluster, attr)
	v, err := r.Uint()
	if err != nil {
		h.t.Fatalf("read %#x/%#x: %v", cluster, attr, err)
	}
	return v
}

const (
	cmdOff, cmdOn                = 0, 1
	cmdOffWithEffect             = 0x40
	cmdOnWithRecall              = 0x41
	cmdOnWithTimedOff            = 0x42
	cmdMoveToLevel               = 0
	cmdMoveToLevelWithOnOff      = 4
	cmdMoveToHueSat              = 6
	cmdMoveToColor               = 7
	cmdMoveToTemp                = 0x0A
	cmdEnhancedMoveToHue         = 0x40
	cmdColorLoopSet              = 0x44
	cmdAddScene, cmdViewScene    = 0, 1
	cmdStoreScene, cmdRecall     = 4, 5
	cmdSceneMembership           = 6
	cmdRemoveAllGroups           = 4
	attrOnTime, attrStartUpOnOff = 0x4001, 0x4003
	attrGlobalScene              = 0x4000
	attrCurrentLevel             = 0
	attrLevelOptions             = 0x0F
	attrOnOffTransition          = 0x10
	attrStartUpLevel             = 0x4000
	attrColorMode                = 0x08
	attrEnhancedMode             = 0x4001
	attrCurrentX, attrCurrentY   = 3, 4
	attrMireds                   = 7
	attrEnhancedHue              = 0x4000
	attrRemainingTime            = 2
)

func TestLevelFollowsOnOff(t *testing.T) {
	h := newHarness(t)
	l := h.addLight()
	_, s := h.commission()

	h.cmdOK(s, clusters.IDOnOff, cmdOn)
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(100), uint(0), uint(0), uint(0))
	if l.level.Level() != 100 || l.level.Brightness() != 100 {
		t.Fatalf("level %d brightness %d, want 100", l.level.Level(), l.level.Brightness())
	}
	// Off fades over OnOffTransitionTime; OnOff is false at once.
	if st := h.writeLight(s, clusters.IDLevelControl, attrOnOffTransition, 40); st != im.Success {
		t.Fatalf("write OnOffTransitionTime: %#x", st)
	}
	h.cmdOK(s, clusters.IDOnOff, cmdOff)
	if l.onOff.On || l.level.Brightness() == 0 || l.level.Brightness() >= 100 {
		t.Fatalf("1 s into the fade: on %v brightness %d", l.onOff.On, l.level.Brightness())
	}
	h.w.Advance(4 * time.Second)
	if l.level.Brightness() != 0 || l.level.Level() != 100 {
		t.Fatalf("after the fade: brightness %d level %d, want 0 and 100", l.level.Brightness(), l.level.Level())
	}
	// A move while off is ignored unless ExecuteIfOff.
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(50), uint(0), uint(0), uint(0))
	if l.level.Level() != 100 {
		t.Fatal("MoveToLevel applied while off")
	}
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(50), uint(0), uint(1), uint(1))
	if l.level.Level() != 50 {
		t.Fatal("MoveToLevel with ExecuteIfOff override not applied")
	}
	// On rises from the minimum back to the level.
	h.cmdOK(s, clusters.IDOnOff, cmdOn)
	if b := l.level.Brightness(); !l.onOff.On || b == 0 || b >= 50 {
		t.Fatalf("1 s into the rise: on %v brightness %d", l.onOff.On, b)
	}
	h.w.Advance(4 * time.Second)
	if got := h.readUint(s, clusters.IDLevelControl, attrCurrentLevel); got != 50 {
		t.Fatalf("CurrentLevel %d after on, want 50", got)
	}
	// MoveToLevelWithOnOff to the minimum turns the light off.
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevelWithOnOff, uint(1), uint(0), uint(0), uint(0))
	if l.onOff.On {
		t.Fatal("MoveToLevelWithOnOff(1) left the light on")
	}
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevelWithOnOff, uint(200), uint(0), uint(0), uint(0))
	if !l.onOff.On || l.level.Level() != 200 {
		t.Fatal("MoveToLevelWithOnOff(200) did not turn on")
	}
	if res := h.cmd(s, clusters.IDLevelControl, cmdMoveToLevel, uint(255), uint(0), uint(0), uint(0)); res.Status != im.ConstraintError {
		t.Fatalf("MoveToLevel(255): %#x", res.Status)
	}
}

func TestColorModes(t *testing.T) {
	h := newHarness(t)
	l := h.addLight()
	_, s := h.commission()
	h.cmdOK(s, clusters.IDOnOff, cmdOn)
	if got := h.readUint(s, clusters.IDColorControl, attrColorMode); got != 2 {
		t.Fatalf("initial ColorMode %d, want 2 (temperature)", got)
	}

	h.cmdOK(s, clusters.IDColorControl, cmdMoveToHueSat, uint(100), uint(200), uint(0), uint(0), uint(0))
	if hue, sat := l.color.HueSaturation(); hue != 100 || sat != 200 || l.color.Mode() != 0 {
		t.Fatalf("hue %d sat %d mode %d", hue, sat, l.color.Mode())
	}
	if r, g, b := l.color.RGB(254); g <= r || g <= b {
		t.Fatalf("hue 100 (green) rendered as %d,%d,%d", r, g, b)
	}
	if res := h.cmd(s, clusters.IDColorControl, cmdMoveToHueSat, uint(255), uint(0), uint(0), uint(0), uint(0)); res.Status != im.ConstraintError {
		t.Fatalf("MoveToHueAndSaturation(255): %#x", res.Status)
	}

	h.cmdOK(s, clusters.IDColorControl, cmdEnhancedMoveToHue, uint(0x8000), uint(0), uint(0), uint(0), uint(0))
	if h.readUint(s, clusters.IDColorControl, attrColorMode) != 0 || h.readUint(s, clusters.IDColorControl, attrEnhancedMode) != 3 {
		t.Fatal("EnhancedMoveToHue: want ColorMode 0, EnhancedColorMode 3")
	}

	// xy over 5 s: halfway after ~2.5 s, there after 5.
	x0, y0 := l.color.XY()
	h.cmdOK(s, clusters.IDColorControl, cmdMoveToColor, uint(20000), uint(20000), uint(50), uint(0), uint(0))
	h.w.Advance(1500 * time.Millisecond)
	if x, _ := l.color.XY(); x == x0 || x == 20000 {
		t.Fatalf("x %d mid-transition (from %d)", x, x0)
	}
	if rt := h.readUint(s, clusters.IDColorControl, attrRemainingTime); rt == 0 || rt > 30 {
		t.Fatalf("RemainingTime %d mid-transition", rt)
	}
	h.w.Advance(3 * time.Second)
	if x, y := l.color.XY(); x != 20000 || y != 20000 || l.color.Mode() != 1 {
		t.Fatalf("xy %d,%d mode %d after the transition (from %d,%d)", x, y, l.color.Mode(), x0, y0)
	}

	// Temperatures are clamped to the physical range.
	h.cmdOK(s, clusters.IDColorControl, cmdMoveToTemp, uint(600), uint(0), uint(0), uint(0))
	if l.color.Mireds() != 454 || l.color.Mode() != 2 {
		t.Fatalf("mireds %d mode %d, want 454 and 2", l.color.Mireds(), l.color.Mode())
	}
	// CoupleColorTempToLevel: the brightest level is the coolest.
	if st := h.writeLight(s, clusters.IDLevelControl, attrLevelOptions, 2); st != im.Success {
		t.Fatalf("write Level Options: %#x", st)
	}
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(254), uint(0), uint(0), uint(0))
	if got := h.readUint(s, clusters.IDColorControl, attrMireds); got != 154 {
		t.Fatalf("coupled mireds %d at level 254, want 154", got)
	}

	// The colour loop turns the enhanced hue and restores it when stopped.
	h.cmdOK(s, clusters.IDColorControl, cmdEnhancedMoveToHue, uint(1000), uint(0), uint(0), uint(0), uint(0))
	h.cmdOK(s, clusters.IDColorControl, cmdColorLoopSet, uint(0x0F), uint(1), uint(1), uint(10), uint(0), uint(0), uint(0))
	h.w.Advance(2 * time.Second)
	if e := l.color.EnhancedHue(); e < 10000 || e > 50000 {
		t.Fatalf("enhanced hue %d ~3 s into a 10 s loop", e)
	}
	if rt := h.readUint(s, clusters.IDColorControl, attrRemainingTime); rt != 0xFFFE {
		t.Fatalf("RemainingTime %#x during the loop", rt)
	}
	h.cmdOK(s, clusters.IDColorControl, cmdColorLoopSet, uint(1), uint(0), uint(0), uint(0), uint(0), uint(0), uint(0))
	if e := l.color.EnhancedHue(); e != 1000 {
		t.Fatalf("enhanced hue %d after the loop, want the stored 1000", e)
	}

	// Off without ExecuteIfOff: colour commands are ignored.
	h.cmdOK(s, clusters.IDOnOff, cmdOff)
	h.cmdOK(s, clusters.IDColorControl, cmdMoveToTemp, uint(300), uint(0), uint(0), uint(0))
	if l.color.Mode() == 2 {
		t.Fatal("MoveToColorTemperature applied while off")
	}
}

func TestScenes(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	l := h.addLight()
	ctlF, s := h.commission()

	h.cmdOK(s, clusters.IDOnOff, cmdOn)
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(80), uint(0), uint(0), uint(0))
	h.cmdOK(s, clusters.IDColorControl, cmdMoveToColor, uint(30000), uint(25000), uint(0), uint(0), uint(0))
	sceneStatus := func(res im.InvokeResult) im.Status {
		t.Helper()
		return groupStatus(t, res)
	}
	if st := sceneStatus(h.cmd(s, clusters.IDScenesManagement, cmdStoreScene, uint(0), uint(1))); st != im.Success {
		t.Fatalf("StoreScene: %#x", st)
	}
	if st := sceneStatus(h.cmd(s, clusters.IDScenesManagement, cmdStoreScene, uint(0x77), uint(1))); st != im.InvalidCommand {
		t.Fatalf("StoreScene in a group without the endpoint: %#x", st)
	}
	// AddScene with explicit values: off, level 200.
	efs := func(w *tlv.Writer, tag tlv.Tag) {
		w.StartArray(tag)
		set := func(cluster uint32, attr uint32, v uint64) {
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(0), uint64(cluster))
			w.StartArray(tlv.ContextTag(1))
			w.StartStruct(tlv.Anonymous)
			w.PutUint(tlv.ContextTag(0), uint64(attr))
			w.PutUint(tlv.ContextTag(1), v)
			w.EndContainer()
			w.EndContainer()
			w.EndContainer()
		}
		set(clusters.IDOnOff, 0, 0)
		set(clusters.IDLevelControl, 0, 200)
		w.EndContainer()
	}
	if st := sceneStatus(h.cmd(s, clusters.IDScenesManagement, cmdAddScene, uint(0), uint(2), uint(2000), "night", efs)); st != im.Success {
		t.Fatalf("AddScene: %#x", st)
	}

	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(10), uint(0), uint(0), uint(0))
	h.cmdOK(s, clusters.IDColorControl, cmdMoveToTemp, uint(300), uint(0), uint(0), uint(0))
	h.cmdOK(s, clusters.IDScenesManagement, cmdRecall, uint(0), uint(1), uint(0))
	if x, y := l.color.XY(); l.level.Level() != 80 || x != 30000 || y != 25000 || l.color.Mode() != 1 || !l.onOff.On {
		t.Fatalf("scene 1: level %d xy %d,%d mode %d on %v", l.level.Level(), x, y, l.color.Mode(), l.onOff.On)
	}
	// Scene 2 turns off at the end of its 2 s transition.
	h.cmdOK(s, clusters.IDScenesManagement, cmdRecall, uint(0), uint(2))
	if !l.onOff.On {
		t.Fatal("scene 2 turned off before its transition ended")
	}
	h.w.Advance(2 * time.Second)
	if l.onOff.On || l.level.Level() != 200 {
		t.Fatalf("scene 2: on %v level %d", l.onOff.On, l.level.Level())
	}

	res := h.cmd(s, clusters.IDScenesManagement, cmdSceneMembership, uint(0))
	if st := sceneStatus(res); st != im.Success {
		t.Fatalf("GetSceneMembership: %#x", st)
	}
	r := field(t, res.Fields, 3)
	var ids []uint64
	r.EnterContainer()
	for r.Next() == nil {
		v, _ := r.Uint()
		ids = append(ids, v)
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("scenes %v, want [1 2]", ids)
	}
	if c, _ := field(t, res.Fields, 1).Uint(); c != 5 {
		t.Fatalf("capacity %d, want 5", c)
	}

	// The scenes survive a restart.
	h.w.Advance(5 * time.Second)
	h2 := newHarnessStore(t, store)
	l2 := h2.addLight()
	s2 := h2.connect(ctlF)
	h2.cmdOK(s2, clusters.IDScenesManagement, cmdRecall, uint(0), uint(1), uint(0))
	if l2.level.Level() != 80 || !l2.onOff.On {
		t.Fatalf("scene 1 after restart: level %d on %v", l2.level.Level(), l2.onOff.On)
	}
	res = h2.cmd(s2, clusters.IDScenesManagement, cmdViewScene, uint(0), uint(2))
	if name, _ := field(t, res.Fields, 4).UTF8(); string(name) != "night" {
		t.Fatalf("scene 2 name %q", name)
	}

	// RemoveAllGroups deletes the group 0 scenes too.
	h2.cmdOK(s2, clusters.IDGroups, cmdRemoveAllGroups)
	if res := h2.cmd(s2, clusters.IDScenesManagement, cmdRecall, uint(0), uint(1)); res.Status != im.NotFound {
		t.Fatalf("recall after RemoveAllGroups: %#x", res.Status)
	}
}

func TestOnOffLighting(t *testing.T) {
	store := &storage.Memory{}
	h := newHarnessStore(t, store)
	l := h.addLight()
	ctlF, s := h.commission()

	h.cmdOK(s, clusters.IDOnOff, cmdOn)
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(120), uint(0), uint(0), uint(0))
	// OffWithEffect keeps the global scene; OnWithRecallGlobalScene brings
	// it back.
	h.cmdOK(s, clusters.IDOnOff, cmdOffWithEffect, uint(0), uint(0))
	if gsc, _ := h.attr(s, lightEP, clusters.IDOnOff, attrGlobalScene).Bool(); l.onOff.On || gsc {
		t.Fatal("OffWithEffect: want off and GlobalSceneControl false")
	}
	h.cmdOK(s, clusters.IDLevelControl, cmdMoveToLevel, uint(30), uint(0), uint(1), uint(1))
	h.cmdOK(s, clusters.IDOnOff, cmdOnWithRecall)
	h.w.Advance(2 * time.Second)
	if !l.onOff.On || l.level.Level() != 120 {
		t.Fatalf("OnWithRecallGlobalScene: on %v level %d", l.onOff.On, l.level.Level())
	}
	if res := h.cmd(s, clusters.IDOnOff, cmdOffWithEffect, uint(2), uint(0)); res.Status != im.ConstraintError {
		t.Fatalf("OffWithEffect(2): %#x", res.Status)
	}

	// OnWithTimedOff: on for 3 s.
	h.cmdOK(s, clusters.IDOnOff, cmdOff)
	h.cmdOK(s, clusters.IDOnOff, cmdOnWithTimedOff, uint(0), uint(30), uint(0))
	if !l.onOff.On {
		t.Fatal("OnWithTimedOff did not turn on")
	}
	if ot := h.readUint(s, clusters.IDOnOff, attrOnTime); ot == 0 || ot > 30 {
		t.Fatalf("OnTime %d", ot)
	}
	h.w.Advance(3 * time.Second)
	if l.onOff.On {
		t.Fatal("still on after OnTime")
	}
	// AcceptOnlyWhenOn while off is ignored.
	h.cmdOK(s, clusters.IDOnOff, cmdOnWithTimedOff, uint(1), uint(30), uint(0))
	if l.onOff.On {
		t.Fatal("OnWithTimedOff with AcceptOnlyWhenOn turned on")
	}

	// Identify effects.
	h.cmdOK(s, clusters.IDIdentify, 0x40, uint(clusters.EffectBreathe), uint(0))
	if !l.id.Identifying() || l.id.Effect() != clusters.EffectBreathe {
		t.Fatal("TriggerEffect(Breathe) not running")
	}
	h.cmdOK(s, clusters.IDIdentify, 0x40, uint(clusters.EffectStop), uint(0))
	if l.id.Identifying() {
		t.Fatal("TriggerEffect(Stop) did not stop")
	}
	if res := h.cmd(s, clusters.IDIdentify, 0x40, uint(3), uint(0)); res.Status != im.ConstraintError {
		t.Fatalf("TriggerEffect(3): %#x", res.Status)
	}

	// Start-up behaviour: on at level 77 whatever the state was.
	if st := h.writeLight(s, clusters.IDOnOff, attrStartUpOnOff, 1); st != im.Success {
		t.Fatalf("write StartUpOnOff: %#x", st)
	}
	if st := h.writeLight(s, clusters.IDLevelControl, attrStartUpLevel, 77); st != im.Success {
		t.Fatalf("write StartUpCurrentLevel: %#x", st)
	}
	h.w.Advance(5 * time.Second)
	h2 := newHarnessStore(t, store)
	l2 := h2.addLight()
	if !l2.onOff.On || l2.level.Level() != 77 {
		t.Fatalf("after restart: on %v level %d, want on at 77", l2.onOff.On, l2.level.Level())
	}
	s2 := h2.connect(ctlF)
	if got := h2.readUint(s2, clusters.IDLevelControl, attrStartUpLevel); got != 77 {
		t.Fatalf("StartUpCurrentLevel %d after restart", got)
	}
}

func TestScenesRemovedWithFabric(t *testing.T) {
	h := newHarness(t)
	h.addLight()
	_, case1 := h.commission()
	const code2 = 12345678
	if res := h.invokeTimed(case1, ac(0), enhancedWindow(code2, []byte("multi-admin salt"), 1000, 0x123)); res.Status != im.Success {
		t.Fatalf("OpenCommissioningWindow: %+v", res)
	}
	_, case2 := h.commissionWith(code2, 2)
	for _, s := range []*exchange.Session{case1, case2} {
		if st := groupStatus(t, h.cmd(s, clusters.IDScenesManagement, cmdStoreScene, uint(0), uint(1))); st != im.Success {
			t.Fatalf("StoreScene: %#x", st)
		}
	}
	res := h.invoke(case2, im.CommandPath{Endpoint: 0, Cluster: clusters.IDOperationalCredentials, Command: 0x0A},
		func(w *tlv.Writer) { w.PutUint(tlv.ContextTag(0), 1) })
	if res.Status != im.Success {
		t.Fatalf("RemoveFabric: %+v", res)
	}
	h.w.Advance(time.Second)
	res = h.cmd(case2, clusters.IDScenesManagement, cmdSceneMembership, uint(0))
	if c, _ := field(t, res.Fields, 1).Uint(); c != 6 {
		t.Fatalf("fabric 2 capacity %d, want 6", c)
	}
	// FabricSceneInfo lists only fabric 2.
	r := h.attr(case2, lightEP, clusters.IDScenesManagement, 2)
	n := 0
	r.EnterContainer()
	for r.Next() == nil {
		n++
	}
	if n != 1 {
		t.Fatalf("FabricSceneInfo has %d entries", n)
	}
}
