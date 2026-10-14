package claude

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

func decodeAny(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return v
}

func TestPlanRevoke(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})

	t.Run("rule", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeUser, "Read(~/notes/**)")
		ch, err := PlanRevoke(f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		if len(ch) != 1 || ch[0].File != g.Location.File || ch[0].GrantID != g.ID || ch[0].Summary == "" {
			t.Fatalf("changes = %+v", ch)
		}
		var before, after struct {
			Permissions struct{ Allow []string }
		}
		json.Unmarshal(ch[0].Before, &before)
		json.Unmarshal(ch[0].After, &after)
		if !reflect.DeepEqual(after.Permissions.Allow, []string{"Bash(npm test:*)", "mcp__srv"}) || len(before.Permissions.Allow) != 4 {
			t.Errorf("allow before %q after %q", before.Permissions.Allow, after.Permissions.Allow)
		}
		// Only the removed lines differ.
		if strings.Count(string(ch[0].Before), "\n") != strings.Count(string(ch[0].After), "\n")+2 {
			t.Errorf("after:\n%s", ch[0].After)
		}
	})

	t.Run("project rule", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeProject, "Edit(/src/**)")
		ch, err := PlanRevoke(f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"permissions":{"allow":["Bash(git status:*)"]}}`; string(ch[0].After) != want {
			t.Errorf("after = %s", ch[0].After)
		}
	})

	t.Run("trust", func(t *testing.T) {
		g := find(t, rep, model.KindTrust, model.ScopeUser, f.desk)
		ch, err := PlanRevoke(f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		if ch[0].File != f.env.ClaudeJSON {
			t.Errorf("file = %s", ch[0].File)
		}
		old := decodeAny(t, ch[0].Before).(map[string]any)
		now := decodeAny(t, ch[0].After).(map[string]any)
		old["projects"].(map[string]any)[f.desk].(map[string]any)["hasTrustDialogAccepted"] = false
		if !reflect.DeepEqual(old, now) {
			t.Errorf("only hasTrustDialogAccepted of that folder may change")
		}
		if !strings.Contains(ch[0].Summary, f.desk) {
			t.Errorf("summary = %q", ch[0].Summary)
		}
	})

	t.Run("legacy", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeLegacy, "Bash(ls:*)")
		ch, err := PlanRevoke(f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		now := decodeAny(t, ch[0].After).(map[string]any)
		tools := now["projects"].(map[string]any)[f.proj].(map[string]any)["allowedTools"].([]any)
		if len(tools) != 0 {
			t.Errorf("allowedTools = %v", tools)
		}
	})

	t.Run("refused", func(t *testing.T) {
		managed := find(t, rep, model.KindRule, model.ScopeManaged, "Bash(echo:*)")
		gone := find(t, rep, model.KindRule, model.ScopeProject, "Bash(make:*)")
		cases := map[string]model.Grant{"managed": managed, "gone": gone}
		other := find(t, rep, model.KindRule, model.ScopeUser, "mcp__srv")
		other.Agent = model.Codex
		cases["other agent"] = other
		for name, g := range cases {
			if ch, err := PlanRevoke(f.env, g); err == nil || ch != nil {
				t.Errorf("%s: want an error, got %v", name, ch)
			}
		}
	})

	t.Run("rule already removed", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeUser, "mcp__srv")
		g.Value = "mcp__other"
		if _, err := PlanRevoke(f.env, g); err == nil {
			t.Error("want an error when the rule is not in the file")
		}
	})

	t.Run("file missing", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeUser, "mcp__srv")
		g.Location.File = f.home + "/nope/settings.json"
		if _, err := PlanRevoke(f.env, g); err == nil {
			t.Error("want an error for a missing file")
		}
	})
}
