package claude

import (
	"encoding/json"
	"os"
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

// change is the file edit RevokeDoc makes for one grant, without writing anything.
type change struct {
	File          string
	Before, After []byte
	Summary       string
}

func revokeChange(t *testing.T, env model.Env, g model.Grant) (change, error) {
	t.Helper()
	file := revokeFile(env, g)
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	after, summary, err := RevokeDoc(env, g, before)
	return change{File: file, Before: before, After: after, Summary: summary}, err
}

func TestRevokeDoc(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})

	t.Run("rule", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeUser, "Read(~/notes/**)")
		ch, err := revokeChange(t, f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		if ch.File != g.Location.File || ch.Summary == "" {
			t.Fatalf("change = %+v", ch)
		}
		var before, after struct {
			Permissions struct{ Allow []string }
		}
		json.Unmarshal(ch.Before, &before)
		json.Unmarshal(ch.After, &after)
		if !reflect.DeepEqual(after.Permissions.Allow, []string{"Bash(npm test:*)", "mcp__srv"}) || len(before.Permissions.Allow) != 4 {
			t.Errorf("allow before %q after %q", before.Permissions.Allow, after.Permissions.Allow)
		}
		// Only the removed lines differ.
		if strings.Count(string(ch.Before), "\n") != strings.Count(string(ch.After), "\n")+2 {
			t.Errorf("after:\n%s", ch.After)
		}
	})

	t.Run("project rule", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeProject, "Edit(/src/**)")
		ch, err := revokeChange(t, f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"permissions":{"allow":["Bash(git status:*)"]}}`; string(ch.After) != want {
			t.Errorf("after = %s", ch.After)
		}
	})

	t.Run("trust", func(t *testing.T) {
		g := find(t, rep, model.KindTrust, model.ScopeUser, f.desk)
		ch, err := revokeChange(t, f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		if ch.File != f.env.ClaudeJSON {
			t.Errorf("file = %s", ch.File)
		}
		old := decodeAny(t, ch.Before).(map[string]any)
		now := decodeAny(t, ch.After).(map[string]any)
		old["projects"].(map[string]any)[f.desk].(map[string]any)["hasTrustDialogAccepted"] = false
		if !reflect.DeepEqual(old, now) {
			t.Errorf("only hasTrustDialogAccepted of that folder may change")
		}
		if !strings.Contains(ch.Summary, f.desk) {
			t.Errorf("summary = %q", ch.Summary)
		}
	})

	t.Run("legacy", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeLegacy, "Bash(ls:*)")
		ch, err := revokeChange(t, f.env, g)
		if err != nil {
			t.Fatal(err)
		}
		now := decodeAny(t, ch.After).(map[string]any)
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
			if ch, err := revokeChange(t, f.env, g); err == nil || ch.After != nil {
				t.Errorf("%s: want an error, got %v", name, ch)
			}
		}
	})

	t.Run("rule already removed", func(t *testing.T) {
		g := find(t, rep, model.KindRule, model.ScopeUser, "mcp__srv")
		g.Value = "mcp__other"
		if _, err := revokeChange(t, f.env, g); err == nil {
			t.Error("want an error when the rule is not in the file")
		}
	})
}
