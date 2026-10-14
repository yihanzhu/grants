package revoke

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
)

// All fixtures are synthetic and live under t.TempDir().

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func claudeRule(id, file, value string) model.Grant {
	return model.Grant{
		ID: id, Key: "claude-code|rule|" + file + "|" + value, Agent: model.ClaudeCode, Kind: model.KindRule, Value: value,
		Scope: model.ScopeUser, Status: model.StatusActive, Revocable: true, Location: model.Location{File: file},
		RevokeNote: "Claude Code applies it on the next tool call.",
	}
}

func codexRule(id, file string, pattern ...string) model.Grant {
	p := make([][]string, len(pattern))
	for i, t := range pattern {
		p[i] = []string{t}
	}
	return model.Grant{
		ID: id, Agent: model.Codex, Kind: model.KindRule, Value: strings.Join(pattern, " "), Pattern: p, Tool: "exec",
		Scope: model.ScopeUser, Status: model.StatusActive, Revocable: true, Location: model.Location{File: file},
		RevokeNote: "Restart Codex to apply.",
	}
}

func TestChainClaudeRulesInOneFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "settings.json")
	write(t, file, "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(a:*)\",\n      \"Bash(b:*)\",\n      \"Bash(c:*)\",\n      \"Bash(d:*)\"\n    ]\n  }\n}\n")
	env := model.Env{Home: dir}
	grants := []model.Grant{claudeRule("aaaa111", file, "Bash(b:*)"), claudeRule("bbbb222", file, "Bash(d:*)")}

	changes, items, err := Plan(env, grants)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || len(items) != 2 {
		t.Fatalf("changes=%d items=%d, want 1 and 2", len(changes), len(items))
	}
	var got struct{ Permissions struct{ Allow []string } }
	if err := json.Unmarshal(changes[0].After, &got); err != nil {
		t.Fatalf("after is not JSON: %v\n%s", err, changes[0].After)
	}
	if want := []string{"Bash(a:*)", "Bash(c:*)"}; !reflect.DeepEqual(got.Permissions.Allow, want) {
		t.Errorf("allow = %q, want %q", got.Permissions.Allow, want)
	}
	if changes[0].GrantID != "aaaa111,bbbb222" {
		t.Errorf("grant ids = %q", changes[0].GrantID)
	}
	if lines := strings.Split(changes[0].Summary, "\n"); len(lines) != 2 || !strings.Contains(lines[0], "Bash(b:*)") || !strings.Contains(lines[1], "Bash(d:*)") {
		t.Errorf("summary = %q", changes[0].Summary)
	}
	if string(changes[0].Before) != read(t, file) {
		t.Error("Before must be the file as it is now")
	}
	for _, it := range items {
		if it.File != file || it.Summary == "" || it.Note != "Claude Code applies it on the next tool call." || len(it.Diff) == 0 {
			t.Errorf("item = %+v", it)
		}
	}
	// The second item's diff is computed on the document after the first removal.
	if joined := strings.Join(items[1].Diff, "\n"); !strings.Contains(joined, "Bash(d:*)") || strings.Contains(joined, "Bash(b:*)") {
		t.Errorf("second diff = %q", joined)
	}
}

func TestChainClaudeJSONTrustAndLegacy(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".claude.json")
	write(t, file, `{"firstStartTime":"2026-01-01T00:00:00Z","projects":{"/work/a":{"hasTrustDialogAccepted":true,"allowedTools":["Bash(ls:*)","Bash(pwd:*)"]},"/work/b":{"hasTrustDialogAccepted":true}}}`)
	env := model.Env{Home: dir, ClaudeJSON: file}

	trust := func(id, p string) model.Grant {
		return model.Grant{ID: id, Agent: model.ClaudeCode, Kind: model.KindTrust, Value: p, Scope: model.ScopeUser, Status: model.StatusActive, Revocable: true}
	}
	legacy := claudeRule("cccc333", file, "Bash(ls:*)")
	legacy.Scope, legacy.Project = model.ScopeLegacy, "/work/a"

	// No Location.File on the trust grants: revoke finds ~/.claude.json itself.
	changes, items, err := Plan(env, []model.Grant{trust("tttt111", "/work/a"), trust("tttt222", "/work/b"), legacy})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || len(items) != 3 || changes[0].File != file {
		t.Fatalf("changes=%v items=%d", changes, len(items))
	}
	var before, after map[string]any
	json.Unmarshal(changes[0].Before, &before)
	if err := json.Unmarshal(changes[0].After, &after); err != nil {
		t.Fatal(err)
	}
	proj := func(m map[string]any, p string) map[string]any {
		return m["projects"].(map[string]any)[p].(map[string]any)
	}
	proj(before, "/work/a")["hasTrustDialogAccepted"] = false
	proj(before, "/work/b")["hasTrustDialogAccepted"] = false
	proj(before, "/work/a")["allowedTools"] = []any{"Bash(pwd:*)"}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("after = %v\nwant     %v", after, before)
	}
}

func TestChainCodexRules(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rules", "default.rules")
	src := "# my rules\nprefix_rule(pattern=[\"git\", \"push\"], decision=\"allow\")\nprefix_rule(pattern=[\"npm\", \"test\"], decision=\"allow\")\nprefix_rule(pattern=[\"make\"], decision=\"allow\")\nprefix_rule(pattern=[\"rm\"], decision=\"forbidden\")\n"
	write(t, file, src)
	env := model.Env{CodexHome: dir}

	changes, items, err := Plan(env, []model.Grant{codexRule("rrrr111", file, "git", "push"), codexRule("rrrr222", file, "make")})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || len(items) != 2 {
		t.Fatalf("changes=%d items=%d", len(changes), len(items))
	}
	want := "# my rules\nprefix_rule(pattern=[\"npm\", \"test\"], decision=\"allow\")\nprefix_rule(pattern=[\"rm\"], decision=\"forbidden\")\n"
	if string(changes[0].After) != want {
		t.Errorf("after =\n%s\nwant\n%s", changes[0].After, want)
	}
	if got := strings.Join(items[0].Diff, "\n"); !strings.HasPrefix(got, "- prefix_rule(") || !strings.Contains(got, `"push"`) {
		t.Errorf("diff = %q", got)
	}
}

func TestChainCodexTrust(t *testing.T) {
	dir := t.TempDir()
	here, gone := filepath.Join(dir, "work", "here"), filepath.Join(dir, "work", "gone")
	if err := os.MkdirAll(here, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, ".codex", "config.toml")
	write(t, cfg, "model = \"x\"\n\n[projects.\""+here+"\"]\ntrust_level = \"trusted\"\n\n[projects.\""+gone+"\"]\ntrust_level = \"trusted\"\n\n[other]\nkey = 1\n")
	env := model.Env{CodexHome: filepath.Join(dir, ".codex")}
	trust := func(id, p string) model.Grant {
		return model.Grant{ID: id, Agent: model.Codex, Kind: model.KindTrust, Value: p, Scope: model.ScopeUser, Status: model.StatusActive, Revocable: true, Location: model.Location{File: cfg}}
	}

	changes, items, err := Plan(env, []model.Grant{trust("tttt111", here), trust("tttt222", gone)})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || len(items) != 2 {
		t.Fatalf("changes=%d items=%d", len(changes), len(items))
	}
	var doc map[string]any
	if _, err := toml.Decode(string(changes[0].After), &doc); err != nil {
		t.Fatalf("after is not TOML: %v\n%s", err, changes[0].After)
	}
	projects := doc["projects"].(map[string]any)
	if got := projects[here].(map[string]any)["trust_level"]; got != "untrusted" {
		t.Errorf("existing folder trust_level = %v, want untrusted", got)
	}
	if _, ok := projects[gone]; ok {
		t.Error("the missing folder's table should be removed")
	}
	if doc["model"] != "x" || doc["other"].(map[string]any)["key"] != int64(1) {
		t.Errorf("other settings changed: %v", doc)
	}
	if !strings.Contains(items[1].Summary, "no longer exists") {
		t.Errorf("summary = %q", items[1].Summary)
	}
}

func TestSeveralFilesGetOneChangeEach(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	write(t, a, `{"permissions":{"allow":["x","y"]}}`)
	write(t, b, `{"permissions":{"allow":["x","y"]}}`)
	changes, items, err := Plan(model.Env{}, []model.Grant{claudeRule("1111111", a, "x"), claudeRule("2222222", b, "x"), claudeRule("3333333", a, "y")})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || len(items) != 3 {
		t.Fatalf("changes=%d items=%d", len(changes), len(items))
	}
	if changes[0].File != a || changes[1].File != b {
		t.Errorf("files = %s, %s; want the order of first appearance", changes[0].File, changes[1].File)
	}
	if string(changes[0].After) != `{"permissions":{"allow":[]}}` || string(changes[1].After) != `{"permissions":{"allow":["y"]}}` {
		t.Errorf("after = %s | %s", changes[0].After, changes[1].After)
	}
}

func TestSymlinkedFilesAreOneFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "link.json")
	write(t, real, `{"permissions":{"allow":["x","y"]}}`)
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks not available")
	}
	changes, _, err := Plan(model.Env{}, []model.Grant{claudeRule("1111111", real, "x"), claudeRule("2222222", link, "y")})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || string(changes[0].After) != `{"permissions":{"allow":[]}}` {
		t.Fatalf("changes = %+v", changes)
	}
}

func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "settings.json")
	write(t, file, `{"permissions":{"allow":["x"]}}`)
	good := claudeRule("good111", file, "x")

	gone := claudeRule("gone111", file, "x")
	gone.Status = model.StatusGone
	unknown := claudeRule("unkn111", file, "x")
	unknown.Status = model.StatusUnknown
	managed := claudeRule("mana111", file, "x")
	managed.Scope, managed.Revocable, managed.RevokeNote = model.ScopeManaged, false, "Set by your organization."
	notRevocable := claudeRule("nrev111", file, "x")
	notRevocable.Revocable, notRevocable.RevokeNote = false, "because"
	missingValue := claudeRule("miss111", file, "not-there")
	missingFile := claudeRule("file111", filepath.Join(dir, "none.json"), "x")
	noFile := codexRule("nofi111", "", "ls")

	tests := []struct {
		name string
		g    model.Grant
		want string
	}{
		{"gone", gone, "already removed"},
		{"unknown", unknown, "cannot be revoked now"},
		{"managed", managed, "organization"},
		{"not revocable", notRevocable, "because"},
		{"rule not in file", missingValue, "no longer in"},
		{"file missing", missingFile, "cannot read"},
		{"no file", noFile, "has no file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes, items, err := Plan(model.Env{}, []model.Grant{good, tt.g})
			if err == nil || changes != nil || items != nil {
				t.Fatalf("want an error and no plan, got changes=%v items=%v err=%v", changes, items, err)
			}
			if !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), tt.g.ID) {
				t.Errorf("error = %q, want it to name the grant and say %q", err, tt.want)
			}
		})
	}

	t.Run("PlanEach keeps the good ones", func(t *testing.T) {
		changes, items, skipped := PlanEach(model.Env{}, []model.Grant{gone, good, managed})
		if len(changes) != 1 || len(items) != 1 || items[0].Grant.ID != "good111" || len(skipped) != 2 {
			t.Fatalf("changes=%d items=%d skipped=%d", len(changes), len(items), len(skipped))
		}
	})
	t.Run("every grant of a file skipped leaves no change", func(t *testing.T) {
		changes, items, skipped := PlanEach(model.Env{}, []model.Grant{gone})
		if len(changes) != 0 || len(items) != 0 || len(skipped) != 1 {
			t.Fatalf("changes=%d items=%d skipped=%d", len(changes), len(items), len(skipped))
		}
	})
	t.Run("a failed grant does not damage the chain", func(t *testing.T) {
		two := claudeRule("two1111", file, "x")
		changes, _, skipped := PlanEach(model.Env{}, []model.Grant{good, two}) // the second x is already gone
		if len(skipped) != 1 || len(changes) != 1 || string(changes[0].After) != `{"permissions":{"allow":[]}}` {
			t.Fatalf("skipped=%d changes=%v", len(skipped), changes)
		}
	})
}

func TestPlanThenApplyThenUndo(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "settings.json")
	orig := "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(a:*)\",\n      \"Bash(b:*)\"\n    ]\n  }\n}\n"
	write(t, file, orig)
	changes, _, err := Plan(model.Env{}, []model.Grant{claudeRule("aaaa111", file, "Bash(a:*)")})
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if _, err := edit.Apply(state, now, changes); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, file), "Bash(a:*)") {
		t.Fatal("rule still in the file")
	}
	if _, err := edit.Undo(state, now, false); err != nil {
		t.Fatal(err)
	}
	if read(t, file) != orig {
		t.Errorf("file after undo = %q", read(t, file))
	}
}

func TestDiff(t *testing.T) {
	t.Run("redacts secrets", func(t *testing.T) {
		d := diff([]byte("a\nBash(curl -H 'Authorization: Bearer abcdefghijklmnop' x)\nb\n"), []byte("a\nb\n"))
		if len(d) != 1 || strings.Contains(d[0], "abcdefghijklmnop") || !strings.HasPrefix(d[0], "- ") {
			t.Errorf("diff = %q", d)
		}
	})
	t.Run("clips a long list", func(t *testing.T) {
		var a, b []string
		for i := range 20 {
			a = append(a, "line"+string(rune('a'+i)))
		}
		d := diff([]byte(strings.Join(a, "\n")), []byte(strings.Join(b, "\n")))
		if len(d) != maxDiffLines || !strings.Contains(d[len(d)-1], "more changed lines") {
			t.Errorf("diff = %q", d)
		}
	})
	t.Run("one long line shows the changed span", func(t *testing.T) {
		pad := strings.Repeat("x", 5000)
		before := `{"a":"` + pad + `","t":true,"b":"` + pad + `"}`
		after := `{"a":"` + pad + `","t":false,"b":"` + pad + `"}`
		d := diff([]byte(before), []byte(after))
		if len(d) != 2 || !strings.Contains(d[0], "true") || !strings.Contains(d[1], "false") || len(d[0]) > 200 {
			t.Errorf("diff = %q", d)
		}
	})
	t.Run("multi-byte text stays valid", func(t *testing.T) {
		pad := strings.Repeat("é", 300)
		d := diff([]byte(pad+"1"+pad), []byte(pad+"2"+pad))
		for _, l := range d {
			if !bytes.Equal([]byte(l), []byte(strings.ToValidUTF8(l, ""))) {
				t.Errorf("invalid UTF-8 in %q", l)
			}
		}
	})
}
