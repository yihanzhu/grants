package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
	"github.com/yihanzhu/grants/internal/store"
)

// Tests for the rule "a grant is gone only when the file that held it was read
// without it, or no longer exists". Each runs the real adapters over a synthetic home.

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// bothHome is a fake home where Claude Code and Codex both exist.
func bothHome(t *testing.T) model.Env {
	t.Helper()
	env := codexHome(t, nil, nil)
	if err := os.MkdirAll(env.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return env
}

func runAt(t *testing.T, env model.Env, d string) []model.Grant {
	t.Helper()
	env.Now = day(d)
	res, err := Run(env, scan.Options{NoCache: true})
	if err != nil {
		t.Fatal(err)
	}
	return res.Grants
}

func has(gs []model.Grant, value string, status model.Status) bool {
	for _, g := range gs {
		if g.Value == value && g.Status == status {
			return true
		}
	}
	return false
}

func noGone(t *testing.T, gs []model.Grant) {
	t.Helper()
	for _, g := range gs {
		if g.Status == model.StatusGone {
			t.Errorf("%s %q is reported gone, but nothing was read that shows its removal", g.Kind, g.Value)
		}
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
}

func lockDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
}

func codexProject(t *testing.T, env model.Env, proj string) {
	t.Helper()
	write(t, filepath.Join(proj, ".codex", "rules", "p.rules"), `prefix_rule(pattern=["projcmd"], decision="allow")`+"\n")
	write(t, filepath.Join(env.CodexHome, "config.toml"), "[projects.\""+proj+"\"]\ntrust_level = \"trusted\"\n")
}

func TestCodexBlockedProjectFolderIsNotGone(t *testing.T) {
	skipIfRoot(t)
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	codexProject(t, env, proj)
	first := runAt(t, env, "2026-10-01")
	if !has(first, "projcmd", model.StatusActive) {
		t.Fatalf("run 1 grants = %+v", first)
	}
	// macOS privacy blocks the project's .codex folder. Its rule key ends with the
	// rules file path, which no prefix list could name.
	lockDir(t, filepath.Join(proj, ".codex"))
	second := runAt(t, env, "2026-10-08")
	noGone(t, second)
	if !has(second, proj, model.StatusActive) {
		t.Errorf("the trust is still active: %+v", second)
	}
}

func TestCodexUnparsableConfigIsNotGone(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	codexProject(t, env, proj)
	write(t, filepath.Join(env.CodexHome, "rules", "default.rules"), `prefix_rule(pattern=["usercmd"], decision="allow")`+"\n")
	runAt(t, env, "2026-10-01")

	// With no readable config no project is trusted, so no project rules file is visited.
	write(t, filepath.Join(env.CodexHome, "config.toml"), "[projects\n")
	second := runAt(t, env, "2026-10-08")
	noGone(t, second)
	if !has(second, "usercmd", model.StatusActive) {
		t.Errorf("the user rule is still active: %+v", second)
	}

	// Once the config parses again, nothing changed.
	codexProject(t, env, proj)
	noGone(t, runAt(t, env, "2026-10-09"))
}

func claudeProject(t *testing.T, env model.Env, proj string) string {
	t.Helper()
	settings := filepath.Join(proj, ".claude", "settings.json")
	write(t, settings, `{"permissions":{"allow":["Bash(make:*)"]}}`)
	write(t, env.ClaudeJSON, `{"projects":{"`+proj+`":{"hasTrustDialogAccepted":true}}}`)
	return settings
}

func TestClaudeProjectRulesWithUnreadableClaudeJSONAreNotGone(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	claudeProject(t, env, proj)
	first := runAt(t, env, "2026-10-01")
	if !has(first, "Bash(make:*)", model.StatusActive) || !has(first, proj, model.StatusActive) {
		t.Fatalf("run 1 grants = %+v", first)
	}
	// ~/.claude.json holds the project list. Without it the project's settings file
	// is not found, and the trust cannot be checked.
	write(t, env.ClaudeJSON, `{"projects": {`)
	noGone(t, runAt(t, env, "2026-10-08"))
}

func TestClaudeRuleRemovedFromReadableFileIsGone(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	settings := claudeProject(t, env, proj)
	runAt(t, env, "2026-10-01")
	write(t, settings, `{"permissions":{"allow":[]}}`)
	second := runAt(t, env, "2026-10-08")
	if !has(second, "Bash(make:*)", model.StatusGone) {
		t.Errorf("a rule deleted from a file that was read must be gone: %+v", second)
	}
	if !has(second, proj, model.StatusActive) {
		t.Errorf("the trust is untouched: %+v", second)
	}
}

func TestClaudeRemovalNotHiddenByGoneCopyElsewhere(t *testing.T) {
	env := bothHome(t)
	// A user settings backup holds the same rule, so the adapter reports a gone copy
	// for the user file. The project file losing its copy is a separate removal.
	write(t, filepath.Join(env.ClaudeDir, "settings.json"), `{"permissions":{"allow":[]}}`)
	write(t, filepath.Join(env.ClaudeDir, "settings.json.bak"), `{"permissions":{"allow":["Bash(make:*)"]}}`)
	proj := filepath.Join(t.TempDir(), "proj")
	settings := claudeProject(t, env, proj)
	runAt(t, env, "2026-10-01")
	write(t, settings, `{"permissions":{"allow":[]}}`)
	n := 0
	for _, g := range runAt(t, env, "2026-10-08") {
		if g.Value == "Bash(make:*)" && g.Status == model.StatusGone {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want the user-file copy and the project removal both gone, got %d", n)
	}
}

func TestClaudeDeletedSettingsFileMakesItsRulesGone(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	claudeProject(t, env, proj)
	local := filepath.Join(proj, ".claude", "settings.local.json")
	write(t, local, `{"permissions":{"allow":["Bash(lint:*)"]}}`)
	runAt(t, env, "2026-10-01")
	if err := os.Remove(local); err != nil {
		t.Fatal(err)
	}
	second := runAt(t, env, "2026-10-08")
	if !has(second, "Bash(lint:*)", model.StatusGone) {
		t.Errorf("a deleted settings file must make its rules gone: %+v", second)
	}
	if !has(second, "Bash(make:*)", model.StatusActive) {
		t.Errorf("rules in the other file stay active: %+v", second)
	}
}

func TestClaudeTrustRemovedFromReadableClaudeJSONIsGone(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	claudeProject(t, env, proj)
	runAt(t, env, "2026-10-01")
	write(t, env.ClaudeJSON, `{"projects":{"`+proj+`":{"hasTrustDialogAccepted":false}}}`)
	if second := runAt(t, env, "2026-10-08"); !has(second, proj, model.StatusGone) {
		t.Errorf("trust turned off in a file that was read must be gone: %+v", second)
	}
}

func TestUndiscoveredButPresentFolderIsNotGone(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	settings := claudeProject(t, env, proj)
	runAt(t, env, "2026-10-01")
	// ~/.claude.json no longer lists the project and no history names it, so this run
	// never looks at the folder. Its settings file is still there.
	write(t, env.ClaudeJSON, `{"projects":{}}`)
	second := runAt(t, env, "2026-10-08")
	if has(second, "Bash(make:*)", model.StatusGone) {
		t.Errorf("the rule is still in %s: %+v", settings, second)
	}
	// ~/.claude.json was read and holds no trust now, so that grant is gone.
	if !has(second, proj, model.StatusGone) {
		t.Errorf("trust removed from the project list must be gone: %+v", second)
	}
}

func TestSecondRunInfersNothingNew(t *testing.T) {
	env := bothHome(t)
	proj := filepath.Join(t.TempDir(), "proj")
	claudeProject(t, env, proj)
	codexProject(t, env, filepath.Join(t.TempDir(), "cx"))
	runAt(t, env, "2026-10-01")
	count := func(gs []model.Grant) (n int) {
		for _, g := range gs {
			if g.Status == model.StatusGone {
				n++
			}
		}
		return
	}
	a := count(runAt(t, env, "2026-10-02"))
	b := count(runAt(t, env, "2026-10-03"))
	if a != 0 || b != 0 {
		t.Errorf("gone grants after unchanged runs: %d, %d", a, b)
	}
}

// goneFromStore unit cases: the rules that keep it from adding duplicates or guessing.

func seen(agent model.Agent, kind model.Kind, value, file string) *store.Seen {
	return &store.Seen{Agent: agent, Kind: kind, Value: value, File: file, First: day("2026-09-01"), Last: day("2026-09-01")}
}

func TestGoneFromStoreRules(t *testing.T) {
	dir := t.TempDir()
	exists := filepath.Join(dir, "a.rules")
	write(t, exists, "")
	other := filepath.Join(dir, "b.rules")
	write(t, other, "")
	missing := filepath.Join(dir, "missing.rules")
	e := env()
	e.Now = day("2026-09-10")

	cases := []struct {
		name    string
		seen    *store.Seen
		reports []model.Report
		want    bool
	}{
		{"read file without the grant", seen(model.Codex, model.KindRule, "x", exists),
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{exists}}}, true},
		{"file that no longer exists", seen(model.Codex, model.KindRule, "x", missing),
			[]model.Report{{Agent: model.Codex, Found: true}}, true},
		{"file exists but was not read", seen(model.Codex, model.KindRule, "x", exists),
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{other}}}, false},
		{"another agent read it", seen(model.Codex, model.KindRule, "x", exists),
			[]model.Report{{Agent: model.Codex, Found: true}, {Agent: model.ClaudeCode, Found: true, Read: []string{exists}}}, false},
		{"stored without a file", seen(model.Codex, model.KindRule, "x", ""),
			[]model.Report{{Agent: model.Codex, Found: true}}, false},
		{"file path not clean", seen(model.Codex, model.KindRule, "x", exists),
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{dir + "/./a.rules"}}}, true},
		{"agent not found", seen(model.Codex, model.KindRule, "x", missing),
			[]model.Report{{Agent: model.Codex, Found: false}}, false},
		{"adapter already reports it gone", seen(model.Codex, model.KindRule, "x", missing),
			[]model.Report{{Agent: model.Codex, Found: true, Grants: []model.Grant{{Key: "other", Agent: model.Codex, Kind: model.KindRule, Value: "x", Status: model.StatusGone}}}}, false},
		{"adapter reports it unknown", seen(model.Codex, model.KindRule, "x", missing),
			[]model.Report{{Agent: model.Codex, Found: true, Grants: []model.Grant{{Key: "other", Agent: model.Codex, Kind: model.KindRule, Value: "x", Status: model.StatusUnknown}}}}, false},
		{"same rule is active in the same file", seen(model.Codex, model.KindRule, "x", exists),
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{exists}, Grants: []model.Grant{{Key: "other", Agent: model.Codex, Kind: model.KindRule, Value: "x", Status: model.StatusActive, Location: model.Location{File: exists}}}}}, false},
		{"same rule is active in another file", seen(model.Codex, model.KindRule, "x", exists),
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{exists}, Grants: []model.Grant{{Key: "other", Agent: model.Codex, Kind: model.KindRule, Value: "x", Status: model.StatusActive, Location: model.Location{File: other}}}}}, true},
		{"claude: a gone copy from another file does not hide a removal", seen(model.ClaudeCode, model.KindRule, "Bash(x)", exists),
			[]model.Report{{Agent: model.ClaudeCode, Found: true, Read: []string{exists}, Grants: []model.Grant{{Key: "other", Agent: model.ClaudeCode, Kind: model.KindRule, Value: "Bash(x)", Status: model.StatusGone}}}}, true},
		{"codex: history in another project does not hide a removal", &store.Seen{Agent: model.Codex, Kind: model.KindRule, Value: "x", File: exists, Project: "/p1", First: day("2026-09-01"), Last: day("2026-09-01")},
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{exists}, Grants: []model.Grant{{Key: "other", Agent: model.Codex, Kind: model.KindRule, Value: "x", Project: "/p2", Status: model.StatusGone}}}}, true},
		{"codex: history in the same project covers it", &store.Seen{Agent: model.Codex, Kind: model.KindRule, Value: "x", File: exists, Project: "/p1", First: day("2026-09-01"), Last: day("2026-09-01")},
			[]model.Report{{Agent: model.Codex, Found: true, Read: []string{exists}, Grants: []model.Grant{{Key: "other", Agent: model.Codex, Kind: model.KindRule, Value: "x", Project: "/p1", Status: model.StatusUnknown}}}}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			obs := &store.Observations{Runs: []time.Time{day("2026-09-01"), day("2026-09-10")}, Grants: map[string]*store.Seen{"k": tt.seen}}
			out := merge(e, tt.reports, obs)
			got := false
			for _, g := range out {
				got = got || (g.Key == "k" && g.Status == model.StatusGone)
			}
			if got != tt.want {
				t.Errorf("gone = %v, want %v (grants %+v)", got, tt.want, out)
			}
		})
	}
}

func TestSeenRecordsFile(t *testing.T) {
	env := codexHome(t, []string{"alpha"}, nil)
	runAt(t, env, "2026-10-01")
	obs, err := store.Load(env.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range obs.Grants {
		if s.File != filepath.Join(env.CodexHome, "rules", "default.rules") {
			t.Errorf("seen = %+v, want the rules file", s)
		}
	}
	if len(obs.Grants) != 1 {
		t.Errorf("grants = %d", len(obs.Grants))
	}
}
