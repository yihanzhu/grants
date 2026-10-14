package codex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

// fixture is a synthetic CODEX_HOME with rules, config, backups and sessions.
type fixture struct {
	env                                 model.Env
	app, missing, vault, dated, removed string
	userRules, projRules, managedRules  string
	configPath                          string
	rootBlocksVault                     bool
	backupTime                          time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	tmp := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = resolved
	}
	f := &fixture{}
	home := filepath.Join(tmp, "home")
	ch := filepath.Join(home, ".codex")
	f.env = model.Env{Home: home, CodexHome: ch, StateDir: filepath.Join(tmp, "state"), Now: at(30, 0, 0), UnusedAfter: 90 * 24 * time.Hour}
	f.app = filepath.Join(tmp, "work", "app")
	f.missing = filepath.Join(tmp, "work", "missing")
	f.vault = filepath.Join(tmp, "work", "vault")
	f.dated = filepath.Join(tmp, "work", "2026-03-12", "proj")
	f.removed = filepath.Join(tmp, "work", "removed")
	for _, d := range []string{f.app, f.vault, f.dated, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A folder macOS would not let us read: its .codex folder has no permissions.
	blocked := filepath.Join(f.vault, ".codex")
	if err := os.MkdirAll(filepath.Join(blocked, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	_, err := os.ReadDir(filepath.Join(blocked, "rules"))
	f.rootBlocksVault = err != nil

	f.configPath = filepath.Join(ch, "config.toml")
	writeFile(t, f.configPath, fmt.Sprintf(`model = "x"

# folders
[projects.%q]
trust_level = "trusted"

[projects.%q]
trust_level = "trusted"

[projects.%q]
trust_level = "trusted"

[projects.%q]
trust_level = "trusted"

[projects."/work/untrusted"]
trust_level = "untrusted"
`, f.app, f.missing, f.vault, f.dated))
	setTime(t, f.configPath, at(26, 0, 0))

	// A backup that still lists a folder the config has dropped.
	backup := f.configPath + ".bak-20260310-120000"
	writeFile(t, backup, fmt.Sprintf("[projects.%q]\ntrust_level = \"trusted\"\n\n[projects.%q]\ntrust_level = \"trusted\"\n", f.app, f.removed))
	f.backupTime = time.Date(2026, 3, 10, 12, 0, 0, 0, time.Local)
	// A backup with no stamp falls back to its modification time.
	writeFile(t, f.configPath+"~", fmt.Sprintf("[projects.%q]\ntrust_level = \"trusted\"\n", f.app))
	setTime(t, f.configPath+"~", at(20, 0, 0))

	f.userRules = filepath.Join(ch, "rules", "default.rules")
	writeFile(t, f.userRules, `prefix_rule(pattern=["git", "status"], decision="allow")
prefix_rule(pattern=["npm", "test"], decision="allow")
prefix_rule(pattern=["curl", "-s", "https://example.com/x"], decision="allow")
prefix_rule(pattern=["rm", "-rf"], decision="prompt")
prefix_rule(pattern=["make", "ship"], decision="allow")
prefix_rule(pattern=["npm", "test"], decision="allow")
prefix_rule(pattern=["oops)
`)
	setTime(t, f.userRules, at(25, 0, 0))

	f.projRules = filepath.Join(f.app, ".codex", "rules", "p.rules")
	writeFile(t, f.projRules, "prefix_rule(pattern=[\"make\", \"deploy\"], decision=\"allow\")\nprefix_rule(pattern=[\"git\", \"status\"])\n")
	setTime(t, f.projRules, at(26, 0, 0))

	f.managedRules = filepath.Join(tmp, "etc", "m.rules")
	writeFile(t, f.managedRules, "prefix_rule(pattern=[\"ls\"], decision=\"allow\")\n")
	old := managedRulesDir
	managedRulesDir = filepath.Dir(f.managedRules)
	t.Cleanup(func() { managedRulesDir = old })

	sess := func(day int, name string) string {
		return filepath.Join(ch, "sessions", "2026", "03", fmt.Sprintf("%02d", day), "rollout-"+name+".jsonl")
	}
	git := []string{"git", "status"}
	npm := []string{"npm", "test"}
	curl := []string{"curl", "-s", "https://example.com/x"}
	gone := []string{"docker", "system", "prune"}
	deploy := []string{"make", "deploy"}
	secret := []string{"secret-tool", "run"}

	(&rollout{}).meta(at(5, 10, 0), "/elsewhere", "cli").
		devSnapshot(at(5, 10, 1), git, gone).
		cmdItem(at(5, 10, 5), "u1", "completed", "npm", "test").
		write(t, sess(5, "s1"))
	(&rollout{}).meta(at(8, 10, 0), "/elsewhere", "cli").
		devSnapshot(at(8, 10, 1), git, gone).
		call(at(8, 10, 30), "exec_command", "e1", map[string]any{
			"cmd": "curl -s https://example.com/x", "sandbox_permissions": "require_escalated",
			"prefix_rule": curl, "justification": "check the status page",
		}).
		callOutput(at(8, 10, 31), "e1", "Chunk ID: 1").
		write(t, sess(8, "s2"))
	(&rollout{}).meta(at(12, 10, 0), "/elsewhere", "cli").
		worldState(at(12, 10, 1), git, npm, curl).
		cmdItem(at(12, 10, 5), "a1", "completed", "git", "status").
		cmdItem(at(12, 10, 6), "a2", "completed", "/bin/zsh", "-lc", "git status && git diff").
		cmdItem(at(12, 10, 7), "a3", "completed", "npm", "test").
		write(t, sess(12, "s3"))
	(&rollout{}).meta(at(13, 9, 0), f.app, "vscode").
		worldState(at(13, 9, 1), git, npm, curl).
		cmdItem(at(13, 9, 5), "b1", "completed", "make", "deploy").
		write(t, sess(13, "s3b"))
	(&rollout{}).meta(at(13, 11, 0), filepath.Join(f.dated, "sub"), "vscode").
		worldState(at(13, 11, 1), git, npm, curl).
		write(t, sess(13, "s7"))
	(&rollout{}).meta(at(14, 10, 0), "/elsewhere", "cli").
		worldState(at(14, 10, 1), git, npm, curl).
		write(t, sess(14, "s5"))
	(&rollout{}).meta(at(15, 10, 0), f.app, "vscode").
		worldState(at(15, 10, 1), git, npm, curl, deploy).
		cmdItem(at(15, 10, 5), "c1", "completed", "make", "deploy").
		noise(at(15, 12, 0)).
		write(t, sess(15, "s4"))
	(&rollout{}).meta(at(16, 10, 0), filepath.Join(f.vault, "notes"), "vscode").
		worldState(at(16, 10, 1), git, npm, curl, secret).
		write(t, sess(16, "s6"))
	// An archived session is read too.
	(&rollout{}).meta(at(17, 10, 0), "/elsewhere", "cli").
		worldState(at(17, 10, 1), git, npm, curl).
		write(t, filepath.Join(ch, "archived_sessions", "rollout-arch.jsonl"))
	// Files that are not rollouts are ignored.
	writeFile(t, filepath.Join(ch, "sessions", "2026", "03", "05", "notes.jsonl"), "{}\n")
	return f
}

func setTime(t *testing.T, path string, tm time.Time) {
	t.Helper()
	if err := os.Chtimes(path, tm, tm); err != nil {
		t.Fatal(err)
	}
}

func find(t *testing.T, rep model.Report, kind model.Kind, status model.Status, value string) model.Grant {
	t.Helper()
	for _, g := range rep.Grants {
		if g.Kind == kind && g.Status == status && g.Value == value {
			return g
		}
	}
	t.Fatalf("no %s %s grant %q in %d grants", status, kind, value, len(rep.Grants))
	return model.Grant{}
}

func sameTime(t *testing.T, name string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func TestCollectNotFound(t *testing.T) {
	rep := Collect(model.Env{CodexHome: filepath.Join(t.TempDir(), "nope")}, scan.Options{})
	if rep.Found || rep.Agent != model.Codex || len(rep.Grants) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

func TestCollectEmptyHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".codex")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	rep := Collect(model.Env{CodexHome: home}, scan.Options{})
	if !rep.Found || len(rep.Grants) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

func TestCollectRules(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{Workers: 2})
	if !rep.Found || rep.Agent != model.Codex {
		t.Fatalf("report = %+v", rep)
	}

	// git status: first seen in the first snapshot; nothing earlier to bound it.
	g := find(t, rep, model.KindRule, model.StatusActive, "git status")
	if g.Key != model.KeyCodexRule(`["git","status"]`) || g.ID != model.MakeID(g.Key) || g.Tool != "exec" || g.Scope != model.ScopeUser {
		t.Errorf("git status = %+v", g)
	}
	sameTime(t, "git status before", g.Granted.Before, at(5, 10, 1))
	if !g.Granted.After.IsZero() || g.Granted.Source != "Codex session snapshot" {
		t.Errorf("git status window = %+v", g.Granted)
	}
	if g.Location.File != f.userRules || g.Location.Line != 1 || g.Location.Pointer != "prefix_rule" || !g.Revocable || g.RevokeNote != "Restart Codex to apply." {
		t.Errorf("git status location/revoke = %+v %v %q", g.Location, g.Revocable, g.RevokeNote)
	}
	if !g.Usage.Known || g.Usage.Count != 2 || !g.Usage.Last.Equal(at(12, 10, 6)) || !g.Usage.Since.Equal(at(5, 10, 0)) {
		t.Errorf("git status usage = %+v", g.Usage)
	}

	// npm test: absent in the snapshot of day 8, present on day 12. The run on day 5
	// is before the window and does not count. The duplicate line makes one grant.
	g = find(t, rep, model.KindRule, model.StatusActive, "npm test")
	sameTime(t, "npm after", g.Granted.After, at(8, 10, 1))
	sameTime(t, "npm before", g.Granted.Before, at(12, 10, 1))
	if g.Usage.Count != 1 {
		t.Errorf("npm usage = %+v", g.Usage)
	}
	n := 0
	for _, x := range rep.Grants {
		if x.Value == "npm test" && x.Status == model.StatusActive {
			n++
		}
	}
	if n != 1 {
		t.Errorf("npm test appears %d times", n)
	}

	// curl: the escalation that ran inside the window tightens it.
	g = find(t, rep, model.KindRule, model.StatusActive, "curl -s https://example.com/x")
	sameTime(t, "curl after", g.Granted.After, at(8, 10, 1))
	sameTime(t, "curl before", g.Granted.Before, at(8, 10, 30))
	if g.Granted.Source != "approved when the agent asked" || !g.Granted.Approx {
		t.Errorf("curl window = %+v", g.Granted)
	}
	hasProposal := false
	for _, e := range g.Evidence {
		if e.What == "proposed" && strings.Contains(e.Detail, "status page") {
			hasProposal = true
		}
	}
	if !hasProposal {
		t.Errorf("curl evidence = %+v", g.Evidence)
	}
	for i := 1; i < len(g.Evidence); i++ {
		if g.Evidence[i].Time.Before(g.Evidence[i-1].Time) {
			t.Errorf("evidence not oldest first: %+v", g.Evidence)
		}
	}

	// make ship is in no snapshot: the file's modification time is the upper bound and
	// the latest session without it the lower bound.
	g = find(t, rep, model.KindRule, model.StatusActive, "make ship")
	sameTime(t, "ship before", g.Granted.Before, at(25, 0, 0))
	if g.Granted.After.Before(at(17, 10, 1)) { // macOS also gives the file's birth time
		t.Errorf("ship after = %v, want no earlier than the last session", g.Granted.After)
	}
	if g.Granted.Source != "rules file last changed" {
		t.Errorf("ship source = %q", g.Granted.Source)
	}

	// A prompt rule is not a grant.
	for _, x := range rep.Grants {
		if x.Value == "rm -rf" {
			t.Errorf("prompt rule listed as a grant: %+v", x)
		}
	}

	// Project rule: only sessions inside the folder are evidence, so the session
	// outside it on day 14 does not move the lower bound.
	g = find(t, rep, model.KindRule, model.StatusActive, "make deploy")
	if g.Scope != model.ScopeProject || g.Project != f.app || g.Location.File != f.projRules || !g.Revocable {
		t.Errorf("deploy = %+v", g)
	}
	sameTime(t, "deploy after", g.Granted.After, at(13, 9, 1))
	sameTime(t, "deploy before", g.Granted.Before, at(15, 10, 1))
	if g.Usage.Count != 2 { // both runs are after the last snapshot that lacked the rule
		t.Errorf("deploy usage = %+v", g.Usage)
	}

	// The same pattern in a project file gets its own key.
	dup := 0
	for _, x := range rep.Grants {
		if x.Value == "git status" && x.Scope == model.ScopeProject {
			dup++
			if x.Key != g.Key && x.Key != model.KeyCodexRule(`["git","status"]`)+"|"+f.projRules {
				t.Errorf("duplicate key = %q", x.Key)
			}
		}
	}
	if dup != 1 {
		t.Errorf("project git status grants = %d", dup)
	}

	// Managed rules are listed but not revocable.
	g = find(t, rep, model.KindRule, model.StatusActive, "ls")
	if g.Scope != model.ScopeManaged || g.Revocable || g.RevokeNote != "Set by your organization." {
		t.Errorf("managed = %+v", g)
	}

	// Gone rule: seen on days 5 and 8, missing from every later session.
	g = find(t, rep, model.KindRule, model.StatusGone, "docker system prune")
	if g.Revocable || g.RevokeNote != "Already removed" || g.Scope != model.ScopeUser {
		t.Errorf("gone = %+v", g)
	}
	sameTime(t, "gone last seen", g.LastSeen, at(8, 10, 1))
	sameTime(t, "gone before", g.Granted.Before, at(5, 10, 1))

	// A prefix seen only in a folder we could not read is unknown, not gone.
	if f.rootBlocksVault {
		g = find(t, rep, model.KindRule, model.StatusUnknown, "secret-tool run")
		if g.Revocable || g.RevokeNote != "Folder not readable" || g.Project != f.vault {
			t.Errorf("unknown = %+v", g)
		}
	}

	// Coverage and notes.
	if len(rep.Coverage) != 1 || rep.Coverage[0].Source != "Codex sessions" || rep.Coverage[0].Files != 9 {
		t.Errorf("coverage = %+v", rep.Coverage)
	}
	sameTime(t, "coverage from", rep.Coverage[0].From, at(5, 10, 0))
	sameTime(t, "coverage to", rep.Coverage[0].To, at(17, 10, 1))
	var texts []string
	for _, n := range rep.Notes {
		texts = append(texts, n.Text)
	}
	all := strings.Join(texts, "\n")
	if !strings.Contains(all, "1 statement in Codex rules files could not be parsed") {
		t.Errorf("notes = %q", all)
	}
	if f.rootBlocksVault && !strings.Contains(all, "1 trusted folder could not be read (macOS privacy). Give your terminal Full Disk Access to include their rules.") {
		t.Errorf("notes = %q", all)
	}
}

func TestCollectTrust(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})

	// app: the 3/10 backup lists it, so it was trusted by then; the first session is later.
	g := find(t, rep, model.KindTrust, model.StatusActive, f.app)
	if g.Key != model.KeyCodexTrust(f.app) || g.Scope != model.ScopeUser || !g.Revocable {
		t.Errorf("app = %+v", g)
	}
	sameTime(t, "app before", g.Granted.Before, f.backupTime)
	if g.Granted.Source != "config backup" {
		t.Errorf("app source = %q", g.Granted.Source)
	}
	if g.Location.File != f.configPath || g.Location.Line != 4 || g.Location.Pointer != fmt.Sprintf("projects.%q.trust_level", f.app) {
		t.Errorf("app location = %+v", g.Location)
	}
	if g.RevokeNote != `Sets trust_level to "untrusted". Restart Codex to apply.` {
		t.Errorf("app revoke note = %q", g.RevokeNote)
	}
	if !g.Usage.Known || g.Usage.Count != 2 || !g.Usage.Last.Equal(at(15, 12, 0)) {
		t.Errorf("app usage = %+v", g.Usage)
	}

	// dated: a day in the path is the lower bound, the first session the upper.
	g = find(t, rep, model.KindTrust, model.StatusActive, f.dated)
	sameTime(t, "dated after", g.Granted.After, time.Date(2026, 3, 12, 0, 0, 0, 0, time.Local))
	sameTime(t, "dated before", g.Granted.Before, at(13, 11, 0))
	if !g.Granted.Approx || g.Granted.Source != "first Codex session in this folder" {
		t.Errorf("dated window = %+v", g.Granted)
	}

	// missing folder: revoke removes the entry.
	g = find(t, rep, model.KindTrust, model.StatusActive, f.missing)
	if g.RevokeNote != "Removes the entry. Restart Codex to apply." {
		t.Errorf("missing revoke note = %q", g.RevokeNote)
	}
	if g.Usage.Count != 0 || !g.Usage.Known {
		t.Errorf("missing usage = %+v", g.Usage)
	}

	// A folder a backup trusted and the config dropped.
	g = find(t, rep, model.KindTrust, model.StatusGone, f.removed)
	if g.Revocable || g.RevokeNote != "Already removed" {
		t.Errorf("removed = %+v", g)
	}
	sameTime(t, "removed last seen", g.LastSeen, f.backupTime)

	for _, x := range rep.Grants {
		if x.Kind == model.KindTrust && x.Value == "/work/untrusted" {
			t.Error("an untrusted entry must not be a grant")
		}
	}
}

func TestCollectCacheGivesSameResult(t *testing.T) {
	f := newFixture(t)
	first := Collect(f.env, scan.Options{})
	if _, err := os.Stat(filepath.Join(f.env.StateDir, "cache-"+cacheName+".gob")); err != nil {
		t.Errorf("cache file not written: %v", err)
	}
	second := Collect(f.env, scan.Options{})
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Error("a warm run gave a different report")
	}
	noCache := Collect(f.env, scan.Options{NoCache: true})
	c, _ := json.Marshal(noCache)
	if string(a) != string(c) {
		t.Error("a run without cache gave a different report")
	}
}

func TestCollectBadFilesNeverPanic(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.configPath, "this is = not [valid toml\n")
	writeFile(t, filepath.Join(f.env.CodexHome, "rules", "bad.rules"), "\x00\xff((((\n")
	writeFile(t, filepath.Join(f.env.CodexHome, "sessions", "2026", "03", "05", "rollout-garbage.jsonl"), "not json\n{\n\x00\n")
	rep := Collect(f.env, scan.Options{})
	if !rep.Found {
		t.Fatal("not found")
	}
	var warned bool
	for _, n := range rep.Notes {
		if strings.Contains(n.Text, "config.toml") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no note about the bad config: %+v", rep.Notes)
	}
}
