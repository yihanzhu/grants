package claude

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
	"github.com/yihanzhu/grants/internal/timeline"
)

func TestDateGrantKeepsOnlyTheCurrentStretch(t *testing.T) {
	at := func(d int) time.Time { return time.Date(2026, 9, d, 12, 0, 0, 0, time.UTC) }
	obs := func(d int, present bool) timeline.Obs { return timeline.Obs{T: at(d), Present: present, Source: "s"} }

	// Present, removed, added again: the grant dates from the second stretch.
	r := dateGrant([]timeline.Obs{obs(1, false), obs(2, true), obs(3, false), obs(4, true)}, true)
	if !r.Granted.After.Equal(at(3)) || !r.Granted.Before.Equal(at(4)) {
		t.Errorf("re-added: %+v", r.Granted)
	}
	// A gone grant keeps its first appearance and last sighting.
	r = dateGrant([]timeline.Obs{obs(1, false), obs(2, true), obs(3, false), obs(4, true), obs(5, false)}, false)
	if !r.Granted.After.Equal(at(1)) || !r.Granted.Before.Equal(at(2)) || !r.LastSeen.Equal(at(4)) {
		t.Errorf("gone: %+v last %v", r.Granted, r.LastSeen)
	}
	// Active, but only seen absent: just a lower bound.
	r = dateGrant([]timeline.Obs{obs(1, false), obs(2, false)}, true)
	if !r.Granted.After.Equal(at(2)) || !r.Granted.Before.IsZero() {
		t.Errorf("lower bound: %+v", r.Granted)
	}
	// Nothing known.
	if r = dateGrant(nil, true); !r.Granted.After.IsZero() || !r.Granted.Before.IsZero() {
		t.Errorf("empty: %+v", r.Granted)
	}
}

func TestRuleObsDropsBirthAfterEarlierSighting(t *testing.T) {
	at := func(d int) time.Time { return time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC) }
	snaps := []snap{
		{T: at(1), Rules: map[string]bool{"r": true}, Source: srcHistory},
		{T: at(5) /* birth of the file as it is now */, Rules: map[string]bool{}, Source: srcBirth, Birth: true},
		{T: at(6), Rules: map[string]bool{"r": true, "late": true}, Source: srcLive},
	}
	if got := ruleObs(snaps, "r"); len(got) != 2 {
		t.Errorf("r: %d observations, want the birth dropped", len(got))
	}
	if got := ruleObs(snaps, "late"); len(got) != 3 {
		t.Errorf("late: %d observations, want the birth kept", len(got))
	}
	if got := usageCutoff(snaps, at(5)); !got.IsZero() {
		t.Errorf("a birth time must not cut off usage, got %v", got)
	}
	if got := usageCutoff(snaps, at(1)); !got.Equal(at(1)) {
		t.Errorf("cutoff = %v", got)
	}
}

func TestSiblingBackups(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "settings.json")
	writeFile(t, base, "{}")
	for _, n := range []string{"settings.json.bak-20260910-073709", "settings.json.backup", "settings.json~", "settings.json.bak-rename", "settings.json.orig", "settings.jsonx", "other.json.bak"} {
		writeFile(t, filepath.Join(dir, n), "{}")
	}
	if err := os.Mkdir(filepath.Join(dir, "settings.json.bak-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2026, 9, 11, 1, 2, 3, 0, time.UTC)
	setMtime(t, filepath.Join(dir, "settings.json.backup"), mt)
	got := map[string]time.Time{}
	for _, b := range siblingBackups(base) {
		got[filepath.Base(b.Path)] = b.T
	}
	if len(got) != 4 {
		t.Fatalf("backups = %v", got)
	}
	stamp, _ := time.ParseInLocation("20060102150405", "20260910073709", time.Local)
	if !got["settings.json.bak-20260910-073709"].Equal(stamp) {
		t.Errorf("stamped backup time = %v", got["settings.json.bak-20260910-073709"])
	}
	if !got["settings.json.backup"].Equal(mt) {
		t.Errorf("unstamped backup should use mtime, got %v", got["settings.json.backup"])
	}
	if siblingBackups(filepath.Join(dir, "nope", "settings.json")) != nil {
		t.Error("missing folder should give nothing")
	}
}

func TestClaudeJSONBackups(t *testing.T) {
	dir := t.TempDir()
	b := filepath.Join(dir, "backups")
	writeFile(t, filepath.Join(b, ".claude.json.backup."+strconv.FormatInt(ts("2026-10-01T00:00:00Z").UnixMilli(), 10)), `{"projects":{"/x":{"hasTrustDialogAccepted":true}},"oauthAccount":{"x":1}}`)
	writeFile(t, filepath.Join(b, ".claude.json.backup.notanumber"), `{}`)
	writeFile(t, filepath.Join(b, ".claude.json.corrupted.1700000000000"), `{}`)
	writeFile(t, filepath.Join(b, ".claude.json.backup.1700000000000"), `{broken`)
	got := claudeJSONBackups(dir)
	if len(got) != 1 || !got[0].Info.Projects["/x"].Trusted || !got[0].T.Equal(ts("2026-10-01T00:00:00Z")) {
		t.Errorf("backups = %+v", got)
	}
}

func TestReadFileStates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a"), "x")
	if _, st := readFile(filepath.Join(dir, "a")); st != stateOK {
		t.Error("existing file should be OK")
	}
	if _, st := readFile(filepath.Join(dir, "nope")); st != stateMissing {
		t.Error("absent file should be missing")
	}
	if _, st := readFile(filepath.Join(dir, "a", "child")); st != stateMissing {
		t.Error("a path below a file should be missing")
	}
	if _, st := readFile(dir); st != stateBlocked {
		t.Error("a folder cannot be read as a file")
	}
}

// git helpers for the committed-file test.
func runGit(t *testing.T, dir, when string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+dir, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestCollectCommittedProjectSettings(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	proj := filepath.Join(home, "repo")
	settings := filepath.Join(proj, ".claude", "settings.json")
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), `{}`)
	writeFile(t, filepath.Join(home, ".claude.json"), js(m{"projects": m{proj: m{"hasTrustDialogAccepted": false}}}))
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, proj, "2026-09-01T10:00:00Z", "init", "-q")
	writeFile(t, settings, `{"permissions":{"allow":["Bash(a:*)","Bash(c:*)"]}}`)
	runGit(t, proj, "2026-09-01T10:00:00Z", "add", ".")
	runGit(t, proj, "2026-09-01T10:00:00Z", "commit", "-q", "-m", "one")
	writeFile(t, settings, `{"permissions":{"allow":["Bash(a:*)","Bash(b:*)"]}}`)
	runGit(t, proj, "2026-09-05T10:00:00Z", "commit", "-q", "-am", "two")
	// A local file in the same folder is not tracked.
	writeFile(t, filepath.Join(proj, ".claude", "settings.local.json"), `{"permissions":{"allow":["Bash(d:*)"]}}`)

	env := model.Env{Home: home, ClaudeDir: filepath.Join(home, ".claude"), ClaudeJSON: filepath.Join(home, ".claude.json"), StateDir: filepath.Join(root, "state"), Now: time.Now()}
	rep := Collect(env, scan.Options{})

	a := find(t, rep, model.KindRule, model.ScopeProject, "Bash(a:*)")
	if !a.HasFlag(model.FlagCommitted) || a.RevokeNote != "Claude Code applies it on the next tool call. The change will show in git." {
		t.Errorf("a: flags %v note %q", a.Flags, a.RevokeNote)
	}
	sameTime(t, "a before", a.Granted.Before, ts("2026-09-01T10:00:00Z"))
	if !a.Granted.Approx || a.Granted.Source != srcGit {
		t.Errorf("a window = %+v", a.Granted)
	}
	b := find(t, rep, model.KindRule, model.ScopeProject, "Bash(b:*)")
	sameTime(t, "b after", b.Granted.After, ts("2026-09-01T10:00:00Z"))
	sameTime(t, "b before", b.Granted.Before, ts("2026-09-05T10:00:00Z"))
	c := find(t, rep, model.KindRule, model.ScopeProject, "Bash(c:*)")
	if c.Status != model.StatusGone {
		t.Errorf("c = %+v", c)
	}
	sameTime(t, "c last seen", c.LastSeen, ts("2026-09-01T10:00:00Z"))
	d := find(t, rep, model.KindRule, model.ScopeLocal, "Bash(d:*)")
	if d.HasFlag(model.FlagCommitted) {
		t.Error("an untracked local file is not committed")
	}
}
