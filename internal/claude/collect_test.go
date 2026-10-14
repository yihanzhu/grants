package claude

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

type fixture struct {
	env                                  model.Env
	home, claude, proj, gone, desk, hist string
	bare, bad, worktree, managed         string
	settingsMtime                        time.Time
}

// newFixture builds a fake home that exercises every source. All folders are made up.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{home: filepath.Join(root, "home")}
	f.claude = filepath.Join(f.home, ".claude")
	f.proj = filepath.Join(f.home, "work", "app")
	f.gone = filepath.Join(f.home, "work", "old") // never created
	f.desk = filepath.Join(f.home, "work", "desk")
	f.hist = filepath.Join(f.home, "work", "hist")
	f.bare = filepath.Join(f.home, "work", "bare")
	f.bad = filepath.Join(f.home, "work", "bad")
	f.worktree = filepath.Join(f.proj, ".claude", "worktrees", "w1")
	for _, d := range []string{f.proj, f.desk, f.hist, f.bare, f.bad, f.worktree} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.env = model.Env{
		Home: f.home, ClaudeDir: f.claude, ClaudeJSON: filepath.Join(f.home, ".claude.json"),
		StateDir: filepath.Join(root, "state"), Now: time.Now(), UnusedAfter: 90 * 24 * time.Hour,
	}
	f.managed = filepath.Join(root, "managed")
	old := managedRoots
	managedRoots = []string{f.managed}
	t.Cleanup(func() { managedRoots = old })
	// Settings files are "last changed" an hour ago, so they were born after the rules
	// they hold were first seen and the birth time must not date anything.
	f.settingsMtime = time.Now().Add(-time.Hour).Truncate(time.Second)

	writeFile(t, filepath.Join(f.managed, "managed-settings.json"), `{"permissions":{"allow":["Bash(echo:*)"]}}`)

	user := filepath.Join(f.claude, "settings.json")
	writeFile(t, user, "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(npm test:*)\",\n      \"Read(~/notes/**)\",\n      \"Read(~/notes/**)\",\n      \"mcp__srv\"\n    ]\n  }\n}\n")
	writeFile(t, filepath.Join(f.claude, "file-history", tSession, "h1@v1"), `{"permissions":{"allow":[]}}`)
	writeFile(t, filepath.Join(f.claude, "file-history", tSession, "h1@v2"), `{"permissions":{"allow":["Bash(npm test:*)"]}}`)

	writeFile(t, filepath.Join(f.proj, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(git status:*)","Edit(/src/**)"]}}`)
	writeFile(t, filepath.Join(f.proj, ".claude", "settings.json.bak-20260915-100000"), `{"permissions":{"allow":["Bash(git status:*)"]}}`)
	writeFile(t, filepath.Join(f.proj, ".claude", "settings.local.json"), `{"permissions":{"allow":["WebFetch(domain:example.com)"]}}`)
	writeFile(t, filepath.Join(f.worktree, ".claude", "settings.local.json"), `{"permissions":{"allow":["Read(//etc/hosts)"]}}`)
	writeFile(t, filepath.Join(f.bad, ".claude", "settings.json"), `{"permissions": {`)
	for _, p := range []string{user, filepath.Join(f.proj, ".claude", "settings.json"), filepath.Join(f.proj, ".claude", "settings.local.json"), filepath.Join(f.worktree, ".claude", "settings.local.json")} {
		setMtime(t, p, f.settingsMtime)
	}

	// ~/.claude.json holds account data that must not leak into the report.
	writeFile(t, f.env.ClaudeJSON, js(m{
		"firstStartTime": "2026-01-02T03:04:05Z",
		"oauthAccount":   m{"emailAddress": "private@example.com"},
		"projects": m{
			f.proj: m{"hasTrustDialogAccepted": true, "allowedTools": []string{"Bash(ls:*)"}},
			f.desk: m{"hasTrustDialogAccepted": true}, f.hist: m{"hasTrustDialogAccepted": true}, f.bare: m{"hasTrustDialogAccepted": true},
			f.bad: m{"hasTrustDialogAccepted": false},
		},
	}))
	backup := func(at time.Time, projects m) {
		writeFile(t, filepath.Join(f.claude, "backups", ".claude.json.backup."+strconv.FormatInt(at.UnixMilli(), 10)), js(m{"projects": projects}))
	}
	backup(ts("2026-10-01T00:00:00Z"), m{
		f.proj: m{"hasTrustDialogAccepted": false, "allowedTools": []string{"Bash(old:*)"}},
		f.gone: m{"hasTrustDialogAccepted": true},
		f.desk: m{"hasTrustDialogAccepted": true}, f.hist: m{"hasTrustDialogAccepted": true}, f.bare: m{"hasTrustDialogAccepted": true},
	})
	backup(ts("2026-10-02T00:00:00Z"), m{
		f.proj: m{"hasTrustDialogAccepted": true},
		f.desk: m{"hasTrustDialogAccepted": true}, f.hist: m{"hasTrustDialogAccepted": true}, f.bare: m{"hasTrustDialogAccepted": true},
	})

	s1 := filepath.Join(f.claude, "projects", "-home-work-app", tSession+".jsonl")
	writeFile(t, s1, lines(
		toolUseLine("2026-09-01T10:00:00Z", f.proj, tSession, "u1", "t1", "Bash", m{"command": "npm test"}),
		toolUseLine("2026-09-02T10:00:00Z", f.proj, tSession, "u2", "t2", "Read", m{"file_path": filepath.Join(f.home, "notes", "a.txt")}),
		js(m{"type": "file-history-snapshot", "messageId": "m1", "isSnapshotUpdate": false, "snapshot": m{"messageId": "m1", "timestamp": "2026-09-12T08:00:01Z", "trackedFileBackups": m{
			user: m{"backupFileName": "h1@v1", "version": 1, "backupTime": "2026-09-10T08:00:00Z"},
		}}}),
		js(m{"type": "file-history-delta", "messageId": "m2", "trackingPath": user, "timestamp": "2026-09-12T08:00:01Z",
			"backup": m{"backupFileName": "h1@v2", "version": 2, "backupTime": "2026-09-12T08:00:00Z"}}),
		toolUseLine("2026-09-11T09:00:00Z", f.proj, tSession, "ua1", "a1", "Bash", m{"command": "npm test"}),
		resultLine("2026-09-11T09:00:30Z", f.proj, tSession, "ur1", nil, m{
			"permissionDecision": m{"decision": "accept", "source": "user_permanent"}, "sourceToolAssistantUUID": "ua1",
			"message": m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "a1", "content": "ok"}}},
		}),
		toolUseLine("2026-09-16T10:00:00Z", f.proj, tSession, "u5", "t5", "Write", m{"file_path": filepath.Join(f.proj, "src", "x.go"), "content": "package x"}),
		toolUseLine("2026-09-17T10:00:00Z", f.proj, tSession, "u6", "t6", "Bash", m{"command": "git status"}),
		toolUseLine("2026-09-18T10:00:00Z", f.proj, tSession, "u7", "t7", "WebFetch", m{"url": "https://example.com/"}),
	))
	s2 := filepath.Join(f.claude, "projects", "-home-work-old", "22222222-bbbb.jsonl")
	writeFile(t, s2, lines(
		toolUseLine("2026-08-01T10:00:00Z", f.gone, "22222222-bbbb", "v1", "w1", "Bash", m{"command": "npm test"}),
		resultLine("2026-08-02T10:00:00Z", f.gone, "22222222-bbbb", "v2", m{
			"type": "create", "filePath": filepath.Join(f.gone, ".claude", "settings.json"), "originalFile": nil,
			"content": `{"permissions":{"allow":["Bash(make:*)"]}}`,
		}, nil),
	))

	s3 := filepath.Join(f.claude, "projects", "-home-work-desk", "44444444-dddd")
	writeFile(t, s3+".jsonl", lines(
		toolUseLine("2026-10-05T10:00:00Z", f.desk, "44444444-dddd", "d1", "d1", "Bash", m{"command": "ls"}),
		toolUseLine("2026-10-06T10:00:00Z", f.desk, "44444444-dddd", "d2", "d2", "Bash", m{"command": "ls"}),
	))
	writeFile(t, filepath.Join(s3, "subagents", "agent-1.jsonl"), lines(
		toolUseLine("2026-10-05T10:05:00Z", f.desk, "44444444-dddd", "d3", "d3", "Bash", m{"command": "ls"}),
	))

	deskDir := filepath.Join(f.home, "Library", "Application Support", "Claude", "claude-code-sessions", "acct", "org")
	writeFile(t, filepath.Join(deskDir, "local_one.json"), js(m{"createdAt": ts("2026-05-15T09:00:00Z").UnixMilli(), "cwd": f.desk, "originCwd": f.desk, "title": "private title"}))
	writeFile(t, filepath.Join(f.claude, "history.jsonl"), lines(
		js(m{"display": "/usage", "project": f.hist, "timestamp": ts("2026-06-16T09:00:00Z").UnixMilli()}),
		js(m{"display": "/usage", "project": f.hist, "timestamp": ts("2026-06-15T09:00:00Z").UnixMilli()}),
		"garbage",
	))
	return f
}

func find(t *testing.T, rep model.Report, kind model.Kind, scope model.Scope, value string) model.Grant {
	t.Helper()
	var hits []model.Grant
	for _, g := range rep.Grants {
		if g.Kind == kind && g.Scope == scope && g.Value == value {
			hits = append(hits, g)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want one %s %s grant %q, found %d", scope, kind, value, len(hits))
	}
	return hits[0]
}

func sameTime(t *testing.T, name string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("%s = %v, want %v", name, got.UTC(), want.UTC())
	}
}

func TestCollectNotFound(t *testing.T) {
	root := t.TempDir()
	rep := Collect(model.Env{Home: root, ClaudeDir: filepath.Join(root, ".claude"), ClaudeJSON: filepath.Join(root, ".claude.json"), StateDir: root}, scan.Options{})
	if rep.Found || rep.Agent != model.ClaudeCode || len(rep.Grants) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

func TestCollectRulesAndDating(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	if !rep.Found || rep.Agent != model.ClaudeCode {
		t.Fatalf("report header = %+v", rep)
	}
	user := filepath.Join(f.claude, "settings.json")

	// A rule dated by file-history, then narrowed by a "don't ask again" answer.
	g := find(t, rep, model.KindRule, model.ScopeUser, "Bash(npm test:*)")
	if g.Status != model.StatusActive || !g.Revocable || g.Tool != "Bash" || g.Project != "" {
		t.Errorf("rule fields = %+v", g)
	}
	if g.Key != model.KeyClaudeRule(user, "Bash(npm test:*)") {
		t.Errorf("key = %q", g.Key)
	}
	if g.Location.File != user || g.Location.Pointer != "permissions.allow" || g.Location.Line != 4 {
		t.Errorf("location = %+v", g.Location)
	}
	if g.RevokeNote != "Claude Code applies it on the next tool call." {
		t.Errorf("revoke note = %q", g.RevokeNote)
	}
	sameTime(t, "after", g.Granted.After, ts("2026-09-10T08:00:00Z"))
	sameTime(t, "before", g.Granted.Before, ts("2026-09-11T09:00:30Z"))
	if g.Granted.Source != `you chose "don't ask again"` || g.Granted.Approx {
		t.Errorf("source = %q approx=%v", g.Granted.Source, g.Granted.Approx)
	}
	var approved bool
	for _, e := range g.Evidence {
		approved = approved || e.What == "approved-always"
	}
	if !approved {
		t.Errorf("evidence lacks the decision: %+v", g.Evidence)
	}
	for i := 1; i < len(g.Evidence); i++ {
		if g.Evidence[i].Time.Before(g.Evidence[i-1].Time) {
			t.Errorf("evidence not oldest first: %+v", g.Evidence)
		}
	}
	// Only the transcript that ended after the grant counts; the older one does not.
	if !g.Usage.Known || g.Usage.Count != 2 || g.Usage.Last.Unix() != ts("2026-09-11T09:00:00Z").Unix() {
		t.Errorf("usage = %+v", g.Usage)
	}
	sameTime(t, "usage since", g.Usage.Since, ts("2026-08-01T10:00:00Z"))

	// Duplicates in one file give one grant; a rule with no history is dated by the live file.
	n := find(t, rep, model.KindRule, model.ScopeUser, "Read(~/notes/**)")
	sameTime(t, "live before", n.Granted.Before, f.settingsMtime) // After may be the file's birth time; it differs by system
	if n.Usage.Count != 1 || n.Location.Line != 5 {
		t.Errorf("notes rule: usage %+v line %d", n.Usage, n.Location.Line)
	}
	mcp := find(t, rep, model.KindRule, model.ScopeUser, "mcp__srv")
	if !mcp.Usage.Known || mcp.Usage.Count != 0 {
		t.Errorf("mcp usage = %+v", mcp.Usage)
	}

	// Project files: backup sibling dates the rules; the stamp is local time.
	status := find(t, rep, model.KindRule, model.ScopeProject, "Bash(git status:*)")
	bakAt, _ := time.ParseInLocation("20060102150405", "20260915100000", time.Local)
	sameTime(t, "git status before", status.Granted.Before, bakAt)
	if status.Project != f.proj || status.Usage.Count != 1 {
		t.Errorf("git status = project %q usage %+v", status.Project, status.Usage)
	}
	edit := find(t, rep, model.KindRule, model.ScopeProject, "Edit(/src/**)")
	if edit.Granted.After.Before(bakAt) { // the backup, or a later birth time of the file
		t.Errorf("edit after = %v", edit.Granted.After)
	}
	sameTime(t, "edit before", edit.Granted.Before, f.settingsMtime)
	if edit.Usage.Count != 1 {
		t.Errorf("edit usage = %+v", edit.Usage)
	}
	local := find(t, rep, model.KindRule, model.ScopeLocal, "WebFetch(domain:example.com)")
	if local.Project != f.proj || local.Usage.Count != 1 {
		t.Errorf("local = %+v", local)
	}
	wt := find(t, rep, model.KindRule, model.ScopeLocal, "Read(//etc/hosts)")
	if wt.Project != f.worktree {
		t.Errorf("worktree rule project = %q", wt.Project)
	}

	// Managed rules are listed but never revocable.
	mg := find(t, rep, model.KindRule, model.ScopeManaged, "Bash(echo:*)")
	if mg.Revocable || mg.RevokeNote != "Set by your organization." {
		t.Errorf("managed = %+v", mg)
	}

	// A project folder that is deleted: its rule is gone, dated from the Write result.
	gr := find(t, rep, model.KindRule, model.ScopeProject, "Bash(make:*)")
	if gr.Status != model.StatusGone || gr.Revocable || gr.Location.File != "" || gr.Project != f.gone {
		t.Errorf("gone rule = %+v", gr)
	}
	sameTime(t, "gone last seen", gr.LastSeen, ts("2026-08-02T10:00:00Z"))
	sameTime(t, "gone before", gr.Granted.Before, ts("2026-08-02T10:00:00Z"))
	sameTime(t, "gone after", gr.Granted.After, ts("2026-08-02T09:59:59.999Z"))

	// A settings file that is not JSON gives a note, not a grant.
	bad := false
	for _, nt := range rep.Notes {
		bad = bad || (nt.Level == "warn" && strings.Contains(nt.Text, filepath.Join(f.bad, ".claude", "settings.json")))
	}
	if !bad {
		t.Errorf("notes = %+v", rep.Notes)
	}
}

func TestCollectTrustAndLegacy(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	jsonFile := f.env.ClaudeJSON

	// Removed and added again: only the latest stretch dates it.
	p := find(t, rep, model.KindTrust, model.ScopeUser, f.proj)
	sameTime(t, "proj after", p.Granted.After, ts("2026-10-01T00:00:00Z"))
	sameTime(t, "proj before", p.Granted.Before, ts("2026-10-02T00:00:00Z"))
	if p.Granted.Approx || p.Status != model.StatusActive || !p.Revocable || p.Project != f.proj {
		t.Errorf("proj trust = %+v", p)
	}
	if p.Location.File != jsonFile || p.Location.Pointer != `projects["`+f.proj+`"].hasTrustDialogAccepted` || p.Location.Line == 0 {
		t.Errorf("trust location = %+v", p.Location)
	}
	if !strings.Contains(p.RevokeNote, "Applies to new sessions") {
		t.Errorf("revoke note = %q", p.RevokeNote)
	}
	// The only session ended before the latest stretch of trust began.
	if !p.Usage.Known || p.Usage.Count != 0 {
		t.Errorf("trust usage = %+v", p.Usage)
	}

	// The first session in the folder dates trust: desktop sessions, prompt history.
	d := find(t, rep, model.KindTrust, model.ScopeUser, f.desk)
	sameTime(t, "desk before", d.Granted.Before, ts("2026-05-15T09:00:00Z"))
	if !d.Granted.Approx || d.Granted.Source != srcFirstSeen {
		t.Errorf("desk window = %+v", d.Granted)
	}
	if !d.Usage.Known || d.Usage.Count != 1 { // a main and a subagent transcript of one session
		t.Errorf("desk usage = %+v", d.Usage)
	}
	sameTime(t, "desk last", d.Usage.Last, ts("2026-10-06T10:00:00Z"))
	h := find(t, rep, model.KindTrust, model.ScopeUser, f.hist)
	sameTime(t, "hist before", h.Granted.Before, ts("2026-06-15T09:00:00Z"))
	// No session at all: only the backup bounds it.
	b := find(t, rep, model.KindTrust, model.ScopeUser, f.bare)
	sameTime(t, "bare before", b.Granted.Before, ts("2026-10-01T00:00:00Z"))
	if b.Granted.Approx || b.Usage.Count != 0 {
		t.Errorf("bare = %+v", b)
	}

	// Trusted in a backup, missing now.
	gone := find(t, rep, model.KindTrust, model.ScopeUser, f.gone)
	if gone.Status != model.StatusGone || gone.Revocable || gone.Location.File != "" {
		t.Errorf("gone trust = %+v", gone)
	}
	sameTime(t, "gone trust last seen", gone.LastSeen, ts("2026-10-01T00:00:00Z"))
	sameTime(t, "gone trust before", gone.Granted.Before, ts("2026-08-01T10:00:00Z"))

	// An untrusted project is not a grant.
	for _, g := range rep.Grants {
		if g.Kind == model.KindTrust && g.Value == f.bad {
			t.Error("untrusted project listed")
		}
	}

	// Legacy allowedTools, active and gone.
	lg := find(t, rep, model.KindRule, model.ScopeLegacy, "Bash(ls:*)")
	if lg.Project != f.proj || lg.Location.File != jsonFile || lg.Location.Pointer != `projects["`+f.proj+`"].allowedTools` || lg.Location.Line == 0 {
		t.Errorf("legacy = %+v", lg)
	}
	sameTime(t, "legacy after", lg.Granted.After, ts("2026-10-02T00:00:00Z"))
	if !lg.Granted.Before.IsZero() {
		t.Errorf("legacy before = %v", lg.Granted.Before)
	}
	lgone := find(t, rep, model.KindRule, model.ScopeLegacy, "Bash(old:*)")
	if lgone.Status != model.StatusGone {
		t.Errorf("legacy gone = %+v", lgone)
	}
	sameTime(t, "legacy gone last seen", lgone.LastSeen, ts("2026-10-01T00:00:00Z"))
}

func TestCollectNotesAndCoverage(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	var cleanup string
	for _, n := range rep.Notes {
		if n.Level == "info" && strings.Contains(n.Text, "cleanupPeriodDays") {
			cleanup = n.Text
		}
	}
	if !strings.Contains(cleanup, "2026-08-01") {
		t.Errorf("cleanup note = %q", cleanup)
	}
	got := map[string]model.Coverage{}
	for _, c := range rep.Coverage {
		got[c.Source] = c
	}
	if c := got["Claude Code transcripts"]; c.Files != 4 {
		t.Errorf("transcripts coverage = %+v", c)
	} else {
		sameTime(t, "coverage from", c.From, ts("2026-08-01T10:00:00Z"))
		sameTime(t, "coverage to", c.To, ts("2026-10-06T10:00:00Z"))
	}
	if c := got["Claude desktop sessions"]; c.Files != 1 {
		t.Errorf("desktop coverage = %+v", c)
	}
	if c := got["Claude Code prompt history"]; c.Files != 1 {
		t.Errorf("history coverage = %+v", c)
	}
}

func TestCollectNeverReportsAccountData(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	all := js(rep)
	for _, secret := range []string{"private@example.com", "private title", "oauthAccount"} {
		if strings.Contains(all, secret) {
			t.Errorf("report leaks %q", secret)
		}
	}
}

func TestCollectCacheGivesSameResult(t *testing.T) {
	f := newFixture(t)
	cold := Collect(f.env, scan.Options{})
	warm := Collect(f.env, scan.Options{})
	plain := Collect(f.env, scan.Options{NoCache: true})
	if !reflect.DeepEqual(cold, warm) {
		t.Error("warm run differs from cold run")
	}
	if !reflect.DeepEqual(cold, plain) {
		t.Error("run without cache differs")
	}
	if entries, _ := os.ReadDir(f.env.StateDir); len(entries) == 0 {
		t.Error("nothing cached")
	}
}

func TestCollectUnreadableFolderGivesUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	f := newFixture(t)
	locked := filepath.Join(f.home, "work", "locked")
	settings := filepath.Join(locked, ".claude", "settings.json")
	writeFile(t, settings, `{"permissions":{"allow":["Bash(task:*)"]}}`)
	// A transcript that saw the rule in that file earlier.
	writeFile(t, filepath.Join(f.claude, "projects", "-home-work-locked", "33333333-cccc.jsonl"), lines(
		toolUseLine("2026-09-01T10:00:00Z", locked, "33333333-cccc", "x1", "x1", "Bash", m{"command": "ls"}),
		resultLine("2026-09-02T10:00:00Z", locked, "33333333-cccc", "x2", m{
			"type": "create", "filePath": settings, "originalFile": nil, "content": `{"permissions":{"allow":["Bash(task:*)"]}}`,
		}, nil),
	))
	if err := os.Chmod(filepath.Join(locked, ".claude"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(locked, ".claude"), 0o755) })
	rep := Collect(f.env, scan.Options{})
	g := find(t, rep, model.KindRule, model.ScopeProject, "Bash(task:*)")
	if g.Status != model.StatusUnknown || g.Revocable {
		t.Errorf("want unknown and not revocable, got %+v", g)
	}
}

func TestCollectSurvivesGarbage(t *testing.T) {
	f := newFixture(t)
	// Break every input in a different way.
	writeFile(t, f.env.ClaudeJSON, `{"projects": {"/x": `)
	writeFile(t, filepath.Join(f.claude, "projects", "-junk", "bin.jsonl"), "\x00\xff\xfe{\"type\":\"tool_use\"\n{\n\"\n")
	writeFile(t, filepath.Join(f.claude, "projects", "-junk", "empty.jsonl"), "")
	writeFile(t, filepath.Join(f.claude, "history.jsonl"), "{{{{\n\n[1]\n")
	writeFile(t, filepath.Join(f.home, "Library", "Application Support", "Claude", "claude-code-sessions", "a", "local_bad.json"), "not json")
	writeFile(t, filepath.Join(f.claude, "backups", ".claude.json.backup.1700000000000"), "###")
	if err := os.Remove(filepath.Join(f.claude, "settings.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.claude, "settings.json"), 0o755); err != nil { // a folder where a file should be
		t.Fatal(err)
	}
	rep := Collect(f.env, scan.Options{})
	if !rep.Found {
		t.Fatal("not found")
	}
	var warned int
	for _, n := range rep.Notes {
		if n.Level == "warn" {
			warned++
		}
	}
	if warned < 2 {
		t.Errorf("want notes for the broken files, got %+v", rep.Notes)
	}
	// Whatever is still readable is still reported.
	find(t, rep, model.KindRule, model.ScopeProject, "Edit(/src/**)")
}
