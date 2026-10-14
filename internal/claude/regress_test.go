package claude

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

// bareEnv is an empty fake home with a Claude folder, and no managed settings.
func bareEnv(t *testing.T) model.Env {
	t.Helper()
	root := t.TempDir()
	restore := OverrideManaged(filepath.Join(root, "managed"))
	t.Cleanup(restore)
	env := model.Env{
		Home: filepath.Join(root, "home"), ClaudeDir: filepath.Join(root, "home", ".claude"),
		ClaudeJSON: filepath.Join(root, "home", ".claude.json"), StateDir: filepath.Join(root, "state"), Now: time.Now(),
	}
	if err := os.MkdirAll(env.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return env
}

func transcript(env model.Env, name string) string {
	return filepath.Join(env.ClaudeDir, "projects", "-work", name+".jsonl")
}

func TestCollectUnreadableClaudeJSONGivesUnknown(t *testing.T) {
	f := newFixture(t)
	good := Collect(f.env, scan.Options{})
	if len(good.Unread) != 0 {
		t.Fatalf("unread = %v", good.Unread)
	}
	writeFile(t, f.env.ClaudeJSON, `{"projects": {"`+f.proj+`": `) // half-written
	rep := Collect(f.env, scan.Options{})

	want := []string{"claude-code|trust|", "claude-code|rule|" + f.env.ClaudeJSON + "#"}
	if strings.Join(rep.Unread, "\n") != strings.Join(want, "\n") {
		t.Errorf("unread = %v, want %v", rep.Unread, want)
	}
	for _, g := range rep.Grants {
		inJSON := g.Kind == model.KindTrust || g.Scope == model.ScopeLegacy
		if !inJSON {
			continue
		}
		if g.Status == model.StatusGone {
			t.Errorf("%s %q is gone, but ~/.claude.json could not be read", g.Kind, g.Value)
		}
		if g.Status == model.StatusUnknown && (!g.Removed.Before.IsZero() || g.RevokeNote != "File not readable.") {
			t.Errorf("unknown grant %q: %+v", g.Value, g)
		}
	}
	// A trust that backups show is still reported, as unknown.
	if g := find(t, rep, model.KindTrust, model.ScopeUser, f.gone); g.Status != model.StatusUnknown {
		t.Errorf("trust from a backup = %+v", g)
	}
}

func TestCollectGoneGrantsHaveRemovalWindow(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	check := func(name string, g model.Grant) {
		t.Helper()
		if g.Status != model.StatusGone {
			t.Fatalf("%s = %+v", name, g)
		}
		sameTime(t, name+" removed after", g.Removed.After, ts("2026-10-01T00:00:00Z"))
		sameTime(t, name+" removed before", g.Removed.Before, ts("2026-10-02T00:00:00Z"))
	}
	check("trust", find(t, rep, model.KindTrust, model.ScopeUser, f.gone))
	check("legacy", find(t, rep, model.KindRule, model.ScopeLegacy, "Bash(old:*)"))

	// A rule in a settings file that history saw present, then absent.
	dropped := filepath.Join(f.home, "work", "dropped")
	settings := filepath.Join(dropped, ".claude", "settings.json")
	writeFile(t, settings, `{"permissions":{"allow":[]}}`)
	one := `{"permissions":{"allow":["Bash(zip:*)"]}}`
	writeFile(t, filepath.Join(f.claude, "projects", "-work-dropped", "55555555-eeee.jsonl"), lines(
		resultLine("2026-09-02T10:00:00Z", dropped, "55555555-eeee", "w1", m{
			"type": "create", "filePath": settings, "originalFile": nil, "content": one,
		}, nil),
		resultLine("2026-09-05T10:00:00Z", dropped, "55555555-eeee", "w2", m{
			"type": "update", "filePath": settings, "originalFile": one, "content": `{"permissions":{"allow":[]}}`,
		}, nil),
	))
	rep = Collect(f.env, scan.Options{})
	g := find(t, rep, model.KindRule, model.ScopeProject, "Bash(zip:*)")
	if g.Status != model.StatusGone {
		t.Fatalf("rule = %+v", g)
	}
	sameTime(t, "rule removed after", g.Removed.After, ts("2026-09-05T09:59:59.999Z"))
	sameTime(t, "rule removed before", g.Removed.Before, ts("2026-09-05T10:00:00Z"))
}

func TestCollectDecisionDatesOnlyTheMostSpecificRule(t *testing.T) {
	env := bareEnv(t)
	settings := filepath.Join(env.ClaudeDir, "settings.json")
	mtime := time.Now().Add(-time.Hour).Truncate(time.Second)
	backup := mtime.Add(-72 * time.Hour)
	answer := backup.Add(-24 * time.Hour)
	writeFile(t, settings, `{"permissions":{"allow":["Bash","Bash(git:*)","Bash(git push:*)"]}}`)
	setMtime(t, settings, mtime)
	// A backup shows all three rules before the file's own time (which also stands in for its birth).
	writeFile(t, settings+".bak-"+backup.Local().Format("20060102-150405"), `{"permissions":{"allow":["Bash","Bash(git:*)","Bash(git push:*)"]}}`)
	at := func(d time.Time) string { return d.UTC().Format(time.RFC3339) }
	writeFile(t, transcript(env, "s1"), lines(
		toolUseLine(at(answer), "/work", "s1", "ua1", "a1", "Bash", m{"command": "git push origin main"}),
		resultLine(at(answer.Add(time.Second)), "/work", "s1", "ur1", nil, m{
			"permissionDecision": m{"decision": "accept", "source": "user_permanent"}, "sourceToolAssistantUUID": "ua1",
			"message": m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "a1", "content": "ok"}}},
		}),
	))
	rep := Collect(env, scan.Options{})
	for rule, want := range map[string]bool{"Bash": false, "Bash(git:*)": false, "Bash(git push:*)": true} {
		g := find(t, rep, model.KindRule, model.ScopeUser, rule)
		got := g.Granted.Source == `you chose "don't ask again"`
		if got != want {
			t.Errorf("%s: dated by the answer = %v, want %v (window %+v)", rule, got, want, g.Granted)
		}
	}
}

func TestCollectCountsCopiedToolCallsOnce(t *testing.T) {
	env := bareEnv(t)
	settings := filepath.Join(env.ClaudeDir, "settings.json")
	writeFile(t, settings, `{"permissions":{"allow":["Bash(npm test:*)"]}}`)
	call := func(when, sess, id string) string {
		return toolUseLine(when, "/work", sess, "u-"+id, id, "Bash", m{"command": "npm test"})
	}
	writeFile(t, transcript(env, "s1"), lines(call("2026-09-01T10:00:00Z", "s1", "t1"), call("2026-09-01T11:00:00Z", "s1", "t2")))
	// A resumed session copies the first two calls, then adds one.
	writeFile(t, transcript(env, "s2"), lines(
		call("2026-09-01T10:00:00Z", "s2", "t1"), call("2026-09-01T11:00:00Z", "s2", "t2"), call("2026-09-02T10:00:00Z", "s2", "t3")))
	rep := Collect(env, scan.Options{})
	g := find(t, rep, model.KindRule, model.ScopeUser, "Bash(npm test:*)")
	if g.Usage.Count != 3 {
		t.Errorf("usage = %+v, want 3 calls", g.Usage)
	}
	// The same result with a warm cache.
	if again := Collect(env, scan.Options{}); find(t, again, model.KindRule, model.ScopeUser, "Bash(npm test:*)").Usage.Count != 3 {
		t.Error("cached run counts differently")
	}
}

func TestCollectTrustIsNotDatedFromTrustedSubfolder(t *testing.T) {
	env := bareEnv(t)
	parent, child := "/work/proj", "/work/proj/sub"
	writeFile(t, env.ClaudeJSON, js(m{"projects": m{
		parent: m{"hasTrustDialogAccepted": true}, child: m{"hasTrustDialogAccepted": true},
	}}))
	writeFile(t, transcript(env, "s1"), lines(toolUseLine("2026-09-01T10:00:00Z", child, "s1", "u1", "t1", "Bash", m{"command": "ls"})))
	writeFile(t, transcript(env, "s2"), lines(toolUseLine("2026-09-10T10:00:00Z", parent, "s2", "u2", "t2", "Bash", m{"command": "ls"})))
	rep := Collect(env, scan.Options{})
	sameTime(t, "parent before", find(t, rep, model.KindTrust, model.ScopeUser, parent).Granted.Before, ts("2026-09-10T10:00:00Z"))
	sameTime(t, "child before", find(t, rep, model.KindTrust, model.ScopeUser, child).Granted.Before, ts("2026-09-01T10:00:00Z"))
}

func TestEarliestSessionCountsSubfoldersWithoutOwnTrust(t *testing.T) {
	sessions := []session{{T: ts("2026-09-01T10:00:00Z"), Dir: "/work/proj/sub/deep"}}
	got, ok := earliestSession(sessions, "/work/proj", map[string]bool{"/work/proj": true})
	if !ok || !got.Equal(ts("2026-09-01T10:00:00Z")) {
		t.Errorf("got %v %v", got, ok)
	}
	if _, ok := earliestSession(sessions, "/work/proj", map[string]bool{"/work/proj": true, "/work/proj/sub": true}); ok {
		t.Error("a session below another trusted folder must not date this trust")
	}
}

func TestCollectNotesUseSingularForOne(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	f := newFixture(t)
	locked := filepath.Join(f.claude, "projects", "-locked")
	writeFile(t, filepath.Join(locked, "a.jsonl"), "{}\n")
	badFile := filepath.Join(f.claude, "projects", "-work", "bad.jsonl")
	writeFile(t, badFile, "{}\n")
	blocked := filepath.Join(f.home, "work", "locked")
	writeFile(t, filepath.Join(blocked, ".claude", "settings.json"), `{}`)
	writeFile(t, filepath.Join(f.claude, "projects", "-work", "c.jsonl"), lines(
		toolUseLine("2026-09-01T10:00:00Z", blocked, "c", "u1", "t1", "Bash", m{"command": "ls"})))
	for _, p := range []string{locked, badFile, filepath.Join(blocked, ".claude")} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		p := p
		t.Cleanup(func() { os.Chmod(p, 0o755) })
	}
	rep := Collect(f.env, scan.Options{NoCache: true})
	var texts []string
	for _, n := range rep.Notes {
		texts = append(texts, n.Text)
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{"1 transcript folder could not be read.", "1 Claude Code transcript could not be read.", "1 project folder could not be read"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
}

func TestExtractWriteUpdateWithoutOriginalHasNoBeforeState(t *testing.T) {
	settings := tHome + "/.claude/settings.json"
	f := extractLines(t, resultLine("2026-09-10T10:00:00Z", tProj, tSession, "e1", m{
		"type": "update", "filePath": settings, "originalFile": nil, "content": `{"permissions":{"allow":["Bash(a:*)"]}}`,
	}, nil))
	if len(f.Snapshots) != 1 || !f.Snapshots[0].T.Equal(ts("2026-09-10T10:00:00Z")) {
		t.Errorf("snapshots = %+v, want only the state after the write", f.Snapshots)
	}
}

func TestExtractToolCallsCarryIDs(t *testing.T) {
	f := extractLines(t,
		toolUseLine("2026-09-01T10:00:00Z", tProj, tSession, "u1", "t1", "Bash", m{"command": "ls"}),
		toolUseLine("2026-09-01T10:00:01Z", tProj, tSession, "u2", "t1", "Bash", m{"command": "ls"}), // same id in one file
		toolUseLine("2026-09-01T10:00:02Z", tProj, tSession, "u3", "", "Bash", m{"command": "ls"}),
	)
	if len(f.Calls) != 2 || f.Calls[0].ID == 0 || f.Calls[1].ID != 0 || len(f.Calls[0].Keys) == 0 {
		t.Errorf("calls = %+v", f.Calls)
	}
}

func TestExtractResolvesRelativeFileHistory(t *testing.T) {
	back := m{"backupFileName": "h@v1", "version": 1, "backupTime": "2026-09-10T08:00:00Z"}
	f := extractLines(t,
		toolUseLine("2026-09-01T10:00:00Z", tProj, tSession, "u1", "t1", "Bash", m{"command": "ls"}),
		js(m{"type": "file-history-snapshot", "snapshot": m{"trackedFileBackups": m{
			".claude/settings.local.json": back, "sub/.claude/settings.json": back, "notes/.claude.md": back,
		}}}),
	)
	got := map[string]bool{}
	for _, r := range f.FileHistory {
		got[r.File] = true
	}
	want := map[string]bool{tProj + "/.claude/settings.local.json": true, tProj + "/sub/.claude/settings.json": true}
	if len(got) != 2 || !got[tProj+"/.claude/settings.local.json"] || !got[tProj+"/sub/.claude/settings.json"] {
		t.Errorf("file history = %v, want %v", got, want)
	}
}

func TestFileFromPathRefusesRelativePaths(t *testing.T) {
	c := &collector{env: model.Env{Home: "/home/u"}}
	if sf, ok := c.fileFromPath("sub/.claude/settings.json"); ok {
		t.Errorf("relative path accepted: %+v", sf)
	}
	if _, ok := c.fileFromPath("/work/app/.claude/settings.json"); !ok {
		t.Error("absolute settings path refused")
	}
}

// gitEnv keeps the machine's own git config out of a test.
func gitEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
}

func gitOut(t *testing.T, dir string, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_AUTHOR_DATE=2026-09-01T10:00:00Z", "GIT_COMMITTER_DATE=2026-09-01T10:00:00Z")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitVersionsRunsNothingFromRepositoryConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	gitEnv(t)
	repo := t.TempDir()
	gitOut(t, repo, "", "init", "-q")
	writeFile(t, filepath.Join(repo, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(a:*)"]}}`)
	gitOut(t, repo, "", "add", ".")
	gitOut(t, repo, "", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "one")
	// Give the commit a signature header, so git has something to verify.
	raw := gitOut(t, repo, "", "cat-file", "commit", "HEAD")
	head, msg, _ := strings.Cut(raw, "\n\n")
	signed := head + "\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n fake\n -----END PGP SIGNATURE-----\n\n" + msg + "\n"
	sha := gitOut(t, repo, signed, "hash-object", "-t", "commit", "-w", "--stdin")
	gitOut(t, repo, "", "update-ref", "HEAD", sha)
	marker := filepath.Join(t.TempDir(), "ran")
	prog := filepath.Join(t.TempDir(), "gpg.sh")
	writeFile(t, prog, "#!/bin/sh\ntouch '"+marker+"'\nexit 1\n")
	if err := os.Chmod(prog, 0o755); err != nil {
		t.Fatal(err)
	}
	gitOut(t, repo, "", "config", "log.showSignature", "true")
	gitOut(t, repo, "", "config", "gpg.program", prog)

	if vs := gitVersions(repo, ".claude/settings.json"); len(vs) != 1 {
		t.Errorf("versions = %d, want 1", len(vs))
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("git ran the program named by the repository's config")
	}
}

func TestGitVersionsSkipsPartialClones(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	gitEnv(t)
	src := t.TempDir()
	gitOut(t, src, "", "init", "-q")
	gitOut(t, src, "", "config", "uploadpack.allowFilter", "true")
	gitOut(t, src, "", "config", "uploadpack.allowAnySHA1InWant", "true")
	writeFile(t, filepath.Join(src, ".claude", "settings.json"), `{"permissions":{"allow":["Bash(a:*)"]}}`)
	gitOut(t, src, "", "add", ".")
	gitOut(t, src, "", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "one")
	if vs := gitVersions(src, ".claude/settings.json"); len(vs) != 1 {
		t.Fatalf("a normal repository gives %d versions, want 1", len(vs))
	}
	dst := filepath.Join(t.TempDir(), "clone")
	gitOut(t, src, "", "clone", "-q", "--no-local", "--filter=blob:none", "--no-checkout", "file://"+src, dst)
	if vs := gitVersions(dst, ".claude/settings.json"); vs != nil {
		t.Errorf("a partial clone gave %d versions; reading them can fetch over the network", len(vs))
	}
}
