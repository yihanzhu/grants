package codex

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

// miniHome is a small Codex home with a config and no rules. All paths are synthetic.
type miniHome struct {
	env  model.Env
	cfg  string
	work string
}

func newMiniHome(t *testing.T, config string) *miniHome {
	t.Helper()
	tmp := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = resolved
	}
	home := filepath.Join(tmp, "home")
	ch := filepath.Join(home, ".codex")
	m := &miniHome{
		env:  model.Env{Home: home, CodexHome: ch, StateDir: filepath.Join(tmp, "state"), Now: at(30, 0, 0), UnusedAfter: 90 * 24 * time.Hour},
		cfg:  filepath.Join(ch, "config.toml"),
		work: filepath.Join(tmp, "work"),
	}
	if err := os.MkdirAll(m.work, 0o755); err != nil {
		t.Fatal(err)
	}
	restore := OverrideManaged(filepath.Join(tmp, "no-managed"))
	t.Cleanup(restore)
	writeFile(t, m.cfg, config)
	return m
}

func (m *miniHome) session(t *testing.T, name string, r *rollout) {
	t.Helper()
	r.write(t, filepath.Join(m.env.CodexHome, "sessions", "2026", "03", "rollout-"+name+".jsonl"))
}

func (m *miniHome) collect() model.Report { return Collect(m.env, scan.Options{NoCache: true}) }

func trustToml(paths ...string) string {
	var sb strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&sb, "[projects.%q]\ntrust_level = \"trusted\"\n\n", p)
	}
	return sb.String()
}

func TestParseRulesIndentedCallIsNotRevocable(t *testing.T) {
	const call = `prefix_rule(pattern=["npm", "test"], decision="allow")`
	for name, src := range map[string]string{
		"for":     "for x in [\"a\"]:\n    " + call + "\n",
		"if":      "if True:\n\t" + call + "\n",
		"def":     "def f():\n  " + call + "\nf()\n",
		"def two": "prefix_rule(pattern=[\"ls\"])\ndef f():\n  " + call + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			for _, r := range ParseRules([]byte(src)) {
				if r.Name == "prefix_rule" && r.Err == "" && strings.Contains(r.Raw, "npm") {
					t.Errorf("indented rule is listed as a grant: %+v", r)
				}
			}
			out, n, err := RemoveRule([]byte(src), [][]string{{"npm"}, {"test"}}, "allow")
			if err != nil || n != 0 || string(out) != src {
				t.Errorf("RemoveRule = %q, %d, %v; want no change", out, n, err)
			}
		})
	}
	// A call at the start of a line is still a rule.
	rules := ParseRules([]byte(call + "\n"))
	if len(rules) != 1 || rules[0].Err != "" {
		t.Errorf("top-level rule = %+v", rules)
	}
}

func TestRevokeTrustKeepsEntryOnUnmountedVolume(t *testing.T) {
	tmp := t.TempDir()
	env := model.Env{CodexHome: filepath.Join(tmp, ".codex")}
	doc := []byte(trustToml(filepath.Join(tmp, "volume-not-mounted", "proj")))
	g := model.Grant{
		Agent: model.Codex, Kind: model.KindTrust, Status: model.StatusActive, Revocable: true,
		Value: filepath.Join(tmp, "volume-not-mounted", "proj"),
	}
	out, summary, err := RevokeDoc(env, g, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"untrusted"`) || !strings.Contains(summary, "untrusted") {
		t.Errorf("entry was not set to untrusted: %s / %s", summary, out)
	}
}

func TestGoneGrantsHaveRemovalWindow(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})

	g := find(t, rep, model.KindRule, model.StatusGone, "docker system prune")
	sameTime(t, "rule removed after", g.Removed.After, at(8, 10, 1))
	sameTime(t, "rule removed before", g.Removed.Before, at(12, 10, 1))

	g = find(t, rep, model.KindTrust, model.StatusGone, f.removed)
	if g.Removed.Before.IsZero() || g.Removed.After.IsZero() {
		t.Errorf("trust removed window = %+v", g.Removed)
	}
}

func TestRuleKeyDoesNotDependOnOtherFiles(t *testing.T) {
	f := newFixture(t)
	projKey := model.KeyCodexRule(`["git","status"]`) + "|" + f.projRules
	keyOf := func(rep model.Report) (string, bool) {
		for _, g := range rep.Grants {
			if g.Value == "git status" && g.Scope == model.ScopeProject && g.Status == model.StatusActive {
				return g.Key, true
			}
		}
		return "", false
	}
	if k, ok := keyOf(Collect(f.env, scan.Options{})); !ok || k != projKey {
		t.Fatalf("project key = %q, want %q", k, projKey)
	}

	// Remove the user copy of the same pattern.
	writeFile(t, f.userRules, `prefix_rule(pattern=["npm", "test"], decision="allow")`+"\n")
	rep := Collect(f.env, scan.Options{})
	if k, ok := keyOf(rep); !ok || k != projKey {
		t.Errorf("project key after removing the user copy = %q, want %q", k, projKey)
	}
	for _, g := range rep.Grants {
		if g.Key == model.KeyCodexRule(`["git","status"]`) {
			t.Errorf("the user key is still reported: %+v", g)
		}
	}
}

func TestBlockedFolderRuleIsGoneWhenLaterSessionLacksIt(t *testing.T) {
	f := newFixture(t)
	if !f.rootBlocksVault {
		t.Skip("this user can read a folder without permissions")
	}
	// A later session in the unreadable folder lists the approved prefixes without it.
	git := []string{"git", "status"}
	(&rollout{}).meta(at(18, 10, 0), filepath.Join(f.vault, "notes"), "vscode").
		worldState(at(18, 10, 1), git).
		write(t, filepath.Join(f.env.CodexHome, "sessions", "2026", "03", "18", "rollout-later.jsonl"))
	g := find(t, Collect(f.env, scan.Options{}), model.KindRule, model.StatusGone, "secret-tool run")
	sameTime(t, "removed before", g.Removed.Before, at(18, 10, 1))
}

func TestTrustFirstSessionIgnoresTrustedChild(t *testing.T) {
	m := newMiniHome(t, "")
	parent := filepath.Join(m.work, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, m.cfg, trustToml(parent, child))
	m.session(t, "child", (&rollout{}).meta(at(3, 10, 0), child, "cli").worldState(at(3, 10, 1)))
	m.session(t, "plain", (&rollout{}).meta(at(10, 10, 0), filepath.Join(parent, "other"), "cli").worldState(at(10, 10, 1)))

	rep := m.collect()
	g := find(t, rep, model.KindTrust, model.StatusActive, parent)
	sameTime(t, "parent trust before", g.Granted.Before, at(10, 10, 0))
	g = find(t, rep, model.KindTrust, model.StatusActive, child)
	sameTime(t, "child trust before", g.Granted.Before, at(3, 10, 0))
}

func TestTrustUsageSkipsSubagentRollouts(t *testing.T) {
	m := newMiniHome(t, "")
	dir := filepath.Join(m.work, "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, m.cfg, trustToml(dir))
	m.session(t, "top", (&rollout{}).meta(at(3, 10, 0), dir, "cli").worldState(at(3, 10, 1)))
	m.session(t, "sub", (&rollout{}).meta(at(3, 10, 5), dir, map[string]any{"subagent": map[string]any{"depth": 1}}).worldState(at(3, 10, 6)))

	g := find(t, m.collect(), model.KindTrust, model.StatusActive, dir)
	if g.Usage.Count != 1 {
		t.Errorf("usage count = %d, want 1", g.Usage.Count)
	}
}

func TestCacheKeepsPrefixTokensRedacted(t *testing.T) {
	const secret = "ghp_SyntheticTokenValue0123456789"
	const secret2 = "SyntheticFlagValue987654321"
	curl := []string{"curl", "-H", "X: " + secret}
	flag := []string{"tool", "--token", secret2}
	r := (&rollout{}).meta(at(5, 10, 0), "/work/app", "cli").
		devSnapshot(at(5, 10, 1), curl, flag).
		call(at(5, 10, 5), "exec_command", "e1", map[string]any{
			"cmd": "x", "sandbox_permissions": "require_escalated", "prefix_rule": flag,
		}).
		callOutput(at(5, 10, 6), "e1", "ok")
	facts := extract(t, r)
	var all []string
	for _, run := range facts.Prefixes {
		for _, p := range run.Prefixes {
			all = append(all, p...)
		}
	}
	for _, e := range facts.Escalations {
		all = append(all, e.Prefix...)
	}
	if len(all) == 0 {
		t.Fatal("no prefixes were extracted")
	}
	for _, tok := range all {
		if strings.Contains(tok, secret) || strings.Contains(tok, secret2) {
			t.Errorf("token kept in the clear: %q", tok)
		}
	}
}

func TestRuleWithSecretStillMatchesSnapshots(t *testing.T) {
	const secret = "ghp_SyntheticTokenValue0123456789"
	m := newMiniHome(t, "")
	pat := []string{"curl", "-H", "X: " + secret}
	m.session(t, "a", (&rollout{}).meta(at(5, 10, 0), "/work/app", "cli").worldState(at(5, 10, 1)))
	m.session(t, "b", (&rollout{}).meta(at(8, 10, 0), "/work/app", "cli").worldState(at(8, 10, 1), pat))
	writeFile(t, filepath.Join(m.env.CodexHome, "rules", "default.rules"),
		fmt.Sprintf("prefix_rule(pattern=[\"curl\", \"-H\", %q], decision=\"allow\")\n", "X: "+secret))
	var found bool
	for _, g := range m.collect().Grants {
		if g.Kind == model.KindRule && g.Status == model.StatusActive {
			found = true
			sameTime(t, "granted after", g.Granted.After, at(5, 10, 1))
			sameTime(t, "granted before", g.Granted.Before, at(8, 10, 1))
		}
	}
	if !found {
		t.Fatal("rule not listed")
	}
}

func TestConfigParseNoteHidesFileText(t *testing.T) {
	const token = "SyntheticLettersOnlyToken"
	m := newMiniHome(t, "K = "+token+"\n")
	rep := m.collect()
	var text string
	for _, n := range rep.Notes {
		text += n.Text + "\n"
	}
	if !strings.Contains(text, "line 1") || strings.Contains(text, "Synthetic") {
		t.Errorf("notes = %q", text)
	}
}

func TestUnreadConfigIsReportedAndBackupTrustIsUnknown(t *testing.T) {
	m := newMiniHome(t, "")
	dir := filepath.Join(m.work, "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A backup trusts a folder; the live config is broken.
	writeFile(t, m.cfg+".bak-20260310-120000", trustToml(dir))
	writeFile(t, m.cfg, "[projects\n")

	rep := m.collect()
	if !hasPrefix(rep.Unread, "codex|trust|") {
		t.Errorf("Unread = %q, want codex|trust|", rep.Unread)
	}
	g := find(t, rep, model.KindTrust, model.StatusUnknown, dir)
	if !g.Removed.Before.IsZero() || !g.Removed.After.IsZero() {
		t.Errorf("an unknown grant has a removal window: %+v", g.Removed)
	}

	// A readable config reports nothing.
	writeFile(t, m.cfg, trustToml(dir))
	if rep := m.collect(); len(rep.Unread) != 0 {
		t.Errorf("Unread = %q, want none", rep.Unread)
	}
}

func TestUnreadRulesFileIsReported(t *testing.T) {
	m := newMiniHome(t, "")
	rules := filepath.Join(m.env.CodexHome, "rules", "default.rules")
	writeFile(t, rules, `prefix_rule(pattern=["npm", "test"], decision="allow")`+"\n")
	if err := os.Chmod(rules, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rules, 0o644) })
	if _, err := os.ReadFile(rules); err == nil {
		t.Skip("this user can read a file without permissions")
	}
	if rep := m.collect(); !hasPrefix(rep.Unread, "codex|rule|") {
		t.Errorf("Unread = %q, want codex|rule|", rep.Unread)
	}
}

func hasPrefix(list []string, p string) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}
