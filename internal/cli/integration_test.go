package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/model"
)

type row struct {
	ID    string `json:"id"`
	Agent string `json:"agent"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
	// Status is active, gone or unknown.
	Status string `json:"status"`
}

// ids maps "agent kind value" to the grant id.
func ids(t *testing.T) map[string]string {
	t.Helper()
	code, out, errs := run(t, "", "list", "--all", "--json")
	if code != 0 {
		t.Fatalf("list --json: code %d: %s", code, errs)
	}
	var rows []row
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("list --json is not JSON: %v\n%s", err, out)
	}
	m := map[string]string{}
	for _, r := range rows {
		m[r.Agent+" "+r.Kind+" "+r.Value] = r.ID
	}
	return m
}

func (h *home) id(t *testing.T, m map[string]string, agent, kind, value string) string {
	t.Helper()
	id := m[agent+" "+kind+" "+value]
	if id == "" {
		t.Fatalf("no grant %q in %v", agent+" "+kind+" "+value, m)
	}
	return id
}

// squash turns runs of spaces into one, so a check does not depend on column widths.
func squash(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return strings.Join(out, "\n")
}

// rewrite replaces a file and sets its modification time, so dates stay fixed.
func rewrite(t *testing.T, path, content, mtime string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	touch(t, path, mtime)
}

func mustContain(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(out, p) {
			t.Errorf("output lacks %q:\n%s", p, out)
		}
	}
}

func mustNotContain(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(out, p) {
			t.Errorf("output has %q:\n%s", p, out)
		}
	}
}

func TestSummary(t *testing.T) {
	newHome(t)
	t.Setenv("COLUMNS", "150")
	code, out, errs := run(t, "")
	if code != 0 || errs != "" {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	lines := strings.Split(out, "\n")
	// The result comes first.
	if want := "grants: 13 active grants across 2 agents. 4 need a look. 4 point to deleted paths."; lines[0] != want {
		t.Errorf("first line = %q, want %q", lines[0], want)
	}
	mustContain(t, out,
		"rules   trusted folders   high risk   removed",
		"Claude Code   5 (1 deleted)     2 (1 deleted)           3         0",
		"Codex         4 (1 deleted)     2 (1 deleted)           2         0",
		"Needs a look",
		"Clean up",
		"4 grants point to deleted paths: grants revoke --dead",
		"2 one-off rules, approved for a single URL or script: grants revoke --one-off",
		"2 grants not used in 90 days: grants revoke --unused",
		"Files are backed up first. Preview with --dry-run. Undo with grants undo.",
		"History covers Claude Code from 2026-06-01 and Codex from 2026-06-01.",
		"Next: grants show ",
	)
	// Dead-path grants are cleaned up, not listed under "Needs a look".
	look := out[strings.Index(out, "Needs a look"):strings.Index(out, "Clean up")]
	mustNotContain(t, look, "notes", "gone", "missing")
	mustContain(t, look, "never used", "last used 2026-10-03", "pushes code to a remote")
	// One-off rules (other than the one with a credential) are cleaned up, not listed.
	mustNotContain(t, look, "https://example.com/a/b")
	// The credential never reaches the screen.
	mustNotContain(t, out, "abcdefghij0123456789")
	// A secret comes before plain high-risk grants.
	first := strings.Split(look, "\n")[1]
	if !strings.Contains(first, "claude-code") || !strings.Contains(first, "Bash(curl") {
		t.Errorf("first grant to look at = %q, want the one with a credential", first)
	}
	// Plain output: no color codes when stdout is not a terminal.
	mustNotContain(t, out, "\x1b[")
}

func TestSummaryLimitsLookList(t *testing.T) {
	h := newHome(t)
	var sb strings.Builder
	for i := range 14 {
		sb.WriteString(`prefix_rule(pattern=["rm", "-rf", "/tmp/x` + string(rune('a'+i)) + `"], decision="allow")` + "\n")
	}
	f, _ := os.OpenFile(h.codexRules, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(sb.String())
	f.Close()
	_, out, _ := run(t, "")
	mustContain(t, out, "+8 more: grants list --risk high")
	if n := strings.Count(out[strings.Index(out, "Needs a look"):strings.Index(out, "Clean up")], "\n  "); n != 11 {
		t.Errorf("list lines = %d, want 10 grants and the +more line", n)
	}
}

func TestSummaryNothingInstalled(t *testing.T) {
	newHome(t)
	for _, p := range []string{".claude", ".claude.json", ".codex"} {
		os.RemoveAll(filepath.Join(os.Getenv("HOME"), p))
	}
	code, out, _ := run(t, "")
	if code != 0 || !strings.HasPrefix(out, "grants: no Claude Code or Codex found") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestSummaryNothingToDo(t *testing.T) {
	h := newHome(t)
	os.WriteFile(h.claudeUser, []byte(`{"permissions":{"allow":["Bash(ls:*)"]}}`), 0o644)
	os.Remove(h.claudeProj)
	os.WriteFile(h.claudeJSON, []byte(`{"firstStartTime":"2026-05-01T00:00:00Z"}`), 0o644)
	os.WriteFile(h.codexRules, []byte(`prefix_rule(pattern=["ls"], decision="allow")`+"\n"), 0o644)
	os.WriteFile(h.codexCfg, []byte("model = \"m\"\n"), 0o644)
	_, out, _ := run(t, "")
	if first := strings.Split(out, "\n")[0]; first != "grants: 2 active grants across 2 agents. Nothing needs a look." {
		t.Errorf("first line = %q", first)
	}
	mustNotContain(t, out, "Needs a look", "Clean up")
}

func TestListFilters(t *testing.T) {
	newHome(t)
	_, all, _ := run(t, "", "list")
	if got := strings.Count(all, "\n"); got < 13 {
		t.Errorf("list has %d lines", got)
	}
	mustContain(t, all, "ID       AGENT", "13 grants.")

	tests := []struct {
		args []string
		want int // grants
	}{
		{[]string{"--agent", "codex"}, 6},
		{[]string{"--agent", "claude-code"}, 7},
		{[]string{"--kind", "trust"}, 4},
		{[]string{"--kind", "rule", "--agent", "codex"}, 4},
		{[]string{"--risk", "high"}, 5},
		{[]string{"--risk", "medium"}, 10},
		{[]string{"--flag", "dead-path"}, 4},
		{[]string{"--flag", "secret"}, 1},
		{[]string{"--flag", "one-off"}, 2},
		{[]string{"--flag", "unused"}, 6},
		{[]string{"--flag", "committed"}, 0},
	}
	for _, tt := range tests {
		code, out, errs := run(t, "", append([]string{"list", "--json"}, tt.args...)...)
		if code != 0 {
			t.Errorf("%v: code %d %s", tt.args, code, errs)
			continue
		}
		var rows []row
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Errorf("%v: %v", tt.args, err)
			continue
		}
		if len(rows) != tt.want {
			t.Errorf("%v: %d grants, want %d", tt.args, len(rows), tt.want)
		}
	}

	_, none, _ := run(t, "", "list", "--flag", "committed")
	mustContain(t, none, "No grants match.")

	// JSON is redacted and is an array even when empty.
	_, js, _ := run(t, "", "list", "--json", "--flag", "secret")
	mustContain(t, js, "[redacted]")
	mustNotContain(t, js, "abcdefghij0123456789")
	_, js, _ = run(t, "", "list", "--json", "--flag", "committed")
	if strings.TrimSpace(js) != "[]" {
		t.Errorf("empty JSON = %q", js)
	}
}

func TestListFlagsMayFollowArguments(t *testing.T) {
	newHome(t)
	code, out, _ := run(t, "", "list", "--no-color", "--agent", "codex", "--json")
	if code != 0 || !strings.HasPrefix(out, "[") {
		t.Errorf("code=%d out=%q", code, out)
	}
	m := ids(t)
	id := m["codex rule git push"]
	code, out, _ = run(t, "", "show", id, "--json")
	if code != 0 || !strings.Contains(out, `"value": "git push"`) {
		t.Errorf("show id --json: code=%d out=%q", code, out)
	}
}

func TestListShowsGoneOnlyWithAll(t *testing.T) {
	h := newHome(t)
	run(t, "") // run 1 records the grants
	// The Codex rule for npm disappears before the next run.
	rewrite(t, h.codexRules, strings.Replace(readFile(t, h.codexRules), "prefix_rule(pattern=[\"npm\", \"test\"], decision=\"allow\")\n", "", 1), "2026-07-01T09:00:00Z")
	t.Setenv("GRANTS_NOW", "2026-10-14T12:00:00Z")
	_, out, _ := run(t, "", "list", "--agent", "codex")
	mustNotContain(t, out, "npm test")
	mustContain(t, out, "1 hidden (gone or not readable): --all shows them.")
	_, out, _ = run(t, "", "list", "--all", "--agent", "codex")
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "npm test") {
			line = l
		}
	}
	if !strings.HasSuffix(line, "gone") {
		t.Errorf("the gone grant should be listed with --all, flagged gone: %q", line)
	}
	_, out, _ = run(t, "", "log")
	mustContain(t, squash(out), "2026-10-13..2026-10-14 codex removed npm test")
}

func TestShow(t *testing.T) {
	h := newHome(t)
	m := ids(t)

	code, out, _ := run(t, "", "show", m["codex rule git push"])
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out,
		"git push",
		"codex rule · "+m["codex rule git push"],
		"Status    active",
		"Where     ~/.codex/rules/default.rules:2",
		"Applies   everywhere",
		"Granted   "+window(h.codexRules, "2026-05-01", "2026-06-01")+" (Codex session snapshot)",
		"Used      never (history from 2026-06-01)",
		"Risk      high: pushes code to a remote",
		"Revoke    grants revoke "+m["codex rule git push"]+" (Restart Codex to apply.)",
		"Evidence",
		"2026-06-01 10:00  present  Codex session snapshot",
	)

	// An id may be shortened.
	short := m["codex rule git push"][:4]
	if code, out2, _ := run(t, "", "show", short); code != 0 || out2 != out {
		t.Errorf("short id: code=%d", code)
	}

	// A rule that the agent asked for shows why.
	_, out, _ = run(t, "", "show", m["codex rule curl -L https://example.com/a/b?x=1"])
	mustContain(t, out, "one-off:", "Granted   ~2026-06-01 (approved when the agent asked)", "proposed", "download the report")

	// The credential is hidden everywhere.
	_, out, _ = run(t, "", "show", m["claude-code rule Bash(curl -H 'Authorization: [redacted]' https://example.com/x)"])
	mustContain(t, out, "[redacted]", "secret:", "Applies   only in ~/work/app (shared project settings)")
	mustNotContain(t, out, "abcdefghij0123456789")

	// Trust grants.
	_, out, _ = run(t, "", "show", m["claude-code trust "+h.gone])
	mustContain(t, out, "~/work/gone", "Applies   ~/work/gone and everything inside it", "dead-path:")

	// Errors.
	if code, _, errs := run(t, "", "show", "zzzz"); code != 1 || !strings.Contains(errs, `no grant has the id "zzzz"`) {
		t.Errorf("unknown id: code=%d %q", code, errs)
	}
	if code, _, errs := run(t, "", "show", "ab"); code != 1 || !strings.Contains(errs, "at least 4 characters") {
		t.Errorf("short id: code=%d %q", code, errs)
	}
	if code, _, _ := run(t, "", "show"); code != 2 {
		t.Errorf("no id: code=%d", code)
	}
}

func TestResolveID(t *testing.T) {
	grants := []model.Grant{{ID: "abcd111", Agent: model.Codex, Value: "one"}, {ID: "abcd222", Agent: model.Codex, Value: "two"}, {ID: "ef01234"}}
	_, err := resolve(grants, "abcd", "/home/u")
	if err == nil || !strings.Contains(err.Error(), "matches 2 grants") || !strings.Contains(err.Error(), "abcd111") || !strings.Contains(err.Error(), "two") {
		t.Errorf("ambiguous: %v", err)
	}
	if g, err := resolve(grants, "ABCD2", "/home/u"); err != nil || g.ID != "abcd222" {
		t.Errorf("prefix, any case: %v %v", g.ID, err)
	}
	// An exact id wins over longer ids that start with it.
	g, err := resolve([]model.Grant{{ID: "abcd"}, {ID: "abcd222"}}, "abcd", "/home/u")
	if err != nil || g.ID != "abcd" {
		t.Errorf("exact id: %v %v", g.ID, err)
	}
	if _, err := resolve(grants, "abc", "/home/u"); err == nil || !strings.Contains(err.Error(), "at least 4") {
		t.Errorf("short: %v", err)
	}
}

func TestLogAndScan(t *testing.T) {
	h := newHome(t)
	code, out, _ := run(t, "", "log")
	if code != 0 {
		t.Fatal(code)
	}
	// Grants whose file has no birth time (not macOS) only show "existed by", so the
	// split between dated events and the unknown-date section depends on the system.
	var all []event
	_, js, _ := run(t, "", "log", "--json")
	if err := json.Unmarshal([]byte(js), &all); err != nil || len(all) != 13 {
		t.Fatalf("log --json: %v, %d events", err, len(all))
	}
	undated := 0
	for _, e := range all {
		if e.ExistenceOnly {
			undated++
		}
	}
	const title = "Dates unknown; these existed by:"
	datedPart, rest, hasSection := strings.Cut(out, title)
	if hasSection != (undated > 0) {
		t.Errorf("section = %v with %d existence-only events:\n%s", hasSection, undated, out)
	}
	if n := len(strings.Split(strings.TrimSpace(datedPart), "\n")); n != 13-undated {
		t.Errorf("%d dated lines, want %d:\n%s", n, 13-undated, out)
	}
	_ = rest
	sq := squash(out)
	mustContain(t, sq,
		"~2026-06-01 claude-code granted ~/work/app (first Claude Code session in this folder)",
		"~2026-06-01 codex granted curl -L https://example.com/a/b?x=1 (approved when the agent asked)",
	)
	if hasBirth(h.claudeProj) && hasBirth(h.codexRules) {
		mustContain(t, sq,
			"2026-08-20..2026-09-01 claude-code granted Bash(make:*) (settings file last changed)",
			"2026-05-01..2026-06-01 codex granted git push (Codex session snapshot)",
		)
		// Newest first, and the grant that grants only saw today is not among the dated events.
		if !strings.HasPrefix(out, "2026-08-20..2026-09-01") || strings.Contains(datedPart, "first seen by grants") {
			t.Errorf("order:\n%s", out)
		}
	}

	_, out, _ = run(t, "", "log", "--agent", "codex", "--since", "2026-07-01")
	mustContain(t, out, "/work/missing/tool.sh")
	mustNotContain(t, out, "claude-code", "git push")

	_, out, _ = run(t, "", "log", "--json", "--agent", "codex")
	var events []event
	if err := json.Unmarshal([]byte(out), &events); err != nil || len(events) == 0 || events[0].Event != "granted" || events[0].GrantID == "" {
		t.Errorf("json: %v %s", err, out)
	}

	if code, _, errs := run(t, "", "log", "--since", "yesterday"); code != 2 || !strings.Contains(errs, "--since") {
		t.Errorf("bad --since: %d %q", code, errs)
	}

	code, out, _ = run(t, "", "scan")
	mustContain(t, out, "Scanned in ", "Claude Code  7 active grants", "Codex  6 active grants", "Claude Code transcripts  1 file  2026-06-01 to 2026-10-03", "Codex sessions  1 file")
	_, out, _ = run(t, "", "scan", "--no-cache")
	mustContain(t, out, "saved results ignored")
}

// settle reads the config files the revoke tests compare.
func (h *home) files(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, p := range []string{h.claudeUser, h.claudeProj, h.claudeJSON, h.codexCfg, h.codexRules} {
		m[p] = readFile(t, p)
	}
	return m
}

func sameFiles(t *testing.T, got, want map[string]string) {
	t.Helper()
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s differs:\n got %q\nwant %q", filepath.Base(p), got[p], w)
		}
	}
}

func TestRevokeUndo(t *testing.T) {
	h := newHome(t)
	original := h.files(t)
	m := ids(t)
	a := m["claude-code rule Bash(git push:*)"]
	b := m["claude-code rule Read(~/notes/**)"]
	c := m["codex rule git push"]

	// Dry run: shows the plan, writes nothing.
	code, out, errs := run(t, "", "revoke", a, b, c, "--dry-run")
	if code != 0 || errs != "" {
		t.Fatalf("dry run: code=%d %q", code, errs)
	}
	mustContain(t, out,
		"Plan: revoke 3 grants in 2 files.",
		`remove "Bash(git push:*)" from permissions.allow`,
		`- "Bash(git push:*)",`,
		"~/.claude/settings.json",
		"~/.codex/rules/default.rules",
		`- prefix_rule(pattern=["git", "push"], decision="allow")`,
		"Claude Code applies it on the next tool call.",
		"Restart Codex to apply.",
		"Dry run. Nothing was changed.",
	)
	sameFiles(t, h.files(t), original)

	// Without --yes and without a terminal, revoke refuses and changes nothing.
	code, _, errs = run(t, "", "revoke", a)
	if code != 1 || !strings.Contains(errs, "needs a terminal") {
		t.Errorf("no terminal: code=%d %q", code, errs)
	}
	sameFiles(t, h.files(t), original)

	// Revoke two grants in one file and one in another.
	code, out, errs = run(t, "", "revoke", a, b, c, "--yes")
	if code != 0 || errs != "" {
		t.Fatalf("revoke: code=%d %q\n%s", code, errs, out)
	}
	mustContain(t, out, "Revoked 3 grants. Backup: "+filepath.Join(h.state, "backups"), "Undo: grants undo", "Restart Codex to apply.")
	if strings.Count(out, "Restart Codex to apply.") != 2 { // once in the plan, once at the end
		t.Errorf("note repeated:\n%s", out)
	}
	got := h.files(t)
	if got[h.claudeUser] != "{\n  \"permissions\": {\n    \"allow\": [\n      \"Bash(npm test:*)\"\n    ]\n  }\n}\n" {
		t.Errorf("claude settings:\n%s", got[h.claudeUser])
	}
	if got[h.codexRules] != strings.Replace(original[h.codexRules], "prefix_rule(pattern=[\"git\", \"push\"], decision=\"allow\")\n", "", 1) {
		t.Errorf("codex rules:\n%s", got[h.codexRules])
	}
	for _, p := range []string{h.claudeProj, h.claudeJSON, h.codexCfg} {
		if got[p] != original[p] {
			t.Errorf("%s changed", filepath.Base(p))
		}
	}

	// The next run sees the rules as gone, and the log says who removed them.
	_, out, _ = run(t, "", "log")
	mustContain(t, out, "revoked", "Bash(git push:*)", "git push")
	if n := strings.Count(out, " removed "); n != 0 {
		t.Errorf("revoked grants must not also show as removed:\n%s", out)
	}

	// Undo puts every byte back.
	code, out, errs = run(t, "", "undo")
	if code != 0 || errs != "" {
		t.Fatalf("undo: code=%d %q", code, errs)
	}
	mustContain(t, out, "Restored 2 files", "~/.claude/settings.json", "~/.codex/rules/default.rules", "undone: remove")
	sameFiles(t, h.files(t), original)
	_, out, _ = run(t, "", "log")
	mustContain(t, out, "undone")

	// A second undo has nothing to do.
	if code, _, errs := run(t, "", "undo"); code != 1 || !strings.Contains(errs, "nothing to undo") {
		t.Errorf("second undo: code=%d %q", code, errs)
	}
}

func TestRevokeDead(t *testing.T) {
	h := newHome(t)
	original := h.files(t)

	code, out, _ := run(t, "", "revoke", "--dead", "--dry-run")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	mustContain(t, out, "Plan: revoke 4 grants in 4 files.", "~/work/gone", "~/work/gone2", "/work/missing/tool.sh", "notes")
	sameFiles(t, h.files(t), original)

	code, out, errs := run(t, "", "revoke", "--dead", "--yes")
	if code != 0 {
		t.Fatalf("code=%d %q", code, errs)
	}
	mustContain(t, out, "Revoked 4 grants.")
	got := h.files(t)
	// Claude: the dead rule leaves the user file, the dead folder stops being trusted.
	if strings.Contains(got[h.claudeUser], "notes") || !strings.Contains(got[h.claudeUser], "Bash(git push:*)") {
		t.Errorf("claude settings:\n%s", got[h.claudeUser])
	}
	var cj struct {
		Projects map[string]struct {
			Trusted bool `json:"hasTrustDialogAccepted"`
		}
	}
	if err := json.Unmarshal([]byte(got[h.claudeJSON]), &cj); err != nil {
		t.Fatal(err)
	}
	if cj.Projects[h.gone].Trusted || !cj.Projects[h.app].Trusted {
		t.Errorf("claude trust = %+v", cj.Projects)
	}
	// Codex: the missing folder's table is removed; the existing one stays.
	if strings.Contains(got[h.codexCfg], "gone2") || !strings.Contains(got[h.codexCfg], h.app) || !strings.Contains(got[h.codexCfg], "/work/other") {
		t.Errorf("codex config:\n%s", got[h.codexCfg])
	}
	if strings.Contains(got[h.codexRules], "missing") || !strings.Contains(got[h.codexRules], `"git", "push"`) {
		t.Errorf("codex rules:\n%s", got[h.codexRules])
	}

	// Nothing is left to clean up.
	code, out, _ = run(t, "", "revoke", "--dead", "--dry-run")
	if code != 0 || !strings.Contains(out, "No grants point to deleted paths") {
		t.Errorf("second --dead: code=%d %q", code, out)
	}
	_, out, _ = run(t, "", "")
	mustNotContain(t, out, "grants revoke --dead")

	if code, _, _ := run(t, "", "undo"); code != 0 {
		t.Fatal("undo failed")
	}
	sameFiles(t, h.files(t), original)
}

func TestRevokeQuestion(t *testing.T) {
	h := newHome(t)
	original := h.files(t)
	m := ids(t)
	id := m["codex rule /work/missing/tool.sh"]
	old := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return true }
	defer func() { stdinIsTerminal = old }()

	for _, answer := range []string{"\n", "n\n", "no\n", "", "maybe\n"} {
		code, out, _ := run(t, answer, "revoke", id)
		if code != 0 || !strings.Contains(out, "Revoke 1 grant? [y/N] ") || !strings.Contains(out, "Cancelled. Nothing was changed.") {
			t.Errorf("answer %q: code=%d\n%s", answer, code, out)
		}
		sameFiles(t, h.files(t), original)
	}
	code, out, _ := run(t, "Y\n", "revoke", id)
	if code != 0 || !strings.Contains(out, "Revoked 1 grant.") {
		t.Errorf("yes: code=%d\n%s", code, out)
	}
	if strings.Contains(readFile(t, h.codexRules), "missing") {
		t.Error("rule still there")
	}
}

func TestRevokeRefusals(t *testing.T) {
	h := newHome(t)
	original := h.files(t)
	m := ids(t)
	id := m["codex rule git push"]

	for _, tt := range []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"no arguments", []string{"revoke"}, 2, "give a grant id, or use --dead"},
		{"unknown id", []string{"revoke", "zzzz", "--yes"}, 1, `no grant has the id "zzzz"`},
		{"short id", []string{"revoke", id[:3], "--yes"}, 1, "at least 4 characters"},
		{"bad flag", []string{"revoke", id, "--frobnicate"}, 2, "flag provided but not defined"},
		{"bad --unused", []string{"revoke", id, "--unused", "0"}, 2, "--unused needs a number of days"},
	} {
		code, _, errs := run(t, "", tt.args...)
		if code != tt.code || !strings.Contains(errs, tt.msg) {
			t.Errorf("%s: code=%d stderr=%q", tt.name, code, errs)
		}
	}
	sameFiles(t, h.files(t), original)

	// A grant that is already gone cannot be revoked by id.
	run(t, "") // record
	rewrite(t, h.codexRules, strings.Replace(original[h.codexRules], "prefix_rule(pattern=[\"npm\", \"test\"], decision=\"allow\")\n", "", 1), "2026-07-01T09:00:00Z")
	t.Setenv("GRANTS_NOW", "2026-10-14T12:00:00Z")
	goneID := id
	_, listOut, _ := run(t, "", "list", "--all", "--json", "--agent", "codex")
	var rows []row
	json.Unmarshal([]byte(listOut), &rows)
	for _, r := range rows {
		if r.Value == "npm test" {
			goneID = r.ID
		}
	}
	code, _, errs := run(t, "", "revoke", goneID, "--yes")
	if code != 1 || !strings.Contains(errs, "already removed") {
		t.Errorf("gone grant: code=%d %q", code, errs)
	}
}

func TestRevokeManagedIsRefused(t *testing.T) {
	h := newHome(t)
	managed := filepath.Join(h.root, "managed")
	put(t, filepath.Join(managed, "managed-settings.json"), `{"permissions":{"allow":["Bash(echo:*)"]}}`)
	restore := overrideManaged(managed)
	defer restore()
	m := ids(t)
	id := m["claude-code rule Bash(echo:*)"]
	code, _, errs := run(t, "", "revoke", id, "--yes")
	if code != 1 || !strings.Contains(errs, "organization") {
		t.Errorf("code=%d %q", code, errs)
	}
	_, out, _ := run(t, "", "show", id)
	mustContain(t, out, "cannot revoke: Set by your organization.")
}

func TestUndoRefusesChangedFile(t *testing.T) {
	h := newHome(t)
	m := ids(t)
	id := m["codex rule /work/missing/tool.sh"]
	if code, _, errs := run(t, "", "revoke", id, "--yes"); code != 0 {
		t.Fatalf("revoke: %q", errs)
	}
	edited := readFile(t, h.codexRules) + "# edited by hand\n"
	os.WriteFile(h.codexRules, []byte(edited), 0o644)

	code, _, errs := run(t, "", "undo")
	if code != 1 || !strings.Contains(errs, "default.rules") || !strings.Contains(errs, "--force") {
		t.Errorf("undo: code=%d %q", code, errs)
	}
	if readFile(t, h.codexRules) != edited {
		t.Error("undo wrote to a changed file")
	}
	code, out, _ := run(t, "", "undo", "--force")
	if code != 0 || !strings.Contains(out, "Restored 1 file") || !strings.Contains(readFile(t, h.codexRules), "missing") {
		t.Errorf("force: code=%d %q", code, out)
	}
}

func TestRevokeFileChangedAfterPlanning(t *testing.T) {
	// The plan is made from the file as it was read; edit.Apply refuses when it changed.
	// Simulated here through the stdin question: the file changes while grants waits.
	h := newHome(t)
	m := ids(t)
	id := m["codex rule /work/missing/tool.sh"]
	old := stdinIsTerminal
	stdinIsTerminal = func(io.Reader) bool { return true }
	defer func() { stdinIsTerminal = old }()
	rd := &changeWhileReading{path: h.codexRules}
	var out, errb strings.Builder
	code := Main([]string{"revoke", id}, rd, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "nothing was written") {
		t.Errorf("code=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(readFile(t, h.codexRules), "# agent edit") || !strings.Contains(readFile(t, h.codexRules), "missing") {
		t.Error("the file must keep the agent's edit and the rule")
	}
}

// changeWhileReading edits a file when grants reads the answer, like an agent writing
// the file while the question is open.
type changeWhileReading struct{ path string }

func (c *changeWhileReading) Read(p []byte) (int, error) {
	b, _ := os.ReadFile(c.path)
	os.WriteFile(c.path, append(b, []byte("# agent edit\n")...), 0o644)
	return copy(p, "y\n"), nil
}

func TestUsageAndHelp(t *testing.T) {
	newHome(t)
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {"list", "-h"}, {"revoke", "--help"}, {"help", "log"}} {
		code, out, errs := run(t, "", args...)
		if code != 0 || out == "" || errs != "" || !strings.Contains(out, "Usage:") && !strings.Contains(out, "grants lists") {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
	}
	_, out, _ := run(t, "", "help")
	for _, c := range []string{"list", "show", "log", "revoke", "undo", "scan", "version"} {
		mustContain(t, out, c)
	}
	mustContain(t, out, "--no-color", "--unused", "--no-cache")

	for _, tt := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"frobnicate"}, 2, `unknown command "frobnicate"`},
		{[]string{"list", "--risk", "extreme"}, 2, "--risk must be"},
		{[]string{"list", "--agent", "cursor"}, 2, "--agent must be"},
		{[]string{"list", "--kind", "mode"}, 2, "--kind must be"},
		{[]string{"list", "--flag", "weird"}, 2, "--flag must be"},
		{[]string{"list", "extra"}, 2, "unexpected argument"},
		{[]string{"--nonsense"}, 2, "flag provided but not defined"},
		{[]string{"help", "nothing"}, 2, "no help for"},
	} {
		code, _, errs := run(t, "", tt.args...)
		if code != tt.code || !strings.Contains(errs, tt.msg) {
			t.Errorf("%v: code=%d stderr=%q", tt.args, code, errs)
		}
	}

	Version = "v9.9.9"
	defer func() { Version = "dev" }()
	for _, args := range [][]string{{"version"}, {"--version"}} {
		if code, out, _ := run(t, "", args...); code != 0 || out != "grants v9.9.9\n" {
			t.Errorf("%v: %d %q", args, code, out)
		}
	}
}

func TestGlobalFlagsOnSummary(t *testing.T) {
	newHome(t)
	code, out, _ := run(t, "", "--no-color", "--unused", "30", "--no-cache")
	if code != 0 || !strings.HasPrefix(out, "grants:") {
		t.Errorf("code=%d %q", code, out)
	}
	// With a shorter window, history (from 2026-06-01) still covers it, and the flag text follows it.
	mustContain(t, out, "not used in 30 days")
}

func TestBrokenFilesDoNotCrash(t *testing.T) {
	h := newHome(t)
	os.WriteFile(h.claudeUser, []byte("{ not json"), 0o644)
	os.WriteFile(h.claudeJSON, []byte("\x00\x01"), 0o644)
	os.WriteFile(h.codexCfg, []byte("[[[ nope"), 0o644)
	os.WriteFile(h.codexRules, []byte("prefix_rule(pattern=[\n"), 0o644)
	for _, args := range [][]string{{}, {"list", "--all"}, {"log"}, {"scan"}, {"revoke", "--dead", "--dry-run"}} {
		code, out, errs := run(t, "", args...)
		if code != 0 {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errs)
		}
	}
	_, out, _ := run(t, "")
	mustContain(t, out, "Note:")
}

func TestOutputFitsTheTerminal(t *testing.T) {
	newHome(t)
	for _, cols := range []string{"120", "130"} {
		t.Setenv("COLUMNS", cols)
		w := 120
		if cols == "130" {
			w = 130
		}
		for _, args := range [][]string{{"list", "--all"}, {""}, {"log"}} {
			_, out, _ := run(t, "", args...)
			for _, l := range strings.Split(out, "\n") {
				// Notes and the log detail are prose; they may wrap.
				if width(l) > w && !strings.HasPrefix(l, "Claude Code keeps") && !strings.Contains(l, "(") {
					t.Errorf("COLUMNS=%s %v: line is %d wide: %q", cols, args, width(l), l)
				}
			}
		}
	}
}
