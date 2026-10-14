package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/model"
)

// --- revoke selectors ---

func TestRevokeOneOff(t *testing.T) {
	h := newHome(t)
	original := h.files(t)

	code, out, errs := run(t, "", "revoke", "--one-off", "--dry-run")
	if code != 0 || errs != "" {
		t.Fatalf("code=%d %q", code, errs)
	}
	// The rule with a credential and the Codex rule for one URL.
	mustContain(t, out, "Plan: revoke 2 grants in 2 files.", "example.com/x", "example.com/a/b", "Dry run")
	mustNotContain(t, out, "remove \"Bash(make:*)\"", "remove prefix_rule git push")
	sameFiles(t, h.files(t), original)

	if code, out, _ := run(t, "", "revoke", "--one-off", "--yes"); code != 0 || !strings.Contains(out, "Revoked 2 grants.") {
		t.Fatalf("revoke: code=%d %q", code, out)
	}
	got := h.files(t)
	if strings.Contains(got[h.claudeProj], "example.com") || strings.Contains(got[h.codexRules], "example.com") || !strings.Contains(got[h.claudeProj], "make:*") {
		t.Errorf("wrong rules removed:\n%s\n%s", got[h.claudeProj], got[h.codexRules])
	}
	if _, out, _ := run(t, "", "revoke", "--one-off", "--dry-run"); !strings.Contains(out, "No one-off rules found. Nothing to revoke.") {
		t.Errorf("second run: %q", out)
	}
	if code, _, _ := run(t, "", "undo"); code != 0 {
		t.Fatal("undo failed")
	}
	sameFiles(t, h.files(t), original)
}

func TestRevokeUnusedAndCombinations(t *testing.T) {
	h := newHome(t)
	original := h.files(t)
	m := ids(t)

	// Unused: 2 plain rules, the Codex one-off, and the 3 dead grants that are also unused.
	_, out, _ := run(t, "", "revoke", "--unused", "--dry-run")
	mustContain(t, out, "Plan: revoke 6 grants in ")
	mustNotContain(t, out, m["claude-code rule Bash(make:*)"], m["claude-code rule Bash(npm test:*)"])

	// --unused takes the window as a separate word, and it is not read as an id. A
	// shorter window also catches the rule with a credential, last changed on 2026-09-01.
	code, out, errs := run(t, "", "revoke", "--unused", "30", "--dry-run")
	if code != 0 {
		t.Fatalf("--unused 30: code=%d %q", code, errs)
	}
	mustContain(t, out, "Plan: revoke 7 grants in ")
	if code, out, _ := run(t, "", "revoke", "--unused=1", "--dry-run"); code != 0 || !strings.Contains(out, "Plan: revoke ") {
		t.Errorf("--unused=1: code=%d %q", code, out)
	}
	// The window is a number.
	if code, _, errs := run(t, "", "revoke", "--unused=0", "--dry-run"); code != 2 || !strings.Contains(errs, "--unused") {
		t.Errorf("--unused=0: code=%d %q", code, errs)
	}
	if code, _, errs := run(t, "", "revoke", "--unused=soon", "--dry-run"); code != 2 || !strings.Contains(errs, "--unused") {
		t.Errorf("--unused=soon: code=%d %q", code, errs)
	}

	// Selectors combine with each other and with ids, and a grant counts once.
	_, out, _ = run(t, "", "revoke", "--dead", "--one-off", "--dry-run")
	mustContain(t, out, "Plan: revoke 6 grants in ")
	_, out, _ = run(t, "", "revoke", "--dead", "--unused", "--one-off", "--dry-run")
	mustContain(t, out, "Plan: revoke 8 grants in ")
	make := m["claude-code rule Bash(make:*)"]
	_, out, _ = run(t, "", "revoke", make, "--one-off", "--dry-run")
	mustContain(t, out, "Plan: revoke 3 grants in ", make)
	_, out, _ = run(t, "", "revoke", "--one-off", make, "--dry-run")
	mustContain(t, out, "Plan: revoke 3 grants in ")

	// The whole selection can be applied and undone.
	if code, out, _ := run(t, "", "revoke", "--unused", "--yes"); code != 0 || !strings.Contains(out, "Revoked 6 grants.") {
		t.Fatalf("revoke --unused: code=%d %q", code, out)
	}
	if got := h.files(t); strings.Contains(got[h.claudeUser], "git push") || !strings.Contains(got[h.claudeUser], "npm test") {
		t.Errorf("claude settings:\n%s", got[h.claudeUser])
	}
	if _, out, _ := run(t, "", "revoke", "--unused", "--dry-run"); !strings.Contains(out, "No grants were unused for 90 days. Nothing to revoke.") {
		t.Errorf("second run: %q", out)
	}
	run(t, "", "undo")
	sameFiles(t, h.files(t), original)

	// With nothing to pick from, the usage error names the selectors.
	if code, _, errs := run(t, "", "revoke"); code != 2 || !strings.Contains(errs, "--dead, --one-off or --unused") {
		t.Errorf("no argument: code=%d %q", code, errs)
	}
}

func TestSelectorsSkipManagedAndInactive(t *testing.T) {
	mk := func(status model.Status, revocable bool, flag model.Flag) model.Grant {
		return model.Grant{Status: status, Revocable: revocable, Flags: []model.Flag{flag}}
	}
	for _, c := range []struct {
		f   model.Flag
		sel func(model.Grant) bool
	}{{model.FlagDeadPath, isDead}, {model.FlagOneOff, isOneOff}, {model.FlagUnused, isUnused}} {
		if !c.sel(mk(model.StatusActive, true, c.f)) {
			t.Errorf("%s: an active, revocable grant must match", c.f)
		}
		if c.sel(mk(model.StatusActive, false, c.f)) || c.sel(mk(model.StatusGone, true, c.f)) || c.sel(mk(model.StatusUnknown, true, c.f)) {
			t.Errorf("%s: a managed, gone or unreadable grant must not match", c.f)
		}
		if c.sel(model.Grant{Status: model.StatusActive, Revocable: true}) {
			t.Errorf("%s: a grant without the flag must not match", c.f)
		}
	}
}

func TestJoinUnusedDays(t *testing.T) {
	got := joinUnusedDays([]string{"--unused", "30", "abcd123", "--unused", "abcd123", "-unused", "7", "--dead", "--unused", "1234", "--unused", "36500", "--unused", "123456"})
	want := "--unused=30 abcd123 --unused abcd123 --unused=7 --dead --unused=1234 --unused=36500 --unused 123456"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q, want %q", strings.Join(got, " "), want)
	}
}

// --- summary ---

func cleanGrant(id string, flags ...model.Flag) model.Grant {
	return model.Grant{ID: id, Agent: model.Codex, Kind: model.KindRule, Value: "tool " + id, Status: model.StatusActive, Revocable: true,
		Flags: flags, Risk: model.Risk{Level: model.RiskLow}, Usage: model.Usage{Known: true}}
}

func summaryOf(grants ...model.Grant) string {
	res := core.Result{Env: model.Env{Home: "/home/u", UnusedAfter: core.DefaultUnusedAfter}, Grants: grants}
	res.Reports = []model.Report{{Agent: model.Codex, Found: true}}
	var sb strings.Builder
	renderSummary(&sb, res, style{}, 100)
	return sb.String()
}

func TestSummaryCleanUpCountsMatchWhatRevokeSelects(t *testing.T) {
	out := summaryOf(
		cleanGrant("dead1", model.FlagDeadPath, model.FlagOneOff, model.FlagUnused),
		cleanGrant("dead2", model.FlagDeadPath),
		cleanGrant("one1", model.FlagOneOff, model.FlagUnused),
		cleanGrant("unused1", model.FlagUnused),
		cleanGrant("unused2", model.FlagUnused),
		cleanGrant("unused3", model.FlagUnused),
	)
	mustContain(t, out,
		"Clean up",
		"2 grants point to deleted paths: grants revoke --dead",
		"2 one-off rules, approved for a single URL or script: grants revoke --one-off",
		"5 grants not used in 90 days: grants revoke --unused",
		"Nothing needs a look.",
	)
	if n := strings.Count(out, "Files are backed up first."); n != 1 {
		t.Errorf("the backup hint appears %d times, want once:\n%s", n, out)
	}
	// The order is dead, one-off, unused.
	d, o, u := strings.Index(out, "--dead"), strings.Index(out, "--one-off"), strings.Index(out, "--unused")
	if !(d < o && o < u) {
		t.Errorf("order:\n%s", out)
	}
}

func TestSummaryCleanUpSingularAndWindow(t *testing.T) {
	res := core.Result{Env: model.Env{UnusedAfter: 30 * 24 * time.Hour}, Grants: []model.Grant{
		cleanGrant("dead1", model.FlagDeadPath), cleanGrant("unused1", model.FlagUnused),
	}, Reports: []model.Report{{Agent: model.Codex, Found: true}}}
	var sb strings.Builder
	renderSummary(&sb, res, style{}, 100)
	mustContain(t, sb.String(), "1 grant points to a deleted path: grants revoke --dead", "1 grant not used in 30 days: grants revoke --unused=30")
}

func TestSummarySkipsManagedInCleanUp(t *testing.T) {
	g := cleanGrant("managed", model.FlagDeadPath)
	g.Revocable = false
	mustNotContain(t, summaryOf(g), "Clean up")
}

func TestSummaryGrantGetsWidth(t *testing.T) {
	long := "Bash(" + strings.Repeat("a", 70) + ")"
	g := cleanGrant("big1")
	g.Value, g.Risk = long, model.Risk{Level: model.RiskHigh, Reasons: []string{"allows a thing"}}
	res := core.Result{Env: model.Env{UnusedAfter: core.DefaultUnusedAfter}, Grants: []model.Grant{g}, Reports: []model.Report{{Agent: model.Codex, Found: true}}}
	var sb strings.Builder
	renderSummary(&sb, res, style{}, 150)
	mustContain(t, sb.String(), long) // the old 34-character cap would cut it
	sb.Reset()
	renderSummary(&sb, res, style{}, 90)
	for _, l := range strings.Split(sb.String(), "\n") {
		if width(l) > 90 && strings.Contains(l, "big1") {
			t.Errorf("line is wider than the terminal (%d): %q", width(l), l)
		}
	}
}

// --- shortening ---

func TestShortenURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/a/b/c?x=1#top": "https://example.com/…/c",
		"https://example.com/a/b/":          "https://example.com/…/b",
		"https://example.com/a":             "https://example.com/a",
		"https://example.com/a?x=1":         "https://example.com/a",
		"https://example.com/":              "https://example.com",
		"https://example.com?x=1":           "https://example.com",
		"http://localhost:8080/x/y.json,":   "http://localhost:8080/…/y.json,",
	} {
		if got := shortenURL(in); got != want {
			t.Errorf("shortenURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShortenValue(t *testing.T) {
	const rule = "Bash(curl -H 'Accept: x' https://api.example.com/v1/items/42/details?full=1&page=2 -o out.json)"
	// Fits: untouched, URL and all.
	if got := shortenValue(rule, width(rule)); got != rule {
		t.Errorf("fit: %q", got)
	}
	// Too long: the URL shrinks first, and nothing else is cut if that is enough.
	want := "Bash(curl -H 'Accept: x' https://api.example.com/…/details -o out.json)"
	if got := shortenValue(rule, width(want)); got != want {
		t.Errorf("URL step: %q, want %q", got, want)
	}
	// Still too long: the middle goes.
	got := shortenValue(rule, 40)
	if width(got) != 40 || !strings.Contains(got, "…") || !strings.HasPrefix(got, "Bash(curl") || !strings.HasSuffix(got, "out.json)") {
		t.Errorf("middle step: %q (%d)", got, width(got))
	}
	// Two URLs in one rule are both shortened.
	two := "curl https://a.example.com/x/y/z https://b.example.com/p/q/r"
	const shortTwo = "curl https://a.example.com/…/z https://b.example.com/…/r"
	if got := shortenValue(two, width(shortTwo)); got != shortTwo {
		t.Errorf("two URLs: %q", got)
	}
	// A plain folder has no URL; only the middle goes.
	if got := shortenValue("~/work/a/very/long/folder/name", 16); width(got) != 16 {
		t.Errorf("folder: %q", got)
	}
}

func TestScopeShort(t *testing.T) {
	g := model.Grant{Scope: model.ScopeProject, Project: "/home/u/work/app"}
	if got := scopeShort(g); got != "project …/app" {
		t.Errorf("got %q", got)
	}
	g.Scope = model.ScopeLocal
	if got := scopeShort(g); got != "local …/app" {
		t.Errorf("got %q", got)
	}
	if got := scopeShort(model.Grant{Scope: model.ScopeUser}); got != "user" {
		t.Errorf("user: %q", got)
	}
	if got := scopeShort(model.Grant{Scope: model.ScopeManaged}); got != "managed" {
		t.Errorf("managed: %q", got)
	}
}

// listRows renders the list for synthetic grants and returns its lines.
func listRows(termW int, grants ...model.Grant) []string {
	res := core.Result{Env: model.Env{Home: "/home/u"}, Grants: grants}
	var sb strings.Builder
	renderList(&sb, grants, res, listOpts{all: true}, style{}, termW)
	return strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
}

func listGrant(id, value, project string) model.Grant {
	g := model.Grant{ID: id, Agent: model.ClaudeCode, Kind: model.KindRule, Value: value, Scope: model.ScopeUser, Status: model.StatusActive,
		Granted: model.Window{Before: at("2026-08-01 00:00"), After: at("2026-07-01 00:00")}, Risk: model.Risk{Level: model.RiskMedium}}
	if project != "" {
		g.Scope, g.Project = model.ScopeProject, project
	}
	return g
}

func TestListGivesWidthToGrantBeforeScope(t *testing.T) {
	const value = "Bash(curl -sS -X POST https://api.example.com/v1/hooks/build --data-binary @out.json)"
	const project = "/home/u/work/some/deep/folder/app"
	g := listGrant("aaaa111", value, project)
	// The other columns of this row take 78 characters, gaps included.
	const others = 78
	scopeFull, scopeCut := width(scopeText(g, "/home/u")), width(scopeShort(g))
	check := func(name string, termW int, want ...string) []string {
		rows := listRows(termW, g)
		for _, w := range want {
			if !strings.Contains(rows[1], w) {
				t.Errorf("%s (%d columns) lacks %q:\n%s", name, termW, w, strings.Join(rows, "\n"))
			}
		}
		for _, l := range rows {
			if width(l) > termW {
				t.Errorf("%s: line is %d wide, terminal is %d: %q", name, width(l), termW, l)
			}
		}
		return rows
	}

	check("everything fits", others+scopeFull+2+width(value), value, "project ~/work/some/deep/folder/app")
	// One column less: the project path shrinks, the grant stays whole.
	rows := check("short scope", others+scopeFull+1+width(value), value, "project …/app")
	if strings.Contains(rows[1], "deep") {
		t.Errorf("scope was not shortened:\n%s", rows[1])
	}
	// Less again: the URL inside the grant shrinks before any middle is cut.
	short := shortenURLs(value)
	check("short URL", others+scopeCut+2+width(short), "https://api.example.com/…/build --data-binary @out.json)", "project …/app")
	// Much less: the middle of the grant goes, and the scope is still there.
	rows = check("cut", others+scopeCut+2+40, "project …/app", "…")
	if strings.Contains(rows[1], "api.example.com/…/build") && !strings.Contains(rows[1], "…") {
		t.Errorf("cut:\n%s", rows[1])
	}
	// Very narrow: the scope column goes and the note says so.
	rows = listRows(80, g) // the other columns alone are 78 wide, so no line fits
	if strings.Contains(rows[0], "SCOPE") || !strings.Contains(strings.Join(rows, "\n"), "The scope column needs a wider terminal") {
		t.Errorf("80 columns:\n%s", strings.Join(rows, "\n"))
	}
}

// A typical grant is readable on a 150-column terminal, in full.
func TestListReadableAt150(t *testing.T) {
	rows := listRows(150,
		listGrant("aaaa111", "Bash(git commit -m:*)", "/home/u/work/some/deep/folder/app"),
		listGrant("bbbb222", "WebFetch(domain:docs.example.com)", ""),
		listGrant("cccc333", "Bash(curl -sS https://example.com/hooks/build)", "/home/u/work/app"),
	)
	out := strings.Join(rows, "\n")
	mustContain(t, out, "Bash(git commit -m:*)", "WebFetch(domain:docs.example.com)", "Bash(curl -sS https://example.com/hooks/build)")
	mustNotContain(t, out, "…/hooks")
}

// --- log ---

func TestLogMarksExistenceOnlyEvents(t *testing.T) {
	local = time.UTC
	t.Cleanup(func() { local = time.Local })
	res := core.Result{Env: model.Env{Home: "/home/u"}}
	mk := func(id, value string, w model.Window) model.Grant {
		return model.Grant{ID: id, Agent: model.Codex, Kind: model.KindRule, Value: value, Status: model.StatusActive, Granted: w}
	}
	res.Grants = []model.Grant{
		mk("exact1", "a", model.Window{After: at("2026-05-01 00:00"), Before: at("2026-05-01 00:00")}),
		mk("range1", "b", model.Window{After: at("2026-04-01 00:00"), Before: at("2026-05-02 00:00")}),
		mk("approx", "c", model.Window{Before: at("2026-05-03 00:00"), Approx: true}),
		mk("upper1", "d", model.Window{Before: at("2026-05-04 00:00")}),
	}
	got := map[string]bool{}
	for _, e := range buildEvents(res, nil) {
		got[e.GrantID] = e.ExistenceOnly
	}
	want := map[string]bool{"exact1": false, "range1": false, "approx": false, "upper1": true}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: existence_only = %v, want %v", id, got[id], w)
		}
	}
	b, _ := json.Marshal([]event{{Event: "granted"}, {Event: "granted", ExistenceOnly: true}})
	if strings.Count(string(b), "existence_only") != 1 {
		t.Errorf("the field must appear only when true: %s", b)
	}
}

func TestRenderLogGroupsUnknownDates(t *testing.T) {
	local = time.UTC
	t.Cleanup(func() { local = time.Local })
	var events []event
	add := func(date, agent, grant string, existence bool) {
		tm := at(date + " 00:00")
		events = append(events, event{Time: tm, Date: date, Agent: agent, Event: "granted", Grant: grant, ExistenceOnly: existence})
	}
	add("2026-09-10", "codex", "dated", false)
	for _, g := range []string{"one", "two", "three", "four", "five"} {
		add("2026-09-01", "codex", g, true)
	}
	add("2026-08-01", "claude-code", "solo", true)

	var sb strings.Builder
	renderLog(&sb, events, false, style{}, 120)
	out := sb.String()
	dated, rest, ok := strings.Cut(out, "Dates unknown; these existed by:\n")
	if !ok {
		t.Fatalf("no section:\n%s", out)
	}
	if strings.Contains(dated, "one") || !strings.Contains(dated, "dated") || !strings.HasSuffix(dated, "\n\n") {
		t.Errorf("dated part:\n%s", dated)
	}
	mustContain(t, squash(rest),
		"2026-09-01 5 grants one · two · three · +2 more",
		"2026-08-01 1 grant solo",
		"grants log --all lists each one.",
	)
	mustNotContain(t, rest, "four", "five")

	sb.Reset()
	renderLog(&sb, events, true, style{}, 120)
	_, rest, _ = strings.Cut(sb.String(), "Dates unknown; these existed by:\n")
	mustContain(t, rest, "four", "five", "solo")
	mustNotContain(t, rest, "more", "lists each one")
	if n := strings.Count(rest, "\n"); n != 6 {
		t.Errorf("--all has %d lines, want one per grant:\n%s", n, rest)
	}

	// Only unknown dates: no blank line before the section, and no dated part.
	sb.Reset()
	renderLog(&sb, events[1:], false, style{}, 120)
	if !strings.HasPrefix(sb.String(), "Dates unknown;") {
		t.Errorf("only undated:\n%s", sb.String())
	}
	// No unknown dates: no section.
	sb.Reset()
	renderLog(&sb, events[:1], false, style{}, 120)
	mustNotContain(t, sb.String(), "Dates unknown")
}

func TestLogAllFlag(t *testing.T) {
	newHome(t)
	_, out, _ := run(t, "", "log", "--all")
	mustContain(t, out, "Dates unknown; these existed by:", "~/work/gone2")
	mustNotContain(t, out, "lists each one")
	if code, _, errs := run(t, "", "log", "--bogus"); code != 2 || errs == "" {
		t.Errorf("bad flag: %d", code)
	}
}

// --- show ---

func TestShowEvidencePathsAreShortAndWrapped(t *testing.T) {
	h := newHome(t)
	m := ids(t)
	id := m["codex rule curl -L https://example.com/a/b?x=1"]
	_, out, _ := run(t, "", "show", id)
	// Paths are relative to the agent home, so they do not start with ~/.codex.
	mustContain(t, out, "(sessions/2026/06/01/rollout-a.jsonl)", "(rules/default.rules)")
	mustNotContain(t, out, "~/.codex/sessions", h.home+"/.codex/sessions")

	for _, cols := range []string{"60", "45"} {
		t.Setenv("COLUMNS", cols)
		_, out, _ = run(t, "", "show", id)
		w := 60
		if cols == "45" {
			w = 45
		}
		in := false
		for _, l := range strings.Split(out, "\n") {
			if l == "Evidence" {
				in = true
			}
			if in && width(l) > w {
				t.Errorf("%s columns: evidence line is %d wide: %q", cols, width(l), l)
			}
		}
		mustContain(t, out, "sessions/2026/")
	}
}

func TestEvidenceSource(t *testing.T) {
	env := model.Env{Home: "/home/u", CodexHome: "/home/u/.codex", ClaudeDir: "/home/u/.claude"}
	for in, want := range map[string]string{
		"/home/u/.codex/sessions/2026/06/01/r.jsonl:3": "sessions/2026/06/01/r.jsonl:3",
		"/home/u/.claude/projects/-w/x.jsonl":          "projects/-w/x.jsonl",
		"/home/u/work/app/.claude/settings.json":       "~/work/app/.claude/settings.json",
		"/home/u/.claude.json":                         "~/.claude.json",
		"/etc/other":                                   "/etc/other",
	} {
		if got := evidenceSource(in, env); got != want {
			t.Errorf("evidenceSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWrapText(t *testing.T) {
	if got := wrapText("aaa bbb ccc dd", 7); strings.Join(got, "|") != "aaa bbb|ccc dd" {
		t.Errorf("got %q", got)
	}
	if got := wrapText("abcdefghij kl", 4); strings.Join(got, "|") != "abcd|efgh|ij|kl" {
		t.Errorf("long word: %q", got)
	}
	if got := wrapText("", 10); len(got) != 0 {
		t.Errorf("empty: %q", got)
	}
}

// --- plurals ---

func TestPluralMessages(t *testing.T) {
	if got := daysText(24 * time.Hour); got != "1 day" {
		t.Errorf("daysText(1) = %q", got)
	}
	if got := daysText(90 * 24 * time.Hour); got != "90 days" {
		t.Errorf("daysText(90) = %q", got)
	}
	// One grant, one file: the singular everywhere a count is printed.
	h := newHome(t)
	os.WriteFile(h.claudeUser, []byte(`{"permissions":{"allow":["Bash(ls:*)"]}}`), 0o644)
	os.Remove(h.claudeProj)
	os.WriteFile(h.claudeJSON, []byte(`{"firstStartTime":"2026-05-01T00:00:00Z"}`), 0o644)
	os.WriteFile(h.codexRules, []byte("\n"), 0o644)
	os.WriteFile(h.codexCfg, []byte("[projects.\""+h.gone2+"\"]\ntrust_level = \"trusted\"\n"), 0o644)

	_, out, _ := run(t, "")
	mustContain(t, out, "grants: 2 active grants across 2 agents.", "1 points to a deleted path.", "1 grant points to a deleted path: grants revoke --dead")
	_, out, _ = run(t, "", "list")
	mustContain(t, out, "2 grants.")
	_, out, _ = run(t, "", "revoke", "--dead", "--dry-run")
	mustContain(t, out, "Plan: revoke 1 grant in 1 file.")
	if code, out, _ := run(t, "", "revoke", "--dead", "--yes"); code != 0 || !strings.Contains(out, "Revoked 1 grant. Backup:") {
		t.Errorf("revoke: %q", out)
	}
	_, out, _ = run(t, "", "undo")
	mustContain(t, out, "Restored 1 file from the revoke of")
	_, out, _ = run(t, "", "scan")
	mustContain(t, out, "Codex  1 active grant")
}
