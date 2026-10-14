package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/revoke"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFmtWindow(t *testing.T) {
	local = time.UTC
	defer func() { local = time.Local }()
	tests := []struct {
		name string
		w    model.Window
		want string
	}{
		{"unknown", model.Window{}, "unknown"},
		{"exact", model.Window{After: at("2026-03-05 10:00"), Before: at("2026-03-05 10:00").Add(30 * time.Second)}, "2026-03-05"},
		{"within one day", model.Window{After: at("2026-03-05 01:00"), Before: at("2026-03-05 23:00")}, "2026-03-05"},
		{"range", model.Window{After: at("2026-03-05 10:00"), Before: at("2026-04-02 10:00")}, "2026-03-05..2026-04-02"},
		{"only before", model.Window{Before: at("2026-07-10 08:00")}, "before 2026-07-10"},
		{"approx", model.Window{After: at("2026-07-01 00:00"), Before: at("2026-07-17 08:00"), Approx: true}, "~2026-07-17"},
		{"approx with no lower bound", model.Window{Before: at("2026-07-17 08:00"), Approx: true}, "~2026-07-17"},
		{"only after", model.Window{After: at("2026-07-17 08:00")}, "after 2026-07-17"},
	}
	for _, tt := range tests {
		if got := fmtWindow(tt.w); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestFmtWindowUsesLocalTime(t *testing.T) {
	// 23:30 UTC is already the next day in a zone east of UTC.
	local = time.FixedZone("east", 2*3600)
	defer func() { local = time.Local }()
	if got := fmtWindow(model.Window{Before: at("2026-03-05 23:30")}); got != "before 2026-03-06" {
		t.Errorf("got %q", got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in       string
		n        int
		mid, end string
	}{
		{"short", 10, "short", "short"},
		{"exactly10!", 10, "exactly10!", "exactly10!"},
		{"abcdefghijklmnop", 10, "abcde…mnop", "abcdefghi…"},
		{"héllo wörld ünïcode", 9, "héll…code", "héllo wö…"},
		{"abc", 1, "a", "a"},
		{"abc", 0, "", ""},
	}
	for _, tt := range tests {
		if got := truncMiddle(tt.in, tt.n); got != tt.mid || width(got) > max(tt.n, 0) {
			t.Errorf("truncMiddle(%q,%d) = %q, want %q", tt.in, tt.n, got, tt.mid)
		}
		if got := truncEnd(tt.in, tt.n); got != tt.end {
			t.Errorf("truncEnd(%q,%d) = %q, want %q", tt.in, tt.n, got, tt.end)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := tilde("/home/u/work/app", "/home/u"); got != "~/work/app" {
		t.Errorf("tilde = %q", got)
	}
	for in, want := range map[string]string{"/home/u": "~", "/home/user2/x": "/home/user2/x", "/etc": "/etc"} {
		if got := tilde(in, "/home/u"); got != want {
			t.Errorf("tilde(%q) = %q, want %q", in, got, want)
		}
	}
	if got := tilde("/x", ""); got != "/x" {
		t.Errorf("tilde with no home = %q", got)
	}
	if got := tildeText("move /home/u/a to /home/u/b but not /home/ux/c", "/home/u"); got != "move ~/a to ~/b but not /home/ux/c" {
		t.Errorf("tildeText = %q", got)
	}
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 4823: "4,823", 1234567: "1,234,567", -1234: "-1,234"} {
		if got := commas(n); got != want {
			t.Errorf("commas(%d) = %q, want %q", n, got, want)
		}
	}
	if plural(1, "grant", "grants") != "1 grant" || plural(2, "grant", "grants") != "2 grants" || plural(1500, "file", "files") != "1,500 files" {
		t.Error("plural")
	}
	if got := padRight("é", 3) + "|" + padLeft("é", 3); got != "é  |  é" {
		t.Errorf("pad = %q", got)
	}
}

func TestGrantTextRedacts(t *testing.T) {
	g := model.Grant{Kind: model.KindRule, Value: "Bash(curl -H 'Authorization: Bearer abcdefghij0123456789' https://example.com)"}
	if got := grantText(g, "/home/u"); strings.Contains(got, "abcdefghij") || !strings.Contains(got, "[redacted]") {
		t.Errorf("grantText = %q", got)
	}
	g = model.Grant{Kind: model.KindRule, Value: "Bash(echo a\nb)"}
	if got := grantText(g, ""); strings.Contains(got, "\n") {
		t.Errorf("newline kept: %q", got)
	}
	tr := model.Grant{Kind: model.KindTrust, Value: "/home/u/x"}
	if got := grantText(tr, "/home/u"); got != "~/x" {
		t.Errorf("trust = %q", got)
	}
}

func TestRedactGrantCopies(t *testing.T) {
	secret := "Bearer abcdefghij0123456789"
	g := model.Grant{
		Key: "k|" + secret, Value: "v " + secret, Pattern: [][]string{{"curl", secret}},
		Evidence: []model.Evidence{{Detail: "asked: " + secret}},
	}
	r := redactGrant(g)
	if strings.Contains(r.Key+r.Value+r.Pattern[0][1]+r.Evidence[0].Detail, "abcdefghij0123456789") {
		t.Errorf("not redacted: %+v", r)
	}
	if !strings.Contains(g.Pattern[0][1], "abcdefghij") || !strings.Contains(g.Evidence[0].Detail, "abcdefghij") {
		t.Error("redactGrant changed the original")
	}
}

func TestScopeLastUsedFlags(t *testing.T) {
	home := "/home/u"
	if got := scopeText(model.Grant{Scope: model.ScopeProject, Project: "/home/u/x"}, home); got != "project ~/x" {
		t.Errorf("scope = %q", got)
	}
	if got := scopeText(model.Grant{Scope: model.ScopeUser}, home); got != "user" {
		t.Errorf("scope = %q", got)
	}
	if got := scopeText(model.Grant{Scope: model.ScopeManaged}, home); got != "managed" {
		t.Errorf("scope = %q", got)
	}
	local = time.UTC
	defer func() { local = time.Local }()
	last := at("2026-07-01 10:00")
	for _, tt := range []struct {
		u    model.Usage
		want string
	}{
		{model.Usage{}, "?"},
		{model.Usage{Known: true}, "never"},
		{model.Usage{Known: true, Count: 3, Last: last}, "2026-07-01"},
		{model.Usage{Known: true, Count: 3}, "?"},
	} {
		if got := lastUsed(model.Grant{Usage: tt.u}); got != tt.want {
			t.Errorf("lastUsed(%+v) = %q, want %q", tt.u, got, tt.want)
		}
	}
	if got := flagsText(model.Grant{Status: model.StatusGone, Flags: []model.Flag{model.FlagOneOff}}); got != "gone,one-off" {
		t.Errorf("flags = %q", got)
	}
	if got := flagsText(model.Grant{Status: model.StatusActive}); got != "" {
		t.Errorf("flags = %q", got)
	}
}

func TestStyle(t *testing.T) {
	off, on := style{}, style{on: true}
	if off.bold("x") != "x" || off.level(model.RiskHigh, "x") != "x" {
		t.Error("style off must not add codes")
	}
	if got := on.bold("x"); got != "\x1b[1mx\x1b[0m" {
		t.Errorf("bold = %q", got)
	}
	if on.level(model.RiskHigh, "h") != on.red("h") || on.level(model.RiskMedium, "m") != on.yellow("m") || on.level(model.RiskLow, "l") != "l" {
		t.Error("level colors")
	}
	if on.dim("") != "" {
		t.Error("empty text must stay empty")
	}
}

func TestProgressLine(t *testing.T) {
	got := progressLine(map[string][2]int{"Codex sessions": {1200, 4823}, "Claude Code transcripts": {40, 900}})
	if want := "Reading Claude Code transcripts 40/900 · Codex sessions 1,200/4,823"; got != want {
		t.Errorf("got %q", got)
	}
}

func TestProgressStaysQuietWhenFast(t *testing.T) {
	var sb strings.Builder
	p := startProgress(&sb, 80)
	p.update("Codex sessions", 10, 100)
	time.Sleep(200 * time.Millisecond)
	p.finish()
	if sb.String() != "" {
		t.Errorf("progress wrote %q before the delay", sb.String())
	}

	sb.Reset()
	p = startProgress(&sb, 80)
	p.delay = 0
	p.update("Codex sessions", 10, 100)
	time.Sleep(400 * time.Millisecond)
	p.update("Codex sessions", 100, 100)
	p.finish()
	out := sb.String()
	if !strings.Contains(out, "Reading Codex sessions 10/100") || !strings.HasSuffix(out, "\r\x1b[2K") {
		t.Errorf("progress output = %q", out)
	}
}

func TestTermWidth(t *testing.T) {
	var sb strings.Builder
	t.Setenv("COLUMNS", "")
	if got := termWidth(&sb); got != 120 {
		t.Errorf("default width = %d", got)
	}
	t.Setenv("COLUMNS", "77")
	if got := termWidth(&sb); got != 77 {
		t.Errorf("COLUMNS width = %d", got)
	}
	t.Setenv("COLUMNS", "junk")
	if got := termWidth(&sb); got != 120 {
		t.Errorf("bad COLUMNS width = %d", got)
	}
}

// summaryResult builds a result of n high-risk Codex rules, for rendering tests.
func summaryResult(n int) core.Result {
	res := core.Result{Env: model.Env{Home: "/home/u", UnusedAfter: 90 * 24 * time.Hour}}
	res.Reports = []model.Report{{Agent: model.ClaudeCode}, {Agent: model.Codex, Found: true}}
	for i := range n {
		res.Grants = append(res.Grants, model.Grant{
			ID: "id" + string(rune('a'+i)) + "0000", Agent: model.Codex, Kind: model.KindRule, Value: "rm -rf /tmp/" + strings.Repeat("x", i),
			Status: model.StatusActive, Revocable: true, Risk: model.Risk{Level: model.RiskHigh, Reasons: []string{"deletes files"}},
			Usage: model.Usage{Known: true}, Granted: model.Window{Before: at("2026-03-01 00:00").Add(time.Duration(i) * time.Hour)},
		})
	}
	return res
}

func TestRenderSummaryAgentMissing(t *testing.T) {
	var sb strings.Builder
	renderSummary(&sb, summaryResult(2), style{}, 100)
	out := sb.String()
	mustContain(t, out, "grants: 2 active grants across 1 agent. 2 need a look.", "Claude Code   not found")
	mustNotContain(t, out, "Clean up")
}

func TestRenderSummaryNarrowTerminal(t *testing.T) {
	var sb strings.Builder
	renderSummary(&sb, summaryResult(3), style{}, 60)
	out := sb.String()
	look := out[strings.Index(out, "Needs a look"):]
	look = look[:strings.Index(look, "\n\n")]
	for _, l := range strings.Split(look, "\n") {
		if width(l) > 60 {
			t.Errorf("line is wider than the terminal (%d): %q", width(l), l)
		}
	}
}

func TestRenderSummaryColor(t *testing.T) {
	var sb strings.Builder
	renderSummary(&sb, summaryResult(2), style{on: true}, 100)
	out := sb.String()
	mustContain(t, out, "\x1b[1mgrants:\x1b[0m", "\x1b[31mhigh\x1b[0m")
}

func TestRenderSummaryOnlyOneNeedsALook(t *testing.T) {
	var sb strings.Builder
	renderSummary(&sb, summaryResult(1), style{}, 100)
	mustContain(t, sb.String(), "1 needs a look.", "Next: grants show ida0000")
}

func TestNeedsLookOrder(t *testing.T) {
	mk := func(id string, lvl model.Level, day string, flags ...model.Flag) model.Grant {
		return model.Grant{ID: id, Status: model.StatusActive, Revocable: true, Risk: model.Risk{Level: lvl}, Flags: flags, Granted: model.Window{Before: at(day + " 00:00")}}
	}
	managed := mk("managed-dead", model.RiskHigh, "2026-03-01", model.FlagDeadPath)
	managed.Revocable = false
	grants := []model.Grant{
		mk("unused-new", model.RiskLow, "2026-05-01", model.FlagUnused),
		mk("unused-high", model.RiskHigh, "2026-02-01", model.FlagUnused),
		mk("oneoff", model.RiskMedium, "2026-04-01", model.FlagOneOff),
		mk("oneoff-high", model.RiskHigh, "2026-04-01", model.FlagOneOff),
		mk("high-old", model.RiskHigh, "2026-01-01"),
		mk("high-new", model.RiskHigh, "2026-03-01"),
		mk("secret-old", model.RiskHigh, "2025-01-01", model.FlagSecret),
		mk("secret-oneoff", model.RiskHigh, "2025-02-01", model.FlagSecret, model.FlagOneOff),
		mk("dead-high", model.RiskHigh, "2026-03-01", model.FlagDeadPath),
		managed, // grants cannot revoke it, so it is not a clean-up job
		mk("fine", model.RiskLow, "2026-03-01"),
		{ID: "gone-high", Status: model.StatusGone, Risk: model.Risk{Level: model.RiskHigh}},
	}
	var got []string
	for _, g := range needsLook(grants) {
		got = append(got, g.ID)
	}
	// Dead-path and one-off grants go to Clean up, except one that holds a secret. High
	// risk grants that are only unused stay.
	want := "secret-oneoff secret-old high-new managed-dead unused-high high-old"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

func TestRenderPlanCompactForManyGrants(t *testing.T) {
	const file = "/home/u/.codex/rules/default.rules"
	var items []revoke.Item
	for i := range 12 {
		items = append(items, revoke.Item{
			Grant: model.Grant{ID: fmt.Sprintf("id%05d", i)}, File: file, Summary: "remove prefix_rule rm /home/u/x",
			Diff: []string{"- prefix_rule(pattern=[\"rm\"], decision=\"allow\")"}, Note: "Restart Codex to apply.",
		})
	}
	var sb strings.Builder
	renderPlan(&sb, items, []edit.Change{{File: file}}, nil, style{}, "/home/u")
	out := sb.String()
	if strings.Count(out, "\n") > 30 || strings.Contains(out, "- prefix_rule") {
		t.Errorf("a long plan must be one line per grant:\n%s", out)
	}
	mustContain(t, out, "Plan: revoke 12 grants in 1 file.", "id00000  remove prefix_rule rm ~/x", "Files that change:", "~/.codex/rules/default.rules", "Restart Codex to apply.")

	sb.Reset()
	renderPlan(&sb, items[:2], []edit.Change{{File: file}}, []revoke.Skip{{Grant: model.Grant{ID: "zz"}, Err: errors.New("grant zz is already removed")}}, style{}, "/home/u")
	mustContain(t, sb.String(), "id00000  remove prefix_rule rm ~/x", "- prefix_rule(", "1 grant was left out", "already removed")
}
