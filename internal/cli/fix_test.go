package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/revoke"
)

func TestCleanControlCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":     "plain text",
		"a\x1b[2Kb":      `a\x1b[2Kb`,
		"bell\x07":       `bell\x07`,
		"two\nlines\r":   `two\x0alines\x0d`,
		"del\x7f":        `del\x7f`,
		"c1\u0085\u009b": `c1\x85\x9b`,
		"héllo 世界":       "héllo 世界",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	// Every display helper goes through it.
	for name, got := range map[string]string{
		"tilde":     tilde("/home/u/\x1b[2K", "/home/u"),
		"tilde raw": tilde("/x/\x1b[2K", "/home/u"),
		"tildeText": tildeText("in /home/u/a\x1b[2K", "/home/u"),
		"oneLine":   oneLine("a\x1b[2K b"),
		"grantText": grantText(model.Grant{Kind: model.KindTrust, Value: "/work/\x1b[2K\nFAKE"}, "/home/u"),
	} {
		if strings.ContainsAny(got, "\x1b\n") {
			t.Errorf("%s leaves a control character: %q", name, got)
		}
	}
}

func TestRenderPlanCleansControlCharacters(t *testing.T) {
	items := []revoke.Item{{
		Grant: model.Grant{ID: "id00000"}, File: "/home/u/.codex/rules/x\x1b[2K.rules", Summary: "remove /home/u/\x1b[1Aevil",
		Diff: []string{"- prefix_rule(pattern=[\"\x1b[2K\"])"}, Note: "Restart\x1b[2K Codex.",
	}}
	var sb strings.Builder
	renderPlan(&sb, items, []edit.Change{{File: items[0].File}}, nil, style{}, "/home/u")
	if strings.ContainsRune(sb.String(), 0x1b) {
		t.Errorf("the plan has a raw escape:\n%q", sb.String())
	}
}

func TestHostileConfigTextIsNotPrintedRaw(t *testing.T) {
	h := newHome(t)
	rule := "Bash(echo \x1b[2Kfake)"
	put(t, h.claudeUser, fmt.Sprintf("{\"permissions\":{\"allow\":[%s]}}\n", jstr(rule)))
	folder := h.home + "/work/\x1b]0;x\x07\nFAKE LINE"
	put(t, h.claudeJSON, fmt.Sprintf("{\"projects\":{%s:{\"hasTrustDialogAccepted\":true}}}\n", jstr(folder)))

	m := ids(t)
	ruleID := h.id(t, m, "claude-code", "rule", rule)
	trustID := h.id(t, m, "claude-code", "trust", folder)
	for _, args := range [][]string{
		{"list", "--all"}, {"log"}, {""}, {"show", ruleID}, {"show", trustID},
		{"revoke", ruleID, "--dry-run"}, {"revoke", trustID, "--dry-run"},
	} {
		_, out, errs := run(t, "", append(args, "--no-color")...)
		if strings.ContainsAny(out+errs, "\x1b\x07") || strings.Contains(out, "\nFAKE LINE") {
			t.Errorf("grants %v printed raw control characters:\n%q", args, out)
		}
	}
}

func TestVersionRejectsExtraArguments(t *testing.T) {
	if code, out, _ := run(t, "", "version"); code != 0 || !strings.HasPrefix(out, "grants ") {
		t.Errorf("version: code=%d %q", code, out)
	}
	if code, _, errs := run(t, "", "version", "extra"); code != exitUsage || !strings.Contains(errs, "unexpected argument") {
		t.Errorf("version extra: code=%d %q", code, errs)
	}
}

func TestUnusedDaysHaveAnUpperLimit(t *testing.T) {
	newHome(t)
	for _, v := range []string{"106752", "999999999999", "36501"} {
		code, _, errs := run(t, "", "list", "--unused", v)
		if code != exitUsage || !strings.Contains(errs, "1 to 36500") {
			t.Errorf("--unused %s: code=%d %q", v, code, errs)
		}
	}
	if code, _, errs := run(t, "", "list", "--unused", "36500"); code != 0 {
		t.Errorf("--unused 36500: code=%d %q", code, errs)
	}
	if code, _, errs := run(t, "", "revoke", "--unused=999999", "--dry-run"); code != exitUsage || !strings.Contains(errs, "1 to 36500") {
		t.Errorf("revoke --unused=999999: code=%d %q", code, errs)
	}
}

func TestGlobalFlagsBeforeTheCommand(t *testing.T) {
	newHome(t)
	_, want, _ := run(t, "", "list", "--no-color")
	for _, args := range [][]string{
		{"--no-color", "list"},
		{"--no-color", "--no-cache", "list"},
		{"--unused", "30", "list", "--no-color"},
		{"--unused=30", "list", "--no-color"},
	} {
		code, out, errs := run(t, "", args...)
		if code != 0 || errs != "" {
			t.Errorf("grants %v: code=%d %q", args, code, errs)
		}
		if len(args) < 3 && out != want { // same window as the plain call
			t.Errorf("grants %v printed a different list", args)
		}
	}
	// A flag before the command still reaches revoke's own parser.
	code, out, _ := run(t, "", "--no-color", "revoke", "--dead", "--dry-run")
	if code != 0 || !strings.Contains(out, "Dry run") {
		t.Errorf("--no-color revoke --dead --dry-run: code=%d %q", code, out)
	}
	// Flags alone still give the summary; an unknown word is still an unknown command.
	if code, out, _ := run(t, "", "--no-color"); code != 0 || !strings.Contains(out, "active grants") {
		t.Errorf("flags only: code=%d %q", code, out)
	}
	if code, _, errs := run(t, "", "--no-color", "frobnicate"); code != exitUsage || !strings.Contains(errs, `unknown command "frobnicate"`) {
		t.Errorf("unknown: code=%d %q", code, errs)
	}
	// "--unused revoke" must not take the command name for a number of days.
	if code, out, _ := run(t, "", "--unused", "revoke", "--dead", "--dry-run"); code != 0 || !strings.Contains(out, "Dry run") {
		t.Errorf("--unused revoke: code=%d %q", code, out)
	}
}

// The count next to each bulk command is what that command would select.
func TestSummaryCountsEqualRevokeSelection(t *testing.T) {
	grants := []model.Grant{
		cleanGrant("a1", model.FlagDeadPath, model.FlagOneOff, model.FlagUnused),
		cleanGrant("a2", model.FlagDeadPath, model.FlagUnused),
		cleanGrant("a3", model.FlagOneOff),
		cleanGrant("a4", model.FlagUnused),
	}
	var d, o, u int
	for _, g := range grants {
		if isDead(g) {
			d++
		}
		if isOneOff(g) {
			o++
		}
		if isUnused(g) {
			u++
		}
	}
	out := summaryOf(grants...)
	mustContain(t, out,
		fmt.Sprintf("%d grants point to deleted paths: grants revoke --dead", d),
		fmt.Sprintf("%d one-off rules, approved for a single URL or script: grants revoke --one-off", o),
		fmt.Sprintf("%d grants not used in 90 days: grants revoke --unused", u),
	)
}
