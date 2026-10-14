package cli

import (
	"bytes"
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

	// check runs every command and expects the exit code it should give, and no raw
	// control character or forged line in either output.
	check := func(t *testing.T, cases []hostileCase) {
		t.Helper()
		for _, c := range cases {
			code, out, errs := run(t, "", append(c.args, "--no-color")...)
			if code != c.code {
				t.Errorf("grants %v: exit %d, want %d\nstdout: %q\nstderr: %q", c.args, code, c.code, out, errs)
			}
			if strings.ContainsAny(out+errs, "\x1b\x07") || strings.Contains(out+errs, "\nFAKE LINE") {
				t.Errorf("grants %v printed raw control characters:\nstdout: %q\nstderr: %q", c.args, out, errs)
			}
		}
	}
	check(t, []hostileCase{
		{nil, 0}, {[]string{"list", "--all"}, 0}, {[]string{"log"}, 0},
		{[]string{"show", ruleID}, 0}, {[]string{"show", trustID}, 0},
		{[]string{"revoke", ruleID, "--dry-run"}, 0}, {[]string{"revoke", trustID, "--dry-run"}, 0},
	})

	// Both grants are removed from their files. The next run reports them as gone, and
	// naming one to revoke is an error that quotes its text.
	put(t, h.claudeUser, "{\"permissions\":{\"allow\":[]}}\n")
	put(t, h.claudeJSON, "{\"projects\":{}}\n")
	m = ids(t)
	goneRule := h.id(t, m, "claude-code", "rule", rule)
	goneTrust := h.id(t, m, "claude-code", "trust", folder)
	check(t, []hostileCase{
		{nil, 0}, {[]string{"list", "--all"}, 0}, {[]string{"log"}, 0},
		{[]string{"show", goneRule}, 0}, {[]string{"show", goneTrust}, 0},
		{[]string{"revoke", goneRule}, exitError}, {[]string{"revoke", goneTrust, "--yes"}, exitError},
		{[]string{"revoke", goneRule, goneTrust, "--dry-run"}, exitError},
	})
	// The error still says what is wrong.
	_, _, errs := run(t, "", "revoke", goneRule, "--dry-run", "--no-color")
	if !strings.Contains(errs, "already removed") || !strings.Contains(errs, `\x1b`) {
		t.Errorf("error for a gone grant = %q", errs)
	}
}

type hostileCase struct {
	args []string
	code int
}

func TestAmbiguousIDErrorKeepsItsLinesAndCleansEachOne(t *testing.T) {
	grants := []model.Grant{
		{ID: "abcd001", Agent: model.Codex, Kind: model.KindRule, Value: "one\x1b[2K\nFAKE LINE"},
		{ID: "abcd002", Agent: model.Codex, Kind: model.KindRule, Value: "two"},
	}
	_, err := resolve(grants, "abcd", "/home/u")
	if err == nil {
		t.Fatal("want an ambiguity error")
	}
	var sb strings.Builder
	a := &app{stderr: &sb}
	if code := a.fail("%v", err); code != exitError {
		t.Fatalf("code = %d", code)
	}
	out := sb.String()
	if strings.ContainsAny(out, "\x1b") || strings.Contains(out, "\nFAKE LINE") {
		t.Errorf("raw text in %q", out)
	}
	if n := strings.Count(out, "\n"); n != 3 { // header, two ids, no extra
		t.Errorf("%d line breaks in %q, want 3", n, out)
	}
}

func TestVersionRejectsExtraArguments(t *testing.T) {
	if code, out, _ := run(t, "", "version"); code != 0 || !strings.HasPrefix(out, "grants ") {
		t.Errorf("version: code=%d %q", code, out)
	}
	if code, _, errs := run(t, "", "version", "extra"); code != exitUsage || !strings.Contains(errs, "unexpected argument") {
		t.Errorf("version extra: code=%d %q", code, errs)
	}
	if code, _, errs := run(t, "", "version", "--no-color", "extra"); code != exitUsage || !strings.Contains(errs, "unexpected argument") {
		t.Errorf("version --no-color extra: code=%d %q", code, errs)
	}
	if code, _, errs := run(t, "", "help", "list", "extra"); code != exitUsage || !strings.Contains(errs, "unexpected argument") {
		t.Errorf("help list extra: code=%d %q", code, errs)
	}
}

func TestVersionAndHelpTakeGlobalFlagsInAnyPosition(t *testing.T) {
	newHome(t)
	_, wantVersion, _ := run(t, "", "version")
	_, wantHelp, _ := run(t, "", "help", "list")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"version", "--no-color"}, wantVersion},
		{[]string{"--no-color", "version"}, wantVersion},
		{[]string{"version", "--no-cache", "--unused", "30"}, wantVersion},
		{[]string{"--no-color", "help", "list"}, wantHelp},
		{[]string{"help", "list", "--no-color"}, wantHelp},
		{[]string{"help", "--no-color", "list"}, wantHelp},
	} {
		code, out, errs := run(t, "", tt.args...)
		if code != 0 || errs != "" || out != tt.want {
			t.Errorf("grants %v: code=%d out=%q err=%q", tt.args, code, out, errs)
		}
	}
	if code, _, errs := run(t, "", "version", "--bogus"); code != exitUsage || errs == "" {
		t.Errorf("version --bogus: code=%d %q", code, errs)
	}
}

func TestUnusedHintWorksForEveryWindow(t *testing.T) {
	newHome(t)
	// The summary names a command with the window in it, in the form that always parses.
	res := core.Result{Env: model.Env{UnusedAfter: 1000 * 24 * time.Hour}, Grants: []model.Grant{cleanGrant("unused1", model.FlagUnused)},
		Reports: []model.Report{{Agent: model.Codex, Found: true}}}
	var sb strings.Builder
	renderSummary(&sb, res, style{}, 100)
	mustContain(t, sb.String(), "grants revoke --unused=1000")
	// Both spellings take a window of up to 5 digits.
	for _, args := range [][]string{
		{"revoke", "--unused=1000", "--dry-run"}, {"revoke", "--unused", "1000", "--dry-run"},
		{"revoke", "--unused", "36500", "--dry-run"}, {"revoke", "--dry-run", "--unused", "12345"},
	} {
		if code, _, errs := run(t, "", args...); code != 0 {
			t.Errorf("grants %v: code %d %q", args, code, errs)
		}
	}
	if code, _, errs := run(t, "", "revoke", "--unused", "36501", "--dry-run"); code != exitUsage || !strings.Contains(errs, "1 to 36500") {
		t.Errorf("36501: code %d %q", code, errs)
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

func TestUndoForceTellsWhereYourNewerVersionWasSaved(t *testing.T) {
	h := newHome(t)
	id := ids(t)["codex rule /work/missing/tool.sh"]
	if code, _, errs := run(t, "", "revoke", id, "--yes"); code != 0 {
		t.Fatalf("revoke: %q", errs)
	}
	edited := readFile(t, h.codexRules) + "# edited by hand\n"
	put(t, h.codexRules, edited)

	_, _, errs := run(t, "", "undo", "--no-color")
	if !strings.Contains(errs, "keeps a copy of the current file") {
		t.Errorf("the refusal does not say what --force keeps: %q", errs)
	}
	code, out, errs := run(t, "", "undo", "--force", "--no-color")
	if code != 0 {
		t.Fatalf("undo --force: %d %q", code, errs)
	}
	i := strings.Index(out, "Your newer version was saved to ")
	if i < 0 {
		t.Fatalf("output does not name the saved copy:\n%s", out)
	}
	path := strings.TrimSpace(out[i+len("Your newer version was saved to "):])
	path = strings.Replace(path, "~", h.home, 1)
	if got := readFile(t, strings.SplitN(path, "\n", 2)[0]); got != edited {
		t.Errorf("the saved copy holds %q, want the edited file", got)
	}
	// A plain undo, with nothing to save, prints no such line.
	run(t, "", "revoke", id, "--yes")
	if _, out, _ := run(t, "", "undo"); strings.Contains(out, "newer version") {
		t.Errorf("undo of an untouched file mentions a saved copy: %q", out)
	}
}

func TestHelpFlagErrorPointsToExistingHelp(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"help", "--bogus"}, strings.NewReader(""), &out, &errb)
	if code != exitUsage || !strings.Contains(errb.String(), "Run grants help to see the commands.") {
		t.Errorf("code %d, stderr %q", code, errb.String())
	}
}

func TestFailKeepsLineBreaksOfJoinedErrors(t *testing.T) {
	var errb bytes.Buffer
	a := &app{stderr: &errb}
	a.fail("%v", errors.Join(errors.New("first \x1b[2K file"), errors.New("second file")))
	got := errb.String()
	if !strings.Contains(got, "first \\x1b[2K file\nsecond file") {
		t.Errorf("stderr %q", got)
	}
}
