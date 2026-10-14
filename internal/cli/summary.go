package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/model"
)

// maxLook is how many grants the summary lists under "Needs a look".
const maxLook = 10

func (a *app) cmdSummary(args []string) int {
	var g globals
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	g.register(fs)
	rest, code, done := a.parse("summary", usages["summary"], fs, &g, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		fmt.Fprintf(a.stderr, "grants: unknown command %q\nRun grants help to see the commands.\n", rest[0])
		return exitUsage
	}
	res, code := a.collect(&g)
	if code != exitOK {
		return code
	}
	renderSummary(a.stdout, res, a.st, termWidth(a.stdout))
	return exitOK
}

// lookRank orders the reasons to look at a grant: a credential, then high risk.
func lookRank(g model.Grant) int {
	switch {
	case g.HasFlag(model.FlagSecret):
		return 0
	case g.Risk.Level == model.RiskHigh:
		return 1
	}
	return -1
}

// A grant that grants revoke can remove in bulk is dead, one-off or unused. The summary
// counts each grant in the first of these that fits, in this order.
type cleanup int

const (
	cleanNone cleanup = iota
	cleanDead
	cleanOneOff
	cleanUnused
)

// cleanupOf says which clean-up list an active, revocable grant belongs to.
func cleanupOf(g model.Grant) cleanup {
	switch {
	case g.Status != model.StatusActive || !g.Revocable:
		return cleanNone
	case g.HasFlag(model.FlagDeadPath):
		return cleanDead
	case g.HasFlag(model.FlagOneOff):
		return cleanOneOff
	case g.HasFlag(model.FlagUnused):
		return cleanUnused
	}
	return cleanNone
}

// The selectors of grants revoke. A grant can match several; revoke takes it once.
func isDead(g model.Grant) bool {
	return g.Status == model.StatusActive && g.Revocable && g.HasFlag(model.FlagDeadPath)
}
func isOneOff(g model.Grant) bool {
	return g.Status == model.StatusActive && g.Revocable && g.HasFlag(model.FlagOneOff)
}
func isUnused(g model.Grant) bool {
	return g.Status == model.StatusActive && g.Revocable && g.HasFlag(model.FlagUnused)
}

// needsLook picks active grants that are high risk or hold a secret. A grant that points
// to a deleted path or looks like a one-off is a clean-up job instead, unless it holds a
// secret: a credential in a rule is worth seeing by name. Most worrying first, then
// newest first.
func needsLook(grants []model.Grant) []model.Grant {
	var out []model.Grant
	for _, g := range grants {
		if g.Status != model.StatusActive || lookRank(g) < 0 {
			continue
		}
		if c := cleanupOf(g); (c == cleanDead || c == cleanOneOff) && !g.HasFlag(model.FlagSecret) {
			continue
		}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := lookRank(out[i]), lookRank(out[j]); ri != rj {
			return ri < rj
		}
		return windowTime(out[i].Granted).After(windowTime(out[j].Granted))
	})
	return out
}

// tally counts one agent's grants for the table.
type tally struct {
	found                 bool
	rules, trusts         int
	deadRules, deadTrusts int
	high, removed         int
	since                 time.Time
	hasSince              bool
}

func tallies(res core.Result) map[model.Agent]*tally {
	out := map[model.Agent]*tally{}
	for _, r := range res.Reports {
		out[r.Agent] = &tally{found: r.Found}
	}
	for _, g := range res.Grants {
		t := out[g.Agent]
		if t == nil {
			t = &tally{found: true}
			out[g.Agent] = t
		}
		switch g.Status {
		case model.StatusGone:
			t.removed++
			continue
		case model.StatusUnknown:
			continue
		}
		dead := g.HasFlag(model.FlagDeadPath)
		if g.Kind == model.KindTrust {
			t.trusts++
			if dead {
				t.deadTrusts++
			}
		} else {
			t.rules++
			if dead {
				t.deadRules++
			}
		}
		if g.Risk.Level == model.RiskHigh {
			t.high++
		}
		if g.Usage.Known && !g.Usage.Since.IsZero() && (!t.hasSince || g.Usage.Since.Before(t.since)) {
			t.since, t.hasSince = g.Usage.Since, true
		}
	}
	// Use the oldest history the adapter reported when no grant carries a date.
	for _, r := range res.Reports {
		t := out[r.Agent]
		if t.hasSince {
			continue
		}
		for _, c := range r.Coverage {
			if !c.From.IsZero() && (!t.hasSince || c.From.Before(t.since)) {
				t.since, t.hasSince = c.From, true
			}
		}
	}
	return out
}

func countText(n, dead int) string {
	if dead > 0 {
		return fmt.Sprintf("%d (%d deleted)", n, dead)
	}
	return fmt.Sprint(n)
}

// renderSummary prints the screen that `grants` shows with no command.
func renderSummary(w io.Writer, res core.Result, st style, termW int) {
	ts := tallies(res)
	order := []model.Agent{model.ClaudeCode, model.Codex}

	active, agents := 0, 0
	var clean [cleanUnused + 1]int
	for _, g := range res.Grants {
		if g.Status != model.StatusActive {
			continue
		}
		active++
		clean[cleanupOf(g)]++
	}
	dead := clean[cleanDead]
	for _, ag := range order {
		if t := ts[ag]; t != nil && t.found {
			agents++
		}
	}
	look := needsLook(res.Grants)

	// Headline: the result first.
	switch {
	case agents == 0:
		fmt.Fprintln(w, st.bold("grants: no Claude Code or Codex found on this machine."))
		fmt.Fprintln(w, "It looked for ~/.claude, ~/.claude.json and ~/.codex.")
		printNotes(w, res, st)
		return
	case active == 0:
		fmt.Fprintln(w, st.bold(fmt.Sprintf("grants: no active grants across %s.", plural(agents, "agent", "agents"))))
	default:
		parts := []string{fmt.Sprintf("%s across %s.", plural(active, "active grant", "active grants"), plural(agents, "agent", "agents"))}
		switch len(look) {
		case 0:
			parts = append(parts, "Nothing needs a look.")
		case 1:
			parts = append(parts, "1 needs a look.")
		default:
			parts = append(parts, fmt.Sprintf("%s need a look.", commas(len(look))))
		}
		switch {
		case dead == 1:
			parts = append(parts, "1 points to a deleted path.")
		case dead > 1:
			parts = append(parts, fmt.Sprintf("%s point to deleted paths.", commas(dead)))
		}
		fmt.Fprintln(w, st.bold("grants:")+" "+strings.Join(parts, " "))
	}
	fmt.Fprintln(w)

	// Table of what each agent holds.
	head := []string{"", "rules", "trusted folders", "high risk", "removed"}
	rows := [][]string{head}
	for _, ag := range order {
		t := ts[ag]
		if t == nil {
			continue
		}
		if !t.found {
			rows = append(rows, []string{agentName(ag), "not found", "", "", ""})
			continue
		}
		rows = append(rows, []string{agentName(ag), countText(t.rules, t.deadRules), countText(t.trusts, t.deadTrusts), fmt.Sprint(t.high), fmt.Sprint(t.removed)})
	}
	widths := make([]int, len(head))
	for _, r := range rows {
		for i, c := range r {
			widths[i] = max(widths[i], width(c))
		}
	}
	for ri, r := range rows {
		var sb strings.Builder
		for i, c := range r {
			if i > 0 {
				sb.WriteString("   ")
			}
			if i == 0 {
				sb.WriteString(padRight(c, widths[i]))
				continue
			}
			sb.WriteString(padLeft(c, widths[i]))
		}
		line := strings.TrimRight(sb.String(), " ")
		if ri == 0 {
			line = st.dim(line)
		}
		fmt.Fprintln(w, line)
	}

	// Grants to look at.
	if len(look) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.bold("Needs a look"))
		shown := look
		if len(shown) > maxLook {
			shown = shown[:maxLook]
		}
		renderLook(w, shown, res, st, termW)
		if rest := look[len(shown):]; len(rest) > 0 {
			fmt.Fprintf(w, "  %s\n", st.dim(fmt.Sprintf("+%s more: %s", commas(len(rest)), moreCommand(rest[0]))))
		}
	}

	// The bulk commands. Each grant is in the first list that fits.
	if clean[cleanDead]+clean[cleanOneOff]+clean[cleanUnused] > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.bold("Clean up"))
		if n := clean[cleanDead]; n > 0 {
			text := commas(n) + " grants point to deleted paths"
			if n == 1 {
				text = "1 grant points to a deleted path"
			}
			fmt.Fprintf(w, "  %s: %s\n", text, st.bold("grants revoke --dead"))
		}
		if n := clean[cleanOneOff]; n > 0 {
			fmt.Fprintf(w, "  %s, approved for a single URL or script: %s\n", plural(n, "one-off rule", "one-off rules"), st.bold("grants revoke --one-off"))
		}
		if n := clean[cleanUnused]; n > 0 {
			cmd := "grants revoke --unused"
			if res.Env.UnusedAfter != core.DefaultUnusedAfter {
				cmd += " " + strconv.Itoa(int(res.Env.UnusedAfter/(24*time.Hour)))
			}
			fmt.Fprintf(w, "  %s not used in %s: %s\n", plural(n, "grant", "grants"), daysText(res.Env.UnusedAfter), st.bold(cmd))
		}
		fmt.Fprintf(w, "  %s\n", st.dim("Files are backed up first. Preview with --dry-run. Undo with grants undo."))
	}

	fmt.Fprintln(w)
	if line := coverageLine(ts, order); line != "" {
		fmt.Fprintln(w, line)
	}
	printNotes(w, res, st)
	next := "<id>"
	if len(look) > 0 {
		next = look[0].ID
	}
	fmt.Fprintf(w, "%s\n", st.dim(fmt.Sprintf("Next: grants show %s · grants revoke %s · grants log", next, next)))
}

// renderLook prints one line per grant: id, agent, the grant, and why it is listed.
func renderLook(w io.Writer, list []model.Grant, res core.Result, st style, termW int) {
	home := res.Env.Home
	grantW := 0
	for _, g := range list {
		grantW = max(grantW, width(grantText(g, home)))
	}
	idW := 7
	for _, g := range list {
		idW = max(idW, width(g.ID))
	}
	agentW := 0
	for _, g := range list {
		agentW = max(agentW, width(string(g.Agent)))
	}
	// The grant gets the width first, but a very long one must leave 40 characters for
	// the reasons (the longest usual run is about that). The grant keeps at least 12.
	grantW = min(grantW, max(termW-(2+idW+2+agentW+2+2)-40, 12))
	prefix := 2 + idW + 2 + agentW + 2 + grantW + 2
	for _, g := range list {
		text := shortenValue(grantText(g, home), grantW)
		why := lookReasons(g)
		why = truncEnd(why, max(termW-prefix-1, 10))
		lvl := string(g.Risk.Level)
		if strings.HasPrefix(why, lvl) {
			why = st.level(g.Risk.Level, lvl) + why[len(lvl):]
		}
		fmt.Fprintf(w, "  %s  %s  %s  %s\n", st.dim(padRight(g.ID, idW)), padRight(string(g.Agent), agentW), padRight(text, grantW), why)
	}
}

// lookReasons is the text after a grant in the list: the risk level, the reasons, and
// how it was used.
func lookReasons(g model.Grant) string {
	// The reasons come last: they are the longest part, and a narrow terminal cuts the end.
	parts := []string{string(g.Risk.Level)}
	if g.HasFlag(model.FlagOneOff) {
		parts = append(parts, "one-off")
	}
	if g.HasFlag(model.FlagCommitted) {
		parts = append(parts, "shared in git")
	}
	if !g.Revocable {
		parts = append(parts, "set by your organization")
	}
	switch {
	case g.Usage.Known && g.Usage.Count == 0:
		parts = append(parts, "never used")
	case g.Usage.Known && !g.Usage.Last.IsZero():
		parts = append(parts, "last used "+fmtDate(g.Usage.Last))
	}
	seen := map[string]bool{}
	n := 0
	for _, r := range g.Risk.Reasons {
		if r == "" || seen[r] || n == 2 {
			continue
		}
		seen[r] = true
		parts = append(parts, r)
		n++
	}
	return strings.Join(parts, " · ")
}

// moreCommand is the command that lists what the summary left out, based on the first
// grant that is missing from the list.
func moreCommand(g model.Grant) string {
	if lookRank(g) == 0 {
		return "grants list --flag secret"
	}
	return "grants list --risk high"
}

// coverageLine says how far back the history reaches for each agent.
func coverageLine(ts map[model.Agent]*tally, order []model.Agent) string {
	var parts []string
	for _, ag := range order {
		if t := ts[ag]; t != nil && t.found && t.hasSince {
			parts = append(parts, fmt.Sprintf("%s from %s", agentName(ag), fmtDate(t.since)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "History covers " + strings.Join(parts, " and ") + "."
}

// printNotes prints what the adapters and the run had to say, one line each.
func printNotes(w io.Writer, res core.Result, st style) {
	var notes []model.Note
	for _, r := range res.Reports {
		notes = append(notes, r.Notes...)
	}
	notes = append(notes, res.Notes...)
	for _, n := range notes {
		line := oneLine(n.Text)
		if n.Level == "warn" {
			fmt.Fprintln(w, st.yellow("Note:")+" "+line)
		} else {
			fmt.Fprintln(w, st.dim(line))
		}
	}
}
