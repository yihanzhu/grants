package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/revoke"
)

// fullPlanMax is how many grants get the long plan (file, diff, note). A bigger plan,
// such as --dead on a long list, prints one line per grant.
const fullPlanMax = 8

// unusedFlag is --unused for revoke. Alone it selects the grants flagged unused, with
// the default window. With a number (--unused=30, or --unused 30) it also sets the
// window in days, like the --unused flag of the other commands.
type unusedFlag struct {
	g        *globals
	selected bool
}

func (f *unusedFlag) IsBoolFlag() bool { return true }

func (f *unusedFlag) String() string {
	if f == nil {
		return ""
	}
	return strconv.FormatBool(f.selected)
}

func (f *unusedFlag) Set(s string) error {
	switch s {
	case "true":
		f.selected = true
	case "false":
		f.selected = false
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("--unused takes a number of days, not %q", s)
		}
		f.selected, f.g.unused = true, n
	}
	return nil
}

// joinUnusedDays turns "--unused 30" into "--unused=30". An id is never shorter than 4
// characters, so a number of 1 to 3 digits after --unused is a window, not an id.
func joinUnusedDays(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if (a == "--unused" || a == "-unused") && i+1 < len(args) && isShortNumber(args[i+1]) {
			out = append(out, "--unused="+args[i+1])
			i++
			continue
		}
		out = append(out, a)
	}
	return out
}

func isShortNumber(s string) bool {
	if len(s) < 1 || len(s) > 3 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (a *app) cmdRevoke(args []string) int {
	var (
		g                      globals
		dead, oneOff, dry, yes bool
		unusedSel              = unusedFlag{g: &g}
	)
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	g.registerBase(fs)
	fs.BoolVar(&dead, "dead", false, "")
	fs.BoolVar(&oneOff, "one-off", false, "")
	fs.Var(&unusedSel, "unused", "")
	fs.BoolVar(&dry, "dry-run", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	ids, code, done := a.parse("revoke", usages["revoke"], fs, &g, joinUnusedDays(args))
	if done {
		return code
	}
	unused := unusedSel.selected
	if len(ids) == 0 && !dead && !oneOff && !unused {
		fmt.Fprintln(a.stderr, "grants revoke: give a grant id, or use --dead, --one-off or --unused. grants list shows the ids.")
		return exitUsage
	}
	if !dry && !yes && !stdinIsTerminal(a.stdin) {
		return a.fail("grants revoke needs a terminal to ask you. Use --yes to skip the question, or --dry-run to only see the plan.")
	}
	res, code := a.collect(&g)
	if code != exitOK {
		return code
	}
	home := res.Env.Home

	var selected []model.Grant
	picked := map[string]bool{}
	explicit := map[string]bool{}
	for _, q := range ids {
		gr, err := resolve(res.Grants, q, home)
		if err != nil {
			return a.fail("%v", err)
		}
		if picked[gr.ID] {
			continue
		}
		picked[gr.ID], explicit[gr.ID] = true, true
		selected = append(selected, gr)
	}
	// The selectors add every active, revocable grant that has the flag.
	for _, gr := range res.Grants {
		if picked[gr.ID] {
			continue
		}
		if dead && isDead(gr) || oneOff && isOneOff(gr) || unused && isUnused(gr) {
			picked[gr.ID] = true
			selected = append(selected, gr)
		}
	}
	if len(selected) == 0 {
		fmt.Fprintln(a.stdout, nothingToRevoke(dead, oneOff, unused, res.Env.UnusedAfter))
		return exitOK
	}

	changes, items, skipped := revoke.PlanEach(res.Env, selected)
	for _, s := range skipped {
		if explicit[s.Grant.ID] {
			return a.fail("%v", s.Err)
		}
	}
	if len(items) == 0 {
		for _, s := range skipped {
			fmt.Fprintf(a.stderr, "grants: skipped %v\n", s.Err)
		}
		return a.fail("nothing can be revoked")
	}

	renderPlan(a.stdout, items, changes, skipped, a.st, home)
	if dry {
		fmt.Fprintln(a.stdout, "\nDry run. Nothing was changed.")
		return exitOK
	}

	n := len(items)
	if !yes {
		fmt.Fprintf(a.stdout, "\nRevoke %s? [y/N] ", plural(n, "grant", "grants"))
		line, _ := bufio.NewReader(a.stdin).ReadString('\n')
		if ans := strings.ToLower(strings.TrimSpace(line)); ans != "y" && ans != "yes" {
			fmt.Fprintln(a.stdout, "Cancelled. Nothing was changed.")
			return exitOK
		}
	}

	batch, err := edit.Apply(res.Env.StateDir, res.Env.Now, changes)
	if err != nil {
		if errors.Is(err, edit.ErrChanged) {
			return a.fail("a file changed while grants was planning, so nothing was written (%s). Run the command again.", trimSentinel(err, edit.ErrChanged))
		}
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.stdout, "\nRevoked %s. Backup: %s. Undo: grants undo\n", plural(n, "grant", "grants"), tilde(backupDir(batch), home))
	for _, note := range distinctNotes(items) {
		fmt.Fprintln(a.stdout, note)
	}
	return exitOK
}

// nothingToRevoke says why a selector found no grant.
func nothingToRevoke(dead, oneOff, unused bool, window time.Duration) string {
	switch {
	case dead && !oneOff && !unused:
		return "No grants point to deleted paths. Nothing to revoke."
	case oneOff && !dead && !unused:
		return "No one-off rules found. Nothing to revoke."
	case unused && !dead && !oneOff:
		return "No grants were unused for " + daysText(window) + ". Nothing to revoke."
	}
	return "No grants match. Nothing to revoke."
}

// renderPlan prints what a revoke will do.
func renderPlan(w io.Writer, items []revoke.Item, changes []edit.Change, skipped []revoke.Skip, st style, home string) {
	files := map[string]bool{}
	for _, c := range changes {
		files[c.File] = true
	}
	fmt.Fprintf(w, "%s %s in %s. Nothing is written until you confirm.\n\n",
		st.bold("Plan:"), "revoke "+plural(len(items), "grant", "grants"), plural(len(files), "file", "files"))

	if len(items) <= fullPlanMax {
		for _, it := range items {
			fmt.Fprintf(w, "  %s  %s\n", st.dim(it.Grant.ID), tildeText(it.Summary, home))
			pad := strings.Repeat(" ", 2+width(it.Grant.ID)+2)
			fmt.Fprintf(w, "%s%s\n", pad, st.dim(tilde(it.File, home)))
			for _, d := range it.Diff {
				fmt.Fprintf(w, "%s%s\n", pad, colorDiff(clean(d), st))
			}
			if it.Note != "" {
				fmt.Fprintf(w, "%s%s\n", pad, clean(it.Note))
			}
		}
	} else {
		for _, it := range items {
			fmt.Fprintf(w, "  %s  %s\n", st.dim(it.Grant.ID), truncEnd(tildeText(it.Summary, home), 110))
		}
		fmt.Fprintln(w, "\nFiles that change:")
		for _, c := range changes {
			fmt.Fprintf(w, "  %s\n", tilde(c.File, home))
		}
		fmt.Fprintln(w, st.dim("\nTo see the exact change for one grant: grants revoke <id> --dry-run"))
		for _, note := range distinctNotes(items) {
			fmt.Fprintln(w, note)
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "\n%s %s left out:\n", st.yellow("Note:"), plural(len(skipped), "grant was", "grants were"))
		for _, s := range skipped {
			fmt.Fprintf(w, "  %s\n", truncEnd(oneLine(s.Err.Error()), 140))
		}
	}
}

func colorDiff(line string, st style) string {
	switch {
	case strings.HasPrefix(line, "- "):
		return st.red(line)
	case strings.HasPrefix(line, "+ "):
		return st.green(line)
	}
	return line
}

// distinctNotes returns each revoke note once, in order.
func distinctNotes(items []revoke.Item) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if it.Note != "" && !seen[it.Note] {
			seen[it.Note] = true
			out = append(out, clean(it.Note))
		}
	}
	return out
}

func backupDir(b edit.Batch) string {
	if len(b.Files) == 0 {
		return ""
	}
	return filepath.Dir(b.Files[0].Backup)
}

// trimSentinel removes the fixed prefix of a wrapped sentinel error from its message.
func trimSentinel(err, sentinel error) string {
	return strings.TrimPrefix(err.Error(), sentinel.Error()+": ")
}
