package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/revoke"
)

// fullPlanMax is how many grants get the long plan (file, diff, note). A bigger plan,
// such as --dead on a long list, prints one line per grant.
const fullPlanMax = 8

func (a *app) cmdRevoke(args []string) int {
	var (
		g              globals
		dead, dry, yes bool
	)
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	g.register(fs)
	fs.BoolVar(&dead, "dead", false, "")
	fs.BoolVar(&dry, "dry-run", false, "")
	fs.BoolVar(&yes, "yes", false, "")
	ids, code, done := a.parse("revoke", usages["revoke"], fs, &g, args)
	if done {
		return code
	}
	if len(ids) == 0 && !dead {
		fmt.Fprintln(a.stderr, "grants revoke: give a grant id, or use --dead. grants list shows the ids.")
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
	if dead {
		for _, gr := range res.Grants {
			if isDead(gr) && !picked[gr.ID] {
				picked[gr.ID] = true
				selected = append(selected, gr)
			}
		}
	}
	if len(selected) == 0 {
		fmt.Fprintln(a.stdout, "No grants point to deleted paths. Nothing to revoke.")
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
				fmt.Fprintf(w, "%s%s\n", pad, colorDiff(d, st))
			}
			if it.Note != "" {
				fmt.Fprintf(w, "%s%s\n", pad, it.Note)
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
			out = append(out, it.Note)
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
