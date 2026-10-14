package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/model"
)

func (a *app) cmdScan(args []string) int {
	var g globals
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	g.register(fs)
	rest, code, done := a.parse("scan", usages["scan"], fs, &g, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		fmt.Fprintf(a.stderr, "grants scan: unexpected argument %q\n", rest[0])
		return exitUsage
	}
	res, code := a.collect(&g)
	if code != exitOK {
		return code
	}
	renderScan(a.stdout, res, g.noCache, a.st)
	return exitOK
}

// renderScan prints what each agent's read covered and how long the run took.
func renderScan(w io.Writer, res core.Result, noCache bool, st style) {
	cache := "saved results used for files that did not change"
	if noCache {
		cache = "saved results ignored"
	}
	fmt.Fprintf(w, "%s %s (%s)\n", st.bold("Scanned in"), fmtDuration(res.Took), cache)

	counts := map[model.Agent]int{}
	for _, g := range res.Grants {
		if g.Status == model.StatusActive {
			counts[g.Agent]++
		}
	}
	for _, r := range res.Reports {
		fmt.Fprintln(w)
		if !r.Found {
			fmt.Fprintf(w, "%s  %s\n", st.bold(agentName(r.Agent)), st.dim("not found on this machine"))
			continue
		}
		fmt.Fprintf(w, "%s  %s\n", st.bold(agentName(r.Agent)), plural(counts[r.Agent], "active grant", "active grants"))
		srcW := 0
		filesW := 0
		for _, c := range r.Coverage {
			srcW = max(srcW, width(c.Source))
			filesW = max(filesW, width(plural(c.Files, "file", "files")))
		}
		for _, c := range r.Coverage {
			span := ""
			if !c.From.IsZero() && !c.To.IsZero() {
				span = "  " + fmtDate(c.From) + " to " + fmtDate(c.To)
			}
			fmt.Fprintf(w, "  %s  %s%s\n", padRight(c.Source, srcW), padLeft(plural(c.Files, "file", "files"), filesW), span)
		}
		for _, n := range r.Notes {
			prefix := ""
			if n.Level == "warn" {
				prefix = st.yellow("Note:") + " "
			}
			fmt.Fprintf(w, "  %s%s\n", prefix, oneLine(n.Text))
		}
	}
	if len(res.Notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range res.Notes {
			fmt.Fprintf(w, "%s %s\n", st.yellow("Note:"), oneLine(n.Text))
		}
	}
}

// fmtDuration writes a run time as 240ms or 6.9s.
func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
