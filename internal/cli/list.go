package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/model"
)

type listOpts struct {
	agent string
	kind  string
	all   bool
	risk  string
	flag  string
}

func (a *app) cmdList(args []string) int {
	var (
		g    globals
		o    listOpts
		asJS bool
	)
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	g.register(fs)
	fs.StringVar(&o.agent, "agent", "", "")
	fs.StringVar(&o.kind, "kind", "", "")
	fs.BoolVar(&o.all, "all", false, "")
	fs.StringVar(&o.risk, "risk", "", "")
	fs.StringVar(&o.flag, "flag", "", "")
	fs.BoolVar(&asJS, "json", false, "")
	rest, code, done := a.parse("list", usages["list"], fs, &g, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		fmt.Fprintf(a.stderr, "grants list: unexpected argument %q\n", rest[0])
		return exitUsage
	}
	if err := o.validate(); err != nil {
		fmt.Fprintf(a.stderr, "grants list: %v\n", err)
		return exitUsage
	}
	res, code := a.collect(&g)
	if code != exitOK {
		return code
	}
	shown := filterGrants(res.Grants, o)
	if asJS {
		return a.printJSON(redactAll(shown))
	}
	renderList(a.stdout, shown, res, o, a.st, termWidth(a.stdout))
	return exitOK
}

func (o listOpts) validate() error {
	switch model.Agent(o.agent) {
	case "", model.ClaudeCode, model.Codex:
	default:
		return fmt.Errorf("--agent must be claude-code or codex, not %q", o.agent)
	}
	switch model.Kind(o.kind) {
	case "", model.KindRule, model.KindTrust:
	default:
		return fmt.Errorf("--kind must be rule or trust, not %q", o.kind)
	}
	switch model.Level(o.risk) {
	case "", model.RiskHigh, model.RiskMedium, model.RiskLow:
	default:
		return fmt.Errorf("--risk must be high, medium or low, not %q", o.risk)
	}
	switch model.Flag(o.flag) {
	case "", model.FlagDeadPath, model.FlagUnused, model.FlagOneOff, model.FlagSecret, model.FlagCommitted:
	default:
		return fmt.Errorf("--flag must be dead-path, unused, one-off, secret or committed, not %q", o.flag)
	}
	return nil
}

// filterGrants keeps the grants that match the flags. Gone and unknown grants stay out
// unless all is set.
func filterGrants(grants []model.Grant, o listOpts) []model.Grant {
	var out []model.Grant
	for _, g := range grants {
		switch {
		case !o.all && g.Status != model.StatusActive:
		case o.agent != "" && string(g.Agent) != o.agent:
		case o.kind != "" && string(g.Kind) != o.kind:
		case o.risk != "" && g.Risk.Level.Rank() < model.Level(o.risk).Rank():
		case o.flag != "" && !g.HasFlag(model.Flag(o.flag)):
		default:
			out = append(out, g)
		}
	}
	return out
}

func redactAll(grants []model.Grant) []model.Grant {
	out := make([]model.Grant, len(grants))
	for i, g := range grants {
		out[i] = redactGrant(g)
	}
	return out
}

func (a *app) printJSON(v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return a.fail("encode JSON: %v", err)
	}
	fmt.Fprintf(a.stdout, "%s\n", b)
	return exitOK
}

// renderList prints the grant table. The GRANT column takes the width that is left.
func renderList(w io.Writer, shown []model.Grant, res core.Result, o listOpts, st style, termW int) {
	home := res.Env.Home
	if len(shown) == 0 {
		fmt.Fprintln(w, "No grants match.")
		if !o.all {
			fmt.Fprintln(w, st.dim("Gone and unreadable grants are hidden. --all shows them."))
		}
		return
	}
	head := []string{"ID", "AGENT", "KIND", "GRANT", "SCOPE", "GRANTED", "LAST USED", "RISK", "FLAGS"}
	const (
		grantCol = 3
		scopeCol = 4
		riskCol  = 7
	)
	rows := make([][]string, 0, len(shown))
	short := make([]string, 0, len(shown)) // the short scope of each row
	for _, g := range shown {
		rows = append(rows, []string{
			g.ID, string(g.Agent), string(g.Kind), grantText(g, home),
			scopeText(g, home), fmtWindow(g.Granted), lastUsed(g), string(g.Risk.Level), flagsText(g),
		})
		short = append(short, scopeShort(g))
	}
	widths := make([]int, len(head))
	for i, h := range head {
		widths[i] = width(h)
	}
	fixed, longest, scopeFull, scopeCut := 0, 0, width(head[scopeCol]), width(head[scopeCol])
	for i, r := range rows {
		for c, cell := range r {
			if c != grantCol && c != scopeCol {
				widths[c] = max(widths[c], width(cell))
			}
		}
		longest = max(longest, width(r[grantCol]))
		scopeFull = max(scopeFull, width(r[scopeCol]))
		scopeCut = max(scopeCut, width(short[i]))
	}
	for c, wd := range widths {
		if c != grantCol && c != scopeCol {
			fixed += wd + 2
		}
	}
	// The GRANT column is what people read, so it gets the width first. The scope column
	// gives way in steps: project paths shrink to their last segment, and when the grant
	// would still be cut below 30 characters, the column goes.
	skip := map[int]bool{}
	grantW := longest
	switch {
	case fixed+scopeFull+2+longest <= termW:
		widths[scopeCol] = scopeFull
	case fixed+scopeCut+2+longest <= termW:
		widths[scopeCol] = scopeCut
		for i := range rows {
			rows[i][scopeCol] = short[i]
		}
	default:
		widths[scopeCol] = scopeCut
		for i := range rows {
			rows[i][scopeCol] = short[i]
		}
		grantW = termW - fixed - scopeCut - 2
		if grantW < 30 {
			skip[scopeCol] = true
			grantW = termW - fixed
		}
		grantW = max(grantW, 16)
	}
	widths[grantCol] = max(min(longest, grantW), width(head[grantCol]))

	var cols []int
	for i := range head {
		if !skip[i] {
			cols = append(cols, i)
		}
	}
	line := func(cells []string, header bool) string {
		var sb strings.Builder
		for n, i := range cols {
			text := cells[i]
			if i == grantCol {
				text = shortenValue(text, widths[i])
			}
			last := n == len(cols)-1
			if !last {
				text = padRight(text, widths[i])
			}
			switch {
			case header:
				text = st.dim(text)
			case i == riskCol:
				text = st.level(model.Level(strings.TrimSpace(cells[i])), text)
			}
			sb.WriteString(text)
			if !last {
				sb.WriteString("  ")
			}
		}
		return strings.TrimRight(sb.String(), " ")
	}
	fmt.Fprintln(w, line(head, true))
	for _, r := range rows {
		fmt.Fprintln(w, line(r, false))
	}
	fmt.Fprintln(w)
	total := len(shown)
	fmt.Fprintf(w, "%s.", plural(total, "grant", "grants"))
	if skip[scopeCol] {
		fmt.Fprint(w, " The scope column needs a wider terminal; grants show has it.")
	}
	if !o.all {
		hidden := 0
		for _, g := range res.Grants {
			if g.Status != model.StatusActive {
				hidden++
			}
		}
		if hidden > 0 {
			fmt.Fprintf(w, " %s hidden (gone or not readable): --all shows them.", commas(hidden))
		}
	}
	fmt.Fprintln(w)
}
