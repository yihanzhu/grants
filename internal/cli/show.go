package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

func (a *app) cmdShow(args []string) int {
	var (
		g    globals
		asJS bool
	)
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	g.register(fs)
	fs.BoolVar(&asJS, "json", false, "")
	rest, code, done := a.parse("show", usages["show"], fs, &g, args)
	if done {
		return code
	}
	if len(rest) != 1 {
		fmt.Fprintln(a.stderr, "grants show: give one grant id (grants list shows them)")
		return exitUsage
	}
	res, code := a.collect(&g)
	if code != exitOK {
		return code
	}
	gr, err := resolve(res.Grants, rest[0], res.Env.Home)
	if err != nil {
		return a.fail("%v", err)
	}
	if asJS {
		return a.printJSON(redactGrant(gr))
	}
	renderShow(a.stdout, gr, res, a.st, termWidth(a.stdout))
	return exitOK
}

// renderShow prints one grant in detail.
func renderShow(w io.Writer, g model.Grant, res core.Result, st style, termW int) {
	home := res.Env.Home
	// A long row wraps under its text. A row with color codes is left alone, since the
	// codes would count as width.
	row := func(label, text string) {
		lines := []string{text}
		if !strings.Contains(text, "\x1b") {
			if wrapped := wrapText(text, max(termW-10, 30)); len(wrapped) > 1 {
				lines = wrapped
			}
		}
		for i, l := range lines {
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(w, "%s %s\n", st.dim(padRight(label, 9)), l)
		}
	}

	title := grantText(g, home)
	tag := fmt.Sprintf("%s %s · %s", g.Agent, g.Kind, g.ID)
	if width(title)+2+width(tag) <= termW {
		fmt.Fprintf(w, "%s  %s\n", st.bold(padRight(title, termW-width(tag)-2)), st.dim(tag))
	} else {
		fmt.Fprintf(w, "%s\n%s\n", st.bold(title), st.dim(tag))
	}

	row("Status", statusText(g))
	switch {
	case g.Location.File != "":
		where := tilde(g.Location.File, home)
		if g.Location.Line > 0 {
			where += fmt.Sprintf(":%d", g.Location.Line)
		}
		row("Where", where)
	case g.Status != model.StatusActive:
		row("Where", "not in any config file now")
	}
	row("Applies", appliesText(g, home))
	granted := fmtWindow(g.Granted)
	if g.Granted.Source != "" && granted != "unknown" {
		granted += " (" + g.Granted.Source + ")"
	}
	row("Granted", granted)
	if g.Status == model.StatusGone && (!g.Removed.Before.IsZero() || !g.Removed.After.IsZero()) {
		row("Removed", fmtWindow(g.Removed))
	}
	if g.Status != model.StatusActive || g.Usage.Known {
		row("Used", usedText(g))
	} else {
		row("Used", "cannot be measured for this "+kindName(g.Kind))
	}
	row("Risk", riskText(g, st))
	if len(g.Flags) > 0 {
		for i, f := range g.Flags {
			label := ""
			if i == 0 {
				label = "Flags"
			}
			row(label, string(f)+": "+flagMeaning(f))
		}
	}
	row("Revoke", revokeText(g))

	if len(g.Evidence) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.bold("Evidence"))
		whatW := 0
		for _, e := range g.Evidence {
			whatW = max(whatW, width(e.What))
		}
		// Each line starts with the time and the kind. The detail wraps in the width that
		// is left, and the source follows it, on its own line when it does not fit. On a
		// narrow terminal the detail goes below the time instead.
		prefixW := 2 + 16 + 2 + whatW + 2
		textW := termW - prefixW
		stacked := textW < 30
		pad := strings.Repeat(" ", prefixW)
		if stacked {
			pad = "    "
			textW = max(termW-width(pad), 12)
		}
		for _, e := range g.Evidence {
			type line struct{ text, src string } // src is the dim "(source)" tail
			var lines []line
			for _, t := range wrapText(oneLine(risk.Redact(e.Detail)), textW) {
				lines = append(lines, line{text: t})
			}
			if e.Source != "" {
				src := "(" + evidenceSource(e.Source, res.Env) + ")"
				if n := len(lines); n > 0 && width(lines[n-1].text)+2+width(src) <= textW {
					lines[n-1].src = "  " + src
				} else {
					lines = append(lines, line{src: truncMiddle(src, textW)})
				}
			}
			if len(lines) == 0 {
				lines = []line{{}}
			}
			head := fmt.Sprintf("  %s  %s  ", fmtDateTime(e.Time), padRight(e.What, whatW))
			if stacked {
				fmt.Fprintln(w, strings.TrimRight(head, " "))
				head = pad
			}
			for i, l := range lines {
				lead := pad
				if i == 0 {
					lead = head
				}
				fmt.Fprintf(w, "%s%s%s\n", lead, l.text, st.dim(l.src))
			}
		}
	}
}

// evidenceSource shortens an evidence file to a path inside the agent's home folder
// (sessions/2026/...), or to ~/... for files elsewhere.
func evidenceSource(src string, env model.Env) string {
	for _, root := range []string{env.CodexHome, env.ClaudeDir} {
		if root != "" && strings.HasPrefix(src, root+"/") {
			return src[len(root)+1:]
		}
	}
	return tilde(src, env.Home)
}

// wrapText breaks s into lines of at most n characters at spaces. A word longer than
// a line is cut.
func wrapText(s string, n int) []string {
	var lines []string
	cur := ""
	flush := func() {
		if cur != "" {
			lines = append(lines, cur)
			cur = ""
		}
	}
	for _, word := range strings.Fields(s) {
		for width(word) > n {
			flush()
			r := []rune(word)
			lines = append(lines, string(r[:n]))
			word = string(r[n:])
		}
		switch {
		case cur == "":
			cur = word
		case width(cur)+1+width(word) <= n:
			cur += " " + word
		default:
			flush()
			cur = word
		}
	}
	flush()
	return lines
}

func statusText(g model.Grant) string {
	switch g.Status {
	case model.StatusGone:
		if !g.LastSeen.IsZero() {
			return "gone (last seen " + fmtDate(g.LastSeen) + ")"
		}
		return "gone"
	case model.StatusUnknown:
		return "unknown (the file that may hold it cannot be read)"
	}
	return "active"
}

func appliesText(g model.Grant, home string) string {
	var base string
	switch {
	case g.Kind == model.KindTrust:
		base = tilde(g.Value, home) + " and everything inside it"
	case g.Project != "":
		base = "only in " + tilde(g.Project, home)
	default:
		base = "everywhere"
	}
	switch g.Scope {
	case model.ScopeManaged:
		base += " (set by your organization)"
	case model.ScopeProject:
		base += " (shared project settings)"
	case model.ScopeLocal:
		base += " (local project settings)"
	case model.ScopeLegacy:
		base += " (old settings location)"
	}
	return base
}

func usedText(g model.Grant) string {
	if !g.Usage.Known {
		return "not known"
	}
	unit := "times"
	one := "1 time"
	if g.Kind == model.KindTrust {
		unit, one = "sessions", "1 session"
	}
	n := fmt.Sprintf("%s %s", commas(g.Usage.Count), unit)
	if g.Usage.Count == 1 {
		n = one
	}
	text := "never"
	if g.Usage.Count > 0 {
		text = n
		if !g.Usage.Last.IsZero() {
			text += ", last " + fmtDate(g.Usage.Last)
		}
	}
	if !g.Usage.Since.IsZero() {
		text += " (history from " + fmtDate(g.Usage.Since) + ")"
	}
	return text
}

func riskText(g model.Grant, st style) string {
	lvl := st.level(g.Risk.Level, string(g.Risk.Level))
	if len(g.Risk.Reasons) == 0 {
		return lvl
	}
	return lvl + ": " + strings.Join(g.Risk.Reasons, "; ")
}

func revokeText(g model.Grant) string {
	switch {
	case g.Status == model.StatusGone:
		return "already removed"
	case g.Status == model.StatusUnknown:
		return "cannot revoke now: " + firstNonEmpty(g.RevokeNote, "the file cannot be read")
	case !g.Revocable:
		return "cannot revoke: " + firstNonEmpty(g.RevokeNote, "grants cannot edit it")
	}
	text := "grants revoke " + g.ID
	if g.RevokeNote != "" {
		text += " (" + g.RevokeNote + ")"
	}
	return text
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
