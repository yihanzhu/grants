package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// local is the time zone for dates. Tests replace it.
var local = time.Local

func fmtDate(t time.Time) string     { return t.In(local).Format("2006-01-02") }
func fmtDateTime(t time.Time) string { return t.In(local).Format("2006-01-02 15:04") }

// fmtWindow renders when a grant was created: one date when it is exact or the range
// fits in one day, a range when it is wider, "before <date>" when only the latest
// bound is known, "~<date>" for an estimate, and "unknown" otherwise.
func fmtWindow(w model.Window) string {
	switch {
	case w.Before.IsZero() && w.After.IsZero():
		return "unknown"
	case w.Before.IsZero():
		return "after " + fmtDate(w.After)
	case w.Approx:
		return "~" + fmtDate(w.Before)
	case w.After.IsZero():
		return "before " + fmtDate(w.Before)
	case w.Exact() || fmtDate(w.After) == fmtDate(w.Before):
		return fmtDate(w.Before)
	}
	return fmtDate(w.After) + ".." + fmtDate(w.Before)
}

// windowTime is the moment used to order a window: its latest bound.
func windowTime(w model.Window) time.Time {
	if !w.Before.IsZero() {
		return w.Before
	}
	return w.After
}

// tilde shows the home folder as ~.
func tilde(path, home string) string {
	if home == "" || home == "/" {
		return path
	}
	switch {
	case path == home:
		return "~"
	case strings.HasPrefix(path, home+"/"):
		return "~" + path[len(home):]
	}
	return path
}

// tildeText shows the home folder as ~ wherever a message names it.
func tildeText(s, home string) string {
	if home == "" || home == "/" {
		return s
	}
	return strings.ReplaceAll(s, home+"/", "~/")
}

// grantText is what a grant is, as one line of text: the rule, or the trusted folder.
// Secrets are hidden.
func grantText(g model.Grant, home string) string {
	if g.Kind == model.KindTrust {
		return tilde(g.Value, home)
	}
	return oneLine(risk.Redact(g.Value))
}

func oneLine(s string) string {
	if !strings.ContainsAny(s, "\r\n\t") {
		return s
	}
	return strings.Join(strings.Fields(s), " ")
}

// truncMiddle shortens s to n characters by cutting out its middle.
func truncMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	head := n / 2
	tail := n - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}

// urlRe finds URLs in a rule: a scheme, then everything up to a space, quote or closer.
var urlRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"` + "`" + `)\]>]+`)

// shortenURL cuts a URL to scheme://host/…/last-segment and drops the query and the
// fragment. A URL with no path or one path segment keeps all of it.
func shortenURL(u string) string {
	tail := ""
	for strings.HasSuffix(u, ".") || strings.HasSuffix(u, ",") || strings.HasSuffix(u, ";") || strings.HasSuffix(u, ":") {
		tail = u[len(u)-1:] + tail
		u = u[:len(u)-1]
	}
	scheme, rest, ok := strings.Cut(u, "://")
	if !ok {
		return u + tail
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	host, path, _ := strings.Cut(rest, "/")
	var segs []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			segs = append(segs, p)
		}
	}
	out := scheme + "://" + host
	switch len(segs) {
	case 0:
	case 1:
		out += "/" + segs[0]
	default:
		out += "/…/" + segs[len(segs)-1]
	}
	return out + tail
}

// shortenURLs shortens every URL inside s.
func shortenURLs(s string) string {
	return urlRe.ReplaceAllStringFunc(s, shortenURL)
}

// shortenValue fits a grant value into n characters. It shortens each URL in it first,
// since the middle of a URL says little, and cuts the middle of the whole text only if
// that is not enough.
func shortenValue(s string, n int) string {
	if width(s) <= n {
		return s
	}
	return truncMiddle(shortenURLs(s), n)
}

// truncEnd shortens s to n characters by cutting its end.
func truncEnd(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func width(s string) int { return len([]rune(s)) }

func padRight(s string, n int) string {
	if d := n - width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func padLeft(s string, n int) string {
	if d := n - width(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

// commas writes 1234 as 1,234.
func commas(n int) string { return model.Commas(n) }

func plural(n int, one, many string) string { return model.Plural(n, one, many) }

// agentName is the name people use for an agent.
func agentName(a model.Agent) string {
	switch a {
	case model.ClaudeCode:
		return "Claude Code"
	case model.Codex:
		return "Codex"
	}
	return string(a)
}

// kindName is the word for a grant kind in prose.
func kindName(k model.Kind) string {
	if k == model.KindTrust {
		return "trusted folder"
	}
	return "rule"
}

// scopeText shows where a grant applies, such as "project ~/x".
func scopeText(g model.Grant, home string) string {
	switch g.Scope {
	case model.ScopeProject, model.ScopeLocal, model.ScopeLegacy:
		if g.Project != "" {
			return string(g.Scope) + " " + tilde(g.Project, home)
		}
	}
	return string(g.Scope)
}

// scopeShort is scopeText with the project folder cut to its last segment, such as
// "project …/app".
func scopeShort(g model.Grant) string {
	switch g.Scope {
	case model.ScopeProject, model.ScopeLocal, model.ScopeLegacy:
		if g.Project != "" {
			return string(g.Scope) + " …/" + filepath.Base(g.Project)
		}
	}
	return string(g.Scope)
}

// lastUsed is a date, "never", or "?" when use cannot be measured.
func lastUsed(g model.Grant) string {
	switch {
	case !g.Usage.Known:
		return "?"
	case g.Usage.Count == 0:
		return "never"
	case g.Usage.Last.IsZero():
		return "?"
	}
	return fmtDate(g.Usage.Last)
}

// flagsText lists flags, and the status of grants that are not active.
func flagsText(g model.Grant) string {
	var parts []string
	if g.Status != model.StatusActive {
		parts = append(parts, string(g.Status))
	}
	for _, f := range g.Flags {
		parts = append(parts, string(f))
	}
	return strings.Join(parts, ",")
}

// redactGrant returns a copy of g that is safe to print: secrets are hidden in the
// rule, the pattern and the evidence.
func redactGrant(g model.Grant) model.Grant {
	g.Key = risk.Redact(g.Key)
	g.Value = risk.Redact(g.Value)
	if g.Pattern != nil {
		p := make([][]string, len(g.Pattern))
		for i, alts := range g.Pattern {
			p[i] = make([]string, len(alts))
			for j, t := range alts {
				p[i][j] = risk.Redact(t)
			}
		}
		g.Pattern = p
	}
	if g.Evidence != nil {
		ev := make([]model.Evidence, len(g.Evidence))
		for i, e := range g.Evidence {
			e.Detail = risk.Redact(e.Detail)
			ev[i] = e
		}
		g.Evidence = ev
	}
	return g
}

// flagMeaning explains a flag in plain words.
func flagMeaning(f model.Flag) string {
	switch f {
	case model.FlagDeadPath:
		return "points to a path that no longer exists"
	case model.FlagOneOff:
		return "names one specific URL, script or long command; looks like a single approval kept for good"
	case model.FlagUnused:
		return "not used in the unused window"
	case model.FlagSecret:
		return "the rule text holds something that looks like a credential"
	case model.FlagCommitted:
		return "lives in a file that git tracks, so revoking it changes the repository"
	}
	return ""
}

func daysText(d time.Duration) string {
	return plural(int(d.Hours()/24), "day", "days")
}
