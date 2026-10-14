package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/core"
	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// event is one line of the log.
type event struct {
	Time    time.Time `json:"time"` // used to order events
	Date    string    `json:"date"` // as shown: a date, a range, or ~date
	Agent   string    `json:"agent"`
	Event   string    `json:"event"` // granted, removed, revoked, undone
	GrantID string    `json:"grant_id,omitempty"`
	Grant   string    `json:"grant"`
	Detail  string    `json:"detail,omitempty"`
	// ExistenceOnly marks a granted event with no lower bound and no estimate: all we
	// know is that the grant existed by Time. Time is then not when it was given.
	ExistenceOnly bool `json:"existence_only,omitempty"`
}

func (a *app) cmdLog(args []string) int {
	var (
		g     globals
		agent string
		since string
		asJS  bool
		all   bool
	)
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	g.register(fs)
	fs.StringVar(&agent, "agent", "", "")
	fs.StringVar(&since, "since", "", "")
	fs.BoolVar(&asJS, "json", false, "")
	fs.BoolVar(&all, "all", false, "")
	rest, code, done := a.parse("log", usages["log"], fs, &g, args)
	if done {
		return code
	}
	if len(rest) > 0 {
		fmt.Fprintf(a.stderr, "grants log: unexpected argument %q\n", rest[0])
		return exitUsage
	}
	switch model.Agent(agent) {
	case "", model.ClaudeCode, model.Codex:
	default:
		fmt.Fprintf(a.stderr, "grants log: --agent must be claude-code or codex, not %q\n", agent)
		return exitUsage
	}
	var from time.Time
	if since != "" {
		t, err := time.ParseInLocation("2006-01-02", since, local)
		if err != nil {
			fmt.Fprintf(a.stderr, "grants log: --since needs a date like 2026-03-05, not %q\n", since)
			return exitUsage
		}
		from = t
	}
	res, code := a.collect(&g)
	if code != exitOK {
		return code
	}
	batches, err := edit.Batches(res.Env.StateDir)
	if err != nil {
		return a.fail("%v", err)
	}
	events := buildEvents(res, batches)
	events = filterEvents(events, agent, from)
	if asJS {
		if events == nil {
			events = []event{}
		}
		return a.printJSON(events)
	}
	renderLog(a.stdout, events, all, a.st, termWidth(a.stdout))
	return exitOK
}

// buildEvents lists what happened to grants, newest first.
func buildEvents(res core.Result, batches []edit.Batch) []event {
	home := res.Env.Home
	byID := map[string]model.Grant{}
	for _, g := range res.Grants {
		byID[g.ID] = g
	}
	revoked := map[string]bool{}
	var events []event

	for _, b := range batches {
		for _, f := range b.Files {
			ids := strings.Split(f.GrantID, ",")
			sums := strings.Split(f.Summary, "\n")
			for i, id := range ids {
				if id == "" {
					continue
				}
				revoked[id] = true
				e := event{Time: b.Time, Date: fmtDate(b.Time), Agent: "-", Event: "revoked", GrantID: id}
				if len(sums) == len(ids) {
					e.Detail = tildeText(risk.Redact(sums[i]), home)
				}
				if g, ok := byID[id]; ok {
					e.Agent, e.Grant = string(g.Agent), grantText(g, home)
				} else {
					e.Grant = tilde(f.File, home)
				}
				events = append(events, e)
				if b.Undone {
					u := event{Time: b.UndoneAt, Date: fmtDate(b.UndoneAt), Agent: e.Agent, Event: "undone", GrantID: id, Grant: e.Grant}
					events = append(events, u)
				}
			}
		}
	}

	for _, g := range res.Grants {
		text := grantText(g, home)
		if !g.Granted.Before.IsZero() {
			e := event{Time: g.Granted.Before, Date: fmtWindow(g.Granted), Agent: string(g.Agent), Event: "granted", GrantID: g.ID, Grant: text, Detail: g.Granted.Source,
				ExistenceOnly: g.Granted.After.IsZero() && !g.Granted.Approx}
			events = append(events, e)
		}
		if g.Status != model.StatusGone || revoked[g.ID] {
			continue
		}
		e := event{Agent: string(g.Agent), Event: "removed", GrantID: g.ID, Grant: text}
		switch {
		case !g.Removed.Before.IsZero():
			e.Time, e.Date = g.Removed.Before, fmtWindow(g.Removed)
		case !g.LastSeen.IsZero():
			e.Time, e.Date, e.Detail = g.LastSeen, fmtDate(g.LastSeen), "last seen"
		default:
			continue
		}
		events = append(events, e)
	}

	rank := map[string]int{"undone": 0, "revoked": 1, "removed": 2, "granted": 3}
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.After(b.Time)
		}
		if rank[a.Event] != rank[b.Event] {
			return rank[a.Event] < rank[b.Event]
		}
		return a.Grant < b.Grant
	})
	return events
}

func filterEvents(events []event, agent string, from time.Time) []event {
	var out []event
	for _, e := range events {
		if agent != "" && e.Agent != agent {
			continue
		}
		if !from.IsZero() && e.Time.Before(from) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// samplesPerDay is how many grants one "dates unknown" line names.
const samplesPerDay = 3

// renderLog prints the events with a date, newest first. Events that only show a grant
// existed by some day follow in their own section: one line per day, or one per grant
// with all.
func renderLog(w io.Writer, events []event, all bool, st style, termW int) {
	if len(events) == 0 {
		fmt.Fprintln(w, "Nothing to show yet.")
		return
	}
	var dated, undated []event
	for _, e := range events {
		if e.ExistenceOnly {
			undated = append(undated, e)
		} else {
			dated = append(dated, e)
		}
	}
	renderDated(w, dated, st, termW)
	if len(undated) == 0 {
		return
	}
	if len(dated) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, st.bold("Dates unknown; these existed by:"))
	if all {
		renderUndatedAll(w, undated, st, termW)
		return
	}
	renderUndatedByDay(w, undated, st, termW)
}

func renderDated(w io.Writer, events []event, st style, termW int) {
	dateW, agentW, evW, grantMax := 0, 0, 0, 0
	for _, e := range events {
		dateW = max(dateW, width(e.Date))
		agentW = max(agentW, width(e.Agent))
		evW = max(evW, width(e.Event))
		grantMax = max(grantMax, width(e.Grant))
	}
	prefix := dateW + 2 + agentW + 2 + evW + 2
	grantW := min(max(termW-prefix-30, 24), max(grantMax, 24))
	for _, e := range events {
		detail := ""
		if e.Detail != "" {
			detail = "  " + st.dim("("+truncEnd(oneLine(e.Detail), 70)+")")
		}
		name := padRight(e.Event, evW)
		switch e.Event {
		case "revoked":
			name = st.red(name)
		case "undone":
			name = st.yellow(name)
		case "removed":
			name = st.dim(name)
		}
		fmt.Fprintf(w, "%s  %s  %s  %s%s\n", padRight(e.Date, dateW), padRight(e.Agent, agentW), name, shortenValue(e.Grant, grantW), detail)
	}
}

// renderUndatedAll lists each grant of the undated section on its own line.
func renderUndatedAll(w io.Writer, events []event, st style, termW int) {
	agentW, grantMax := 0, 0
	for _, e := range events {
		agentW = max(agentW, width(e.Agent))
		grantMax = max(grantMax, width(e.Grant))
	}
	const dateW = 10
	grantW := min(max(termW-(2+dateW+2+agentW+2)-30, 24), max(grantMax, 24))
	for _, e := range events {
		detail := ""
		if e.Detail != "" {
			detail = "  " + st.dim("("+truncEnd(oneLine(e.Detail), 70)+")")
		}
		fmt.Fprintf(w, "  %s  %s  %s%s\n", fmtDate(e.Time), padRight(e.Agent, agentW), shortenValue(e.Grant, grantW), detail)
	}
}

// renderUndatedByDay prints one line per day: how many grants existed by then, and a
// few of them.
func renderUndatedByDay(w io.Writer, events []event, st style, termW int) {
	type day struct {
		date   string
		grants []string
	}
	var days []*day // events come newest first, so the days do too
	byDate := map[string]*day{}
	for _, e := range events {
		d := fmtDate(e.Time)
		if byDate[d] == nil {
			byDate[d] = &day{date: d}
			days = append(days, byDate[d])
		}
		byDate[d].grants = append(byDate[d].grants, e.Grant)
	}
	countW := 0
	for _, d := range days {
		countW = max(countW, width(plural(len(d.grants), "grant", "grants")))
	}
	hidden := false
	for _, d := range days {
		shown := d.grants
		if len(shown) > samplesPerDay {
			shown, hidden = shown[:samplesPerDay], true
		}
		prefix := 2 + 10 + 2 + countW + 2
		each := max((termW-prefix)/len(shown)-3, 12)
		names := make([]string, len(shown))
		for i, g := range shown {
			names[i] = shortenValue(g, each)
		}
		text := strings.Join(names, " · ")
		if more := len(d.grants) - len(shown); more > 0 {
			text += fmt.Sprintf(" · +%d more", more)
		}
		fmt.Fprintf(w, "  %s  %s  %s\n", d.date, padRight(plural(len(d.grants), "grant", "grants"), countW), text)
	}
	if hidden {
		fmt.Fprintf(w, "  %s\n", st.dim("grants log --all lists each one."))
	}
}
