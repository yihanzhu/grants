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
}

func (a *app) cmdLog(args []string) int {
	var (
		g     globals
		agent string
		since string
		asJS  bool
	)
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	g.register(fs)
	fs.StringVar(&agent, "agent", "", "")
	fs.StringVar(&since, "since", "", "")
	fs.BoolVar(&asJS, "json", false, "")
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
	renderLog(a.stdout, events, a.st, termWidth(a.stdout))
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
			e := event{Time: g.Granted.Before, Date: fmtWindow(g.Granted), Agent: string(g.Agent), Event: "granted", GrantID: g.ID, Grant: text, Detail: g.Granted.Source}
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

func renderLog(w io.Writer, events []event, st style, termW int) {
	if len(events) == 0 {
		fmt.Fprintln(w, "Nothing to show yet.")
		return
	}
	dateW, agentW, evW := 0, 0, 0
	for _, e := range events {
		dateW = max(dateW, width(e.Date))
		agentW = max(agentW, width(e.Agent))
		evW = max(evW, width(e.Event))
	}
	prefix := dateW + 2 + agentW + 2 + evW + 2
	grantW := min(max(termW-prefix-30, 24), 60)
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
		fmt.Fprintf(w, "%s  %s  %s  %s%s\n", padRight(e.Date, dateW), padRight(e.Agent, agentW), name, truncMiddle(e.Grant, grantW), detail)
	}
}
