// Package revoke plans the file edits that remove grants. It writes nothing; the
// caller shows the plan, asks the user, and applies it with edit.Apply.
package revoke

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/yihanzhu/grants/internal/claude"
	"github.com/yihanzhu/grants/internal/codex"
	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// Item is what revoking one grant does.
type Item struct {
	Grant   model.Grant
	File    string
	Summary string
	Diff    []string // "- " and "+ " lines, redacted and clipped
	Note    string   // what the user must do afterwards, e.g. restart Codex
}

// Skip is a grant that could not be planned, and why.
type Skip struct {
	Grant model.Grant
	Err   error
}

// maxDiffLines is how many diff lines an Item keeps.
const maxDiffLines = 6

// Plan turns grants into one edit.Change per file. Several grants in one file are
// applied to the same document in order. It fails on the first grant it cannot plan, so
// nothing is half done.
func Plan(env model.Env, grants []model.Grant) ([]edit.Change, []Item, error) {
	changes, items, skipped := plan(env, grants, true)
	if len(skipped) > 0 {
		return nil, nil, skipped[0].Err
	}
	return changes, items, nil
}

// PlanEach is like Plan but leaves out a grant it cannot plan and reports it in the
// skipped list. The rest of the plan stays valid.
func PlanEach(env model.Env, grants []model.Grant) ([]edit.Change, []Item, []Skip) {
	return plan(env, grants, false)
}

type fileJob struct {
	path   string
	before []byte
	doc    []byte // content after the grants applied so far
	ids    []string
	sums   []string
}

func plan(env model.Env, grants []model.Grant, strict bool) ([]edit.Change, []Item, []Skip) {
	var (
		jobs    []*fileJob
		byFile  = map[string]*fileJob{}
		items   []Item
		skipped []Skip
	)
	for _, g := range grants {
		fail := func(err error) {
			skipped = append(skipped, Skip{Grant: g, Err: err})
		}
		if err := check(g); err != nil {
			fail(err)
			if strict {
				return nil, nil, skipped
			}
			continue
		}
		path := fileOf(env, g)
		if path == "" {
			fail(fmt.Errorf("%s: the grant has no file", describe(g)))
			if strict {
				return nil, nil, skipped
			}
			continue
		}
		key := fileKey(path)
		job := byFile[key]
		if job == nil {
			doc, err := os.ReadFile(path)
			if err != nil {
				fail(fmt.Errorf("%s: cannot read %s: %w", describe(g), path, unwrapPath(err)))
				if strict {
					return nil, nil, skipped
				}
				continue
			}
			job = &fileJob{path: path, before: doc, doc: doc}
			byFile[key] = job
			jobs = append(jobs, job)
		}
		after, summary, err := revokeDoc(env, g, job.doc)
		if err != nil {
			fail(fmt.Errorf("%s: %w", describe(g), err))
			if strict {
				return nil, nil, skipped
			}
			continue
		}
		items = append(items, Item{
			Grant: g, File: path, Summary: summary, Diff: diff(job.doc, after), Note: g.RevokeNote,
		})
		job.doc = after
		job.ids = append(job.ids, g.ID)
		job.sums = append(job.sums, strings.ReplaceAll(summary, "\n", " "))
	}

	var changes []edit.Change
	for _, j := range jobs {
		if len(j.ids) == 0 {
			continue // every grant of this file was skipped
		}
		changes = append(changes, edit.Change{
			File: j.path, Before: j.before, After: j.doc,
			GrantID: strings.Join(j.ids, ","), Summary: strings.Join(j.sums, "\n"),
		})
	}
	return changes, items, skipped
}

// check refuses grants that cannot be revoked, with a message for the user.
func check(g model.Grant) error {
	switch {
	case g.Status == model.StatusGone:
		return fmt.Errorf("%s is already removed", describe(g))
	case g.Status != model.StatusActive:
		return fmt.Errorf("%s cannot be revoked now: grants cannot read the file that holds it", describe(g))
	case g.Scope == model.ScopeManaged:
		return fmt.Errorf("%s is set by your organization, and grants never edits managed settings", describe(g))
	case !g.Revocable:
		note := g.RevokeNote
		if note == "" {
			note = "grants cannot revoke it"
		}
		return fmt.Errorf("%s cannot be revoked: %s", describe(g), note)
	}
	return nil
}

func describe(g model.Grant) string {
	return fmt.Sprintf("grant %s (%s)", g.ID, clip(risk.Redact(g.Value), 60))
}

func revokeDoc(env model.Env, g model.Grant, doc []byte) ([]byte, string, error) {
	switch g.Agent {
	case model.ClaudeCode:
		return claude.RevokeDoc(env, g, doc)
	case model.Codex:
		return codex.RevokeDoc(env, g, doc)
	}
	return nil, "", fmt.Errorf("unknown agent %q", g.Agent)
}

// fileOf is the file that holds g.
func fileOf(env model.Env, g model.Grant) string {
	if g.Location.File != "" {
		return g.Location.File
	}
	if g.Kind != model.KindTrust {
		return ""
	}
	if g.Agent == model.ClaudeCode {
		return env.ClaudeJSON
	}
	return filepath.Join(env.CodexHome, "config.toml")
}

// fileKey makes two spellings of one file equal, so one change covers both.
func fileKey(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// diff lists the lines that differ between before and after as "- " and "+ " lines.
// Lines are trimmed, redacted, and clipped; at most maxDiffLines are kept.
func diff(before, after []byte) []string {
	a := strings.Split(string(before), "\n")
	b := strings.Split(string(after), "\n")
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	rem, add := a[pre:len(a)-suf], b[pre:len(b)-suf]
	// A file kept on one line has the whole file in a single changed line. Show only
	// the span that differs.
	if len(rem) == 1 && len(add) == 1 && (len(rem[0]) > 120 || len(add[0]) > 120) {
		rem[0], add[0] = span(rem[0], add[0])
	}
	var out []string
	for _, l := range rem {
		out = append(out, "- "+tidy(l))
	}
	for _, l := range add {
		out = append(out, "+ "+tidy(l))
	}
	if len(out) > maxDiffLines {
		more := len(out) - (maxDiffLines - 1)
		out = append(out[:maxDiffLines-1], fmt.Sprintf("  ... %d more changed lines", more))
	}
	return out
}

// span cuts the text both lines share at the start and at the end, and keeps a little
// of it as context.
func span(x, y string) (string, string) {
	const context = 24
	p := 0
	for p < len(x) && p < len(y) && x[p] == y[p] {
		p++
	}
	for p > 0 && (!utf8.RuneStart(x[min(p, len(x)-1)]) || !utf8.RuneStart(y[min(p, len(y)-1)])) {
		p--
	}
	s := 0
	for s < len(x)-p && s < len(y)-p && x[len(x)-1-s] == y[len(y)-1-s] {
		s++
	}
	for s > 0 && (!utf8.RuneStart(x[len(x)-s]) || !utf8.RuneStart(y[len(y)-s])) {
		s--
	}
	cut := func(t string) string {
		start, end := max(p-context, 0), min(len(t)-s+context, len(t))
		for start > 0 && !utf8.RuneStart(t[start]) {
			start--
		}
		for end < len(t) && !utf8.RuneStart(t[end]) {
			end--
		}
		out := t[start:end]
		if start > 0 {
			out = "..." + out
		}
		if end < len(t) {
			out += "..."
		}
		return out
	}
	return cut(x), cut(y)
}

// tidy trims a diff line, hides secrets, and keeps it short.
func tidy(l string) string {
	l = strings.TrimRight(strings.TrimSpace(l), "\r")
	return clip(risk.Redact(l), 140)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
