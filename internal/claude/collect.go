// Package claude finds the grants Claude Code holds: allow rules in its settings files
// and the folders it trusts. It dates each grant from the agent's own history, counts
// how often it was used, and plans the file edits that revoke it.
package claude

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

// transcriptsOutlived is how much newer the oldest transcript must be than the first
// start of Claude Code before grants says history is missing.
const transcriptsOutlived = 14 * 24 * time.Hour

type collector struct {
	env model.Env
	opt scan.Options
	rep model.Report

	cj      claudeJSON
	cjDoc   []byte
	cjState fileState

	facts   map[string]*TranscriptFacts
	usage   map[string]map[match.Key]Use // per transcript, from its calls after copies are removed
	paths   []string                     // transcripts that were read, sorted
	oldest  time.Time
	desktop []session
	prompts []session

	files  []*settingsFile
	byPath map[string]*settingsFile

	backups     []jsonBackup // backups of ~/.claude.json, read on first use
	backupsRead bool

	blocked map[string]bool // project folders macOS or permissions would not let grants read
}

// Collect finds Claude Code grants, dates them from local history and measures use.
func Collect(env model.Env, opt scan.Options) model.Report {
	c := &collector{env: env, opt: opt, rep: model.Report{Agent: model.ClaudeCode}, blocked: map[string]bool{}}
	if !pathExists(env.ClaudeDir) && !pathExists(env.ClaudeJSON) {
		return c.rep
	}
	c.rep.Found = true
	c.readClaudeJSON()
	c.scanTranscripts()
	c.readOtherHistory()
	c.discoverFiles()
	for _, sf := range c.files {
		c.ruleGrants(sf)
	}
	c.legacyGrants()
	c.trustGrants()
	c.finish()
	return c.rep
}

func (c *collector) note(level, format string, args ...any) {
	c.rep.Notes = append(c.rep.Notes, model.Note{Level: level, Text: fmt.Sprintf(format, args...)})
}

func (c *collector) readClaudeJSON() {
	c.cj = claudeJSON{Projects: map[string]projectInfo{}}
	var tooLarge bool
	c.cjDoc, c.cjState, tooLarge = readFileMax(c.env.ClaudeJSON, maxClaudeJSONSize)
	switch c.cjState {
	case stateBlocked:
		if tooLarge {
			c.note("warn", "%s is too large to read, so trust and legacy rules are missing.", c.env.ClaudeJSON)
		} else {
			c.note("warn", "Could not read %s, so trust and legacy rules are missing.", c.env.ClaudeJSON)
		}
	case stateOK:
		cj, err := parseClaudeJSON(c.cjDoc)
		if err != nil {
			c.note("warn", "Could not parse %s, so trust and legacy rules are missing.", c.env.ClaudeJSON)
			c.cjState = stateBlocked
			return
		}
		c.cj = cj
		c.rep.Read = append(c.rep.Read, filepath.Clean(c.env.ClaudeJSON))
	}
}

func (c *collector) scanTranscripts() {
	root := filepath.Join(c.env.ClaudeDir, "projects")
	histRoot := filepath.Join(c.env.ClaudeDir, "file-history")
	files, skipped, _ := scan.Walk(root, func(p string) bool { return strings.HasSuffix(p, ".jsonl") })
	if skipped > 0 {
		c.note("warn", "%s could not be read.", model.Plural(skipped, "transcript folder", "transcript folders"))
	}
	var cache *scan.Cache
	if !c.opt.NoCache && c.env.StateDir != "" {
		var err error
		if cache, err = scan.Open(c.env.StateDir, transcriptCacheName, transcriptCacheVersion); err != nil {
			c.note("warn", "Could not open the transcript cache: %v", err)
			cache = nil
		}
	}
	got, st := scan.Run(cache, files, c.opt, "Claude Code transcripts", func(p string) (TranscriptFacts, error) {
		return extractTranscript(p, root, histRoot)
	})
	if cache != nil {
		if err := cache.Save(); err != nil {
			c.note("warn", "Could not save the transcript cache: %v", err)
		}
	}
	if st.Failed > 0 {
		c.note("warn", "%s could not be read.", model.Plural(st.Failed, "Claude Code transcript", "Claude Code transcripts"))
	}
	c.facts = make(map[string]*TranscriptFacts, len(got))
	var from, to time.Time
	for p, f := range got {
		f := f
		c.facts[p] = &f
		c.paths = append(c.paths, p)
		if !f.Start.IsZero() && (from.IsZero() || f.Start.Before(from)) {
			from = f.Start
		}
		if f.End.After(to) {
			to = f.End
		}
	}
	sort.Strings(c.paths)
	c.buildUsage()
	c.oldest = from
	if len(got) > 0 {
		c.rep.Coverage = append(c.rep.Coverage, model.Coverage{Source: "Claude Code transcripts", Files: len(got), From: from, To: to})
	}
}

// buildUsage counts the tool calls of every transcript so that a call counts once. A
// resumed or forked session copies the calls of its parent into a new transcript. The
// oldest transcript owns a call, so the original session keeps it. The per-file counts
// are never cached: they would include the copies.
func (c *collector) buildUsage() {
	order := slices.Clone(c.paths)
	sort.SliceStable(order, func(i, j int) bool {
		return c.facts[order[i]].Start.Before(c.facts[order[j]].Start)
	})
	seen := map[uint64]struct{}{}
	c.usage = make(map[string]map[match.Key]Use, len(order))
	for _, p := range order {
		u := map[match.Key]Use{}
		countCalls(u, c.facts[p].Calls, seen)
		c.usage[p] = u
	}
}

// countCalls adds the keys of calls to usage. A call whose ID is in seen is skipped, and
// a call with an ID is added to seen. seen may be nil to count every call.
func countCalls(usage map[match.Key]Use, calls []ToolCall, seen map[uint64]struct{}) {
	for _, call := range calls {
		if call.ID != 0 && seen != nil {
			if _, dup := seen[call.ID]; dup {
				continue
			}
			seen[call.ID] = struct{}{}
		}
		for _, k := range call.Keys {
			u := usage[k]
			u.Count++
			u.Last = max(u.Last, call.Last)
			usage[k] = u
		}
	}
}

func (c *collector) readOtherHistory() {
	var files int
	c.desktop, files = desktopSessions(c.env.Home)
	if files > 0 {
		from, to := span(c.desktop)
		c.rep.Coverage = append(c.rep.Coverage, model.Coverage{Source: "Claude desktop sessions", Files: files, From: from, To: to})
	}
	var from, to time.Time
	c.prompts, files, from, to = promptHistory(filepath.Join(c.env.ClaudeDir, "history.jsonl"))
	if files > 0 {
		c.rep.Coverage = append(c.rep.Coverage, model.Coverage{Source: "Claude Code prompt history", Files: files, From: from, To: to})
	}
}

func span(ss []session) (from, to time.Time) {
	for _, s := range ss {
		if from.IsZero() || s.T.Before(from) {
			from = s.T
		}
		if s.T.After(to) {
			to = s.T
		}
	}
	return from, to
}

// finish adds the notes that need the whole picture. The merge step rates and orders the grants.
func (c *collector) finish() {
	if len(c.blocked) > 0 {
		c.note("warn", "%s could not be read (macOS privacy). Give your terminal Full Disk Access to include their settings.", model.Plural(len(c.blocked), "project folder", "project folders"))
	}
	if !c.oldest.IsZero() && !c.cj.FirstStart.IsZero() && c.oldest.Sub(c.cj.FirstStart) > transcriptsOutlived {
		c.note("info", "Claude Code keeps transcripts for cleanupPeriodDays (30 by default). Grants older than %s are dated from backups and first-session times.", c.oldest.Format("2006-01-02"))
	}
}
