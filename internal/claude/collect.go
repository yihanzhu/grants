// Package claude finds the grants Claude Code holds: allow rules in its settings files
// and the folders it trusts. It dates each grant from the agent's own history, counts
// how often it was used, and plans the file edits that revoke it.
package claude

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
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
	paths   []string // transcripts that were read, sorted
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
	c.cjDoc, c.cjState = readFile(c.env.ClaudeJSON)
	switch c.cjState {
	case stateBlocked:
		c.note("warn", "Could not read %s, so trust and legacy rules are missing.", c.env.ClaudeJSON)
	case stateOK:
		cj, err := parseClaudeJSON(c.cjDoc)
		if err != nil {
			c.note("warn", "Could not parse %s, so trust and legacy rules are missing.", c.env.ClaudeJSON)
			c.cjState = stateBlocked
			return
		}
		c.cj = cj
	}
}

func (c *collector) scanTranscripts() {
	root := filepath.Join(c.env.ClaudeDir, "projects")
	histRoot := filepath.Join(c.env.ClaudeDir, "file-history")
	files, skipped, _ := scan.Walk(root, func(p string) bool { return strings.HasSuffix(p, ".jsonl") })
	if skipped > 0 {
		c.note("warn", "%d transcript folders could not be read.", skipped)
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
		c.note("warn", "%d Claude Code transcripts could not be read.", st.Failed)
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
	c.oldest = from
	if len(got) > 0 {
		c.rep.Coverage = append(c.rep.Coverage, model.Coverage{Source: "Claude Code transcripts", Files: len(got), From: from, To: to})
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

// finish rates every grant, orders them, and adds the notes that need the whole picture.
func (c *collector) finish() {
	exists := pathExists
	for i := range c.rep.Grants {
		g := &c.rep.Grants[i]
		g.ID = model.MakeID(g.Key)
		risk.Assess(g, c.env, exists)
	}
	rank := map[model.Status]int{model.StatusActive: 0, model.StatusUnknown: 1, model.StatusGone: 2}
	sort.SliceStable(c.rep.Grants, func(i, j int) bool {
		a, b := c.rep.Grants[i], c.rep.Grants[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Value < b.Value
	})
	if len(c.blocked) > 0 {
		c.note("warn", "%d project folders could not be read (macOS privacy). Give your terminal Full Disk Access to include their settings.", len(c.blocked))
	}
	if !c.oldest.IsZero() && !c.cj.FirstStart.IsZero() && c.oldest.Sub(c.cj.FirstStart) > transcriptsOutlived {
		c.note("info", "Claude Code keeps transcripts for cleanupPeriodDays (30 by default). Grants older than %s are dated from backups and first-session times.", c.oldest.Format("2006-01-02"))
	}
}
