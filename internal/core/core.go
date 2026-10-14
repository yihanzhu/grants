// Package core runs every agent adapter and turns their reports into one list of
// grants: assessed for risk, flagged when unused, dated, given short ids and sorted.
package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yihanzhu/grants/internal/claude"
	"github.com/yihanzhu/grants/internal/codex"
	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
	"github.com/yihanzhu/grants/internal/store"
)

// DefaultUnusedAfter is how long a grant may go unused before it is flagged.
const DefaultUnusedAfter = 90 * 24 * time.Hour

// Result is everything one run learned.
type Result struct {
	Env     model.Env
	Reports []model.Report // one per agent, in a fixed order: claude-code, codex
	Grants  []model.Grant  // merged, assessed, sorted
	Notes   []model.Note   // problems of the run itself, such as a state file that cannot be written
	Took    time.Duration
}

// EnvFromOS builds the real environment from the process: HOME, CLAUDE_CONFIG_DIR,
// CODEX_HOME, GRANTS_STATE_DIR (or XDG_STATE_HOME), and GRANTS_NOW (RFC 3339, for
// tests). A zero unusedAfter means 90 days.
func EnvFromOS(unusedAfter time.Duration) (model.Env, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return model.Env{}, errors.New("cannot find your home folder; set HOME")
	}
	if unusedAfter <= 0 {
		unusedAfter = DefaultUnusedAfter
	}
	env := model.Env{Home: home, UnusedAfter: unusedAfter, Now: time.Now()}

	env.ClaudeDir = filepath.Join(home, ".claude")
	env.ClaudeJSON = filepath.Join(home, ".claude.json")
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		env.ClaudeDir = d
		if alt := filepath.Join(d, ".claude.json"); fsx.Exists(alt) {
			env.ClaudeJSON = alt
		}
	}
	env.CodexHome = filepath.Join(home, ".codex")
	if d := os.Getenv("CODEX_HOME"); d != "" {
		env.CodexHome = d
	}
	env.StateDir = store.DefaultStateDir(home)

	if s := os.Getenv("GRANTS_NOW"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return model.Env{}, fmt.Errorf("GRANTS_NOW must be an RFC 3339 time: %w", err)
		}
		env.Now = t
	}
	return env, nil
}

// Run collects every agent (concurrently), merges grants' own observations, assesses
// risk and flags, assigns unique ids, records this run, and sorts.
func Run(env model.Env, opt scan.Options) (Result, error) {
	start := time.Now()
	res := Result{Env: env}
	res.Reports = collect(env, opt)

	obs, err := store.Load(env.StateDir)
	if err != nil {
		res.Notes = append(res.Notes, model.Note{Level: "warn", Text: "Could not read grants' own history, so dates come from the agents only: " + err.Error()})
	}
	res.Grants = merge(env, res.Reports, obs)
	if err := obs.Save(env.StateDir); err != nil {
		res.Notes = append(res.Notes, model.Note{Level: "warn", Text: "Could not save grants' own history: " + err.Error()})
	}
	res.Took = time.Since(start)
	return res, nil
}

// collect runs both adapters at once. A crash in one becomes a note in its report.
func collect(env model.Env, opt scan.Options) []model.Report {
	fns := []struct {
		agent model.Agent
		name  string
		run   func(model.Env, scan.Options) model.Report
	}{
		{model.ClaudeCode, "Claude Code", claude.Collect},
		{model.Codex, "Codex", codex.Collect},
	}
	reports := make([]model.Report, len(fns))
	var wg sync.WaitGroup
	for i, f := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					reports[i] = model.Report{Agent: f.agent, Found: true, Notes: []model.Note{{Level: "warn", Text: fmt.Sprintf("%s scan stopped early: %v", f.name, r)}}}
				}
			}()
			reports[i] = f.run(env, opt)
			reports[i].Agent = f.agent
		}()
	}
	wg.Wait()
	return reports
}
