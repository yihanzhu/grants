// Package codex finds the permissions a person has given the Codex agent: command
// prefix rules in .rules files and folders trusted in config.toml. It dates each
// grant from Codex's own session files and measures how often it was used.
package codex

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
	"github.com/yihanzhu/grants/internal/timeline"
)

// managedRulesDir holds rules set by an administrator. It is a variable so tests can
// point it at a temp folder.
var managedRulesDir = "/etc/codex/rules"

// OverrideManaged replaces the folder that holds administrator rules and returns a
// function that puts the default back. It lets tests run on a machine that has real
// managed rules.
func OverrideManaged(dir string) (restore func()) {
	old := managedRulesDir
	managedRulesDir = dir
	return func() { managedRulesDir = old }
}

const restartNote = "Restart Codex to apply."

// ruleFile is one parsed .rules file.
type ruleFile struct {
	Path     string
	Scope    model.Scope
	Project  string // folder for project files
	Rules    []Rule
	Mod      time.Time
	Birth    time.Time
	HasBirth bool
}

// session is the facts of one rollout file.
type session struct {
	Path string
	F    RolloutFacts
}

// snap is one approved-prefix snapshot with the session it came from.
type snap struct {
	From, To time.Time
	Cwd      string
	File     string
	Set      map[string]struct{} // PatternJSON of each approved prefix
	Prefixes [][]string
}

type collector struct {
	env      model.Env
	cfgPath  string
	rep      model.Report
	trusted  []trustEntry
	cfgBad   bool            // config.toml could not be read or parsed
	rulesBad bool            // a rules file or folder (other than a blocked project folder) could not be read
	trustSet map[string]bool // every folder the config or a backup trusts
	backups  []backupData
	files    []ruleFile
	blocked  []string // trusted folders whose rules folder macOS would not let us read
	sessions []session
	snaps    []snap
	since    time.Time // oldest session start
}

type backupData struct {
	backupFile
	Trusted map[string]bool
}

// Collect finds Codex grants, dates them from local history and measures use.
func Collect(env model.Env, opt scan.Options) (rep model.Report) {
	rep = model.Report{Agent: model.Codex}
	if env.CodexHome == "" || !fsx.Exists(env.CodexHome) {
		return rep
	}
	rep.Found = true
	c := &collector{env: env, cfgPath: filepath.Join(env.CodexHome, "config.toml"), rep: rep}
	defer func() {
		if r := recover(); r != nil {
			c.rep.Notes = append(c.rep.Notes, model.Note{Level: "warn", Text: fmt.Sprintf("Codex scan stopped early: %v", r)})
			c.rep.Read = nil // nothing is known to be read, so core infers no removal
			rep = c.rep
		}
	}()
	c.readConfig()
	c.readRules()
	c.readSessions(opt)
	c.buildSnaps()
	c.assemble()
	return c.rep
}

func (c *collector) note(level, format string, args ...any) {
	c.rep.Notes = append(c.rep.Notes, model.Note{Level: level, Text: fmt.Sprintf(format, args...)})
}

func (c *collector) readConfig() {
	doc, err := os.ReadFile(c.cfgPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.note("warn", "Could not read Codex config.toml: %v", err)
			c.cfgBad = true
		}
	} else if c.trusted, err = parseTrusted(doc); err == nil {
		c.rep.Read = append(c.rep.Read, c.cfgPath)
	} else {
		c.cfgBad = true
		// Name only the line: the parser error can quote part of the file, which may
		// be an unquoted secret.
		var pe toml.ParseError
		if errors.As(err, &pe) {
			c.note("warn", "Could not parse Codex config.toml (syntax error at line %d), so trusted folders are missing", pe.Position.Line)
		} else {
			c.note("warn", "Could not parse Codex config.toml, so trusted folders are missing")
		}
	}
	for _, b := range configBackups(c.cfgPath) {
		data, err := os.ReadFile(b.Path)
		if err != nil {
			continue
		}
		entries, err := parseTrusted(data)
		if err != nil {
			continue
		}
		set := make(map[string]bool, len(entries))
		for _, e := range entries {
			set[e.Path] = true
		}
		c.backups = append(c.backups, backupData{backupFile: b, Trusted: set})
	}
	c.trustSet = map[string]bool{}
	for _, t := range c.trusted {
		c.trustSet[t.Path] = true
	}
	for _, b := range c.backups {
		for p := range b.Trusted {
			c.trustSet[p] = true
		}
	}
}

// readRules loads user, managed and project rules files.
func (c *collector) readRules() {
	userDir := filepath.Join(c.env.CodexHome, "rules")
	seen := map[string]bool{}
	add := func(dir string, scope model.Scope, project string) (blocked bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			blocked = errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EPERM)
			if !errors.Is(err, fs.ErrNotExist) && (scope != model.ScopeProject || !blocked) {
				c.rulesBad = true // a blocked project folder is reported as such, not as a gap
			}
			return blocked
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".rules") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			info, err := os.Stat(p)
			if err != nil {
				c.rulesBad = c.rulesBad || !errors.Is(err, fs.ErrNotExist)
				continue
			}
			if !info.Mode().IsRegular() || seen[p] {
				continue
			}
			seen[p] = true
			src, err := os.ReadFile(p)
			if err != nil {
				c.note("warn", "Could not read rules file %s: %v", p, err)
				c.rulesBad = true
				continue
			}
			f := ruleFile{Path: p, Scope: scope, Project: project, Rules: ParseRules(src), Mod: info.ModTime()}
			f.Birth, f.HasBirth = fsx.Birthtime(p)
			c.files = append(c.files, f)
		}
		return false
	}
	add(userDir, model.ScopeUser, "")
	add(managedRulesDir, model.ScopeManaged, "")
	for _, t := range c.trusted {
		if add(filepath.Join(t.Path, ".codex", "rules"), model.ScopeProject, t.Path) {
			c.blocked = append(c.blocked, t.Path)
		}
	}
	if n := len(c.blocked); n > 0 {
		c.note("warn", "%s could not be read (macOS privacy). Give your terminal Full Disk Access to include their rules.", model.Plural(n, "trusted folder", "trusted folders"))
	}
	bad := 0
	for _, f := range c.files {
		fileBad := 0
		for _, r := range f.Rules {
			if r.Err != "" {
				fileBad++
			}
		}
		bad += fileBad
		if fileBad == 0 {
			c.rep.Read = append(c.rep.Read, f.Path) // a file with a broken statement is only partly read
		}
	}
	if bad > 0 {
		c.note("warn", "%s in Codex rules files could not be parsed and %s left out.", model.Plural(bad, "statement", "statements"), map[bool]string{true: "was", false: "were"}[bad == 1])
	}
}

func (c *collector) readSessions(opt scan.Options) {
	var files []string
	skipped := 0
	for _, root := range []string{filepath.Join(c.env.CodexHome, "sessions"), filepath.Join(c.env.CodexHome, "archived_sessions")} {
		got, sk, _ := scan.Walk(root, func(p string) bool {
			n := filepath.Base(p)
			return strings.HasPrefix(n, "rollout-") && (strings.HasSuffix(n, ".jsonl") || strings.HasSuffix(n, ".jsonl.zst"))
		})
		files = append(files, got...)
		skipped += sk
	}
	files = withoutCompressedTwins(files)
	var cache *scan.Cache
	if !opt.NoCache && c.env.StateDir != "" {
		var err error
		if cache, err = scan.Open(c.env.StateDir, cacheName, rolloutVersion); err != nil {
			c.note("warn", "Could not open the Codex scan cache: %v", err)
			cache = nil
		}
	}
	results, stats := scan.Run(cache, files, opt, "Codex sessions", ExtractRollout)
	if cache != nil {
		if err := cache.Save(); err != nil {
			c.note("warn", "Could not save the Codex scan cache: %v", err)
		}
	}
	if stats.Failed > 0 {
		c.note("warn", "%s could not be read.", model.Plural(stats.Failed, "Codex session file", "Codex session files"))
	}
	if skipped > 0 {
		c.note("warn", "%s could not be read.", model.Plural(skipped, "Codex session folder", "Codex session folders"))
	}
	paths := make([]string, 0, len(results))
	for p := range results {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	cov := model.Coverage{Source: "Codex sessions", Files: len(paths)}
	for _, p := range paths {
		f := results[p]
		c.sessions = append(c.sessions, session{Path: p, F: f})
		if !f.Start.IsZero() && (c.since.IsZero() || f.Start.Before(c.since)) {
			c.since = f.Start
		}
		if !f.Start.IsZero() && (cov.From.IsZero() || f.Start.Before(cov.From)) {
			cov.From = f.Start
		}
		if f.End.After(cov.To) {
			cov.To = f.End
		}
	}
	c.rep.Coverage = append(c.rep.Coverage, cov)
}

// buildSnaps flattens every session's prefix runs. Identical sets share one map.
func (c *collector) buildSnaps() {
	interned := map[string]map[string]struct{}{}
	for _, s := range c.sessions {
		for _, run := range s.F.Prefixes {
			keys := make([]string, len(run.Prefixes))
			for i, p := range run.Prefixes {
				keys[i] = PatternJSON(toPositions(p))
			}
			sort.Strings(keys)
			id := strings.Join(keys, "\x00")
			set, ok := interned[id]
			if !ok {
				set = make(map[string]struct{}, len(keys))
				for _, k := range keys {
					set[k] = struct{}{}
				}
				interned[id] = set
			}
			c.snaps = append(c.snaps, snap{From: run.From, To: run.To, Cwd: s.F.Cwd, File: s.Path, Set: set, Prefixes: run.Prefixes})
		}
	}
}

// inScope reports whether a session counts as evidence for a grant limited to folder.
// An empty folder means every session.
func inScope(cwd, folder string) bool { return folder == "" || fsx.Within(cwd, folder) }

func (c *collector) assemble() {
	rules := c.activeRules()
	gone := c.goneRules(rules)
	trusts := c.trustGrants()

	var all []model.Grant
	all = append(all, rules...)
	all = append(all, gone...)
	all = append(all, trusts...)
	c.rep.Grants = all
}

// --- rules ---

// ruleDraft is an active rule before dating.
type ruleDraft struct {
	g  model.Grant
	pj string
	f  *ruleFile
}

func (c *collector) activeRules() []model.Grant {
	order := []model.Scope{model.ScopeUser, model.ScopeManaged, model.ScopeProject}
	seenKey := map[string]bool{}
	var drafts []ruleDraft
	for _, scope := range order {
		for i := range c.files {
			f := &c.files[i]
			if f.Scope != scope {
				continue
			}
			inFile := map[string]bool{}
			for _, r := range f.Rules {
				if r.Err != "" || r.Name != "prefix_rule" || r.Decision != "allow" {
					continue
				}
				pj := PatternJSON(r.Pattern)
				if inFile[pj] {
					continue
				}
				inFile[pj] = true
				// The key depends only on the rule's own file, so removing a copy in
				// another file does not move this id. User rules keep the plain key
				// because history snapshots do not name a file.
				key := model.KeyCodexRule(pj)
				if f.Scope != model.ScopeUser || seenKey[key] {
					key += "|" + f.Path
				}
				seenKey[key] = true
				g := model.Grant{
					Key: key, Agent: model.Codex, Kind: model.KindRule,
					Value: PatternDisplay(r.Pattern), Pattern: r.Pattern, Tool: "exec",
					Scope: f.Scope, Project: f.Project,
					Location: model.Location{File: f.Path, Pointer: "prefix_rule", Line: r.Line},
					Status:   model.StatusActive, Revocable: f.Scope != model.ScopeManaged,
				}
				if g.Revocable {
					g.RevokeNote = restartNote
				} else {
					g.RevokeNote = "Set by your organization."
				}
				drafts = append(drafts, ruleDraft{g: g, pj: pj, f: f})
			}
		}
	}
	out := make([]model.Grant, 0, len(drafts))
	for _, d := range drafts {
		g := d.g
		c.dateRule(&g, d.f)
		g.Usage = c.ruleUsage(g.Pattern, g.Project, g.Granted.After)
		out = append(out, g)
	}
	return out
}

// dateRule fills the grant window and evidence of an active rule.
func (c *collector) dateRule(g *model.Grant, f *ruleFile) {
	obs := c.snapshotObs(g.Pattern, g.Project)
	if f.HasBirth {
		obs = append(obs, timeline.Obs{T: f.Birth, Present: false, Source: "rules file created", File: f.Path})
	}
	obs = append(obs, timeline.Obs{T: f.Mod, Present: true, Source: "rules file last changed", File: f.Path})
	res := timeline.Date(obs)
	g.Granted = res.Granted
	g.Evidence = res.Evidence
	c.applyEscalation(g)
}

// snapshotObs turns the session snapshots into present or absent observations of a
// pattern. Sessions outside folder are ignored when folder is set.
func (c *collector) snapshotObs(pattern [][]string, folder string) []timeline.Obs {
	exp := expand(pattern)
	if exp == nil {
		return nil
	}
	want := make([]string, len(exp))
	for i, e := range exp {
		want[i] = PatternJSON(toPositions(e))
	}
	var obs []timeline.Obs
	for i := range c.snaps {
		s := &c.snaps[i]
		if !inScope(s.Cwd, folder) {
			continue
		}
		present := true
		for _, w := range want {
			if _, ok := s.Set[w]; !ok {
				present = false
				break
			}
		}
		o := timeline.Obs{T: s.From, Present: present, Source: "Codex session snapshot", File: s.File}
		obs = append(obs, o)
		if s.To.After(s.From) {
			o.T = s.To
			obs = append(obs, o)
		}
	}
	return obs
}

// applyEscalation uses the first time the agent asked for the rule's prefix, when the
// command then ran and the time fits the window, as a tighter upper bound.
func (c *collector) applyEscalation(g *model.Grant) {
	exp := expand(g.Pattern)
	if exp == nil {
		return
	}
	var first *Escalation
	for i := range c.sessions {
		s := &c.sessions[i]
		if !inScope(s.F.Cwd, g.Project) {
			continue
		}
		for j := range s.F.Escalations {
			e := &s.F.Escalations[j]
			if !matchesAny(exp, e.Prefix) {
				continue
			}
			if first == nil || e.T.Before(first.T) {
				first = e
			}
		}
	}
	if first == nil || !first.Ran || first.T.IsZero() {
		return
	}
	w := g.Granted
	if (!w.After.IsZero() && !first.T.After(w.After)) || (!w.Before.IsZero() && first.T.After(w.Before)) {
		return
	}
	g.Granted.Before = first.T
	g.Granted.Approx = true // the approval came a little after the request
	g.Granted.Source = "approved when the agent asked"
	detail := first.Justification
	if detail == "" {
		detail = "agent asked to run it outside the sandbox"
	}
	g.Evidence = append(g.Evidence, model.Evidence{Time: first.T, What: "proposed", Detail: detail})
	sort.SliceStable(g.Evidence, func(i, j int) bool { return g.Evidence[i].Time.Before(g.Evidence[j].Time) })
}

func matchesAny(exp [][]string, prefix []string) bool {
	for _, e := range exp {
		if len(e) == len(prefix) {
			same := true
			for i := range e {
				if e[i] != prefix[i] {
					same = false
					break
				}
			}
			if same {
				return true
			}
		}
	}
	return false
}

// ruleUsage sums matching commands over the sessions in scope. A session counts when
// it has a matching command after after (when known); a session that straddles after
// counts in full, so the number can be slightly high.
func (c *collector) ruleUsage(pattern [][]string, folder string, after time.Time) model.Usage {
	u := model.Usage{Since: c.since}
	keys := match.CodexPatternKeys(pattern)
	if len(keys) == 0 || len(pattern) > match.MaxPrefix {
		return u // long patterns are only counted on exact runs, so we cannot measure them
	}
	u.Known = true
	var last int64
	for i := range c.sessions {
		s := &c.sessions[i]
		if !inScope(s.F.Cwd, folder) {
			continue
		}
		for _, k := range keys {
			use, ok := s.F.Usage[k]
			if !ok || use.Count == 0 {
				continue
			}
			if !after.IsZero() && use.Last > 0 && use.Last <= after.Unix() {
				continue
			}
			u.Count += int(use.Count)
			last = max(last, use.Last)
		}
	}
	if last > 0 {
		u.Last = time.Unix(last, 0)
	}
	return u
}

// goneRules finds prefixes that snapshots listed but no readable rules file holds now.
func (c *collector) goneRules(active []model.Grant) []model.Grant {
	have := map[string]bool{}
	for _, g := range active {
		for _, e := range expand(g.Pattern) {
			have[PatternJSON(toPositions(e))] = true
		}
	}
	type seenPrefix struct {
		tokens []string
		cwds   []string
	}
	universe := map[string]*seenPrefix{}
	for i := range c.snaps {
		s := &c.snaps[i]
		for _, p := range s.Prefixes {
			pj := PatternJSON(toPositions(p))
			if have[pj] {
				continue
			}
			sp := universe[pj]
			if sp == nil {
				sp = &seenPrefix{tokens: p}
				universe[pj] = sp
			}
			if n := len(sp.cwds); n == 0 || sp.cwds[n-1] != s.Cwd {
				sp.cwds = append(sp.cwds, s.Cwd)
			}
		}
	}
	pjs := make([]string, 0, len(universe))
	for pj := range universe {
		pjs = append(pjs, pj)
	}
	sort.Strings(pjs)

	var out []model.Grant
	for _, pj := range pjs {
		sp := universe[pj]
		pattern := toPositions(sp.tokens)
		g := model.Grant{
			Key: model.KeyCodexRule(pj), Agent: model.Codex, Kind: model.KindRule,
			Value: PatternDisplay(pattern), Pattern: pattern, Tool: "exec",
			Scope: model.ScopeUser, Status: model.StatusGone, RevokeNote: "Already removed",
		}
		folder, blocked := c.limitFolder(sp.cwds)
		if folder != "" {
			g.Scope, g.Project = model.ScopeProject, folder
		}
		res := timeline.Date(c.snapshotObs(pattern, folder))
		// A later session in the folder without the rule shows it was removed. Only a
		// rule still present at its last sighting may sit in the unreadable folder. A
		// config or rules file that could not be read hides project rules in the same way.
		if res.RemovedAt.Before.IsZero() {
			switch {
			case blocked:
				g.Status, g.RevokeNote = model.StatusUnknown, "Folder not readable"
			case c.cfgBad || c.rulesBad:
				g.Status, g.RevokeNote = model.StatusUnknown, "File not readable"
			}
		}
		if g.Status == model.StatusGone {
			g.Removed = res.RemovedAt
		}
		g.Granted = res.Granted
		g.LastSeen = res.LastSeen
		g.Evidence = res.Evidence
		c.applyEscalation(&g)
		g.Usage = c.ruleUsage(pattern, folder, g.Granted.After)
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// limitFolder decides whether a gone rule looks limited to one project folder: a
// folder we could not read, or else the deepest trusted folder, that holds every
// session where the rule was seen. blocked says that folder was unreadable.
func (c *collector) limitFolder(cwds []string) (folder string, blocked bool) {
	if len(cwds) == 0 {
		return "", false
	}
	containsAll := func(dir string) bool {
		for _, w := range cwds {
			if !fsx.Within(w, dir) {
				return false
			}
		}
		return true
	}
	for _, b := range c.blocked {
		if containsAll(b) {
			return b, true
		}
	}
	best := ""
	for _, t := range c.trusted {
		if t.Path == "/" || t.Path == c.env.Home || !containsAll(t.Path) {
			continue
		}
		if len(t.Path) > len(best) {
			best = t.Path
		}
	}
	return best, false
}

// --- trust ---

func (c *collector) trustGrants() []model.Grant {
	activeSet := map[string]bool{}
	var out []model.Grant
	for _, t := range c.trusted {
		activeSet[t.Path] = true
		g := model.Grant{
			Key: model.KeyCodexTrust(t.Path), Agent: model.Codex, Kind: model.KindTrust,
			Value: t.Path, Scope: model.ScopeUser, Status: model.StatusActive, Revocable: true,
			Location: model.Location{File: c.cfgPath, Pointer: `projects."` + t.Path + `".trust_level`, Line: t.Line},
		}
		if trustPathGone(t.Path) {
			g.RevokeNote = "Removes the entry. " + restartNote
		} else {
			g.RevokeNote = `Sets trust_level to "untrusted". ` + restartNote
		}
		c.dateTrust(&g, true)
		out = append(out, g)
	}
	// Folders a config backup trusted that the config no longer does.
	goneSeen := map[string]bool{}
	var goneG []model.Grant
	for _, b := range c.backups {
		var paths []string
		for p := range b.Trusted {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			if activeSet[p] || goneSeen[p] {
				continue
			}
			goneSeen[p] = true
			g := model.Grant{
				Key: model.KeyCodexTrust(p), Agent: model.Codex, Kind: model.KindTrust,
				Value: p, Scope: model.ScopeUser, Status: model.StatusGone, RevokeNote: "Already removed",
			}
			c.dateTrust(&g, false)
			if c.cfgBad {
				// The config was not read, so the folder may still be trusted.
				g.Status, g.RevokeNote, g.Removed = model.StatusUnknown, "File not readable", model.Window{}
			}
			goneG = append(goneG, g)
		}
	}
	sort.SliceStable(goneG, func(i, j int) bool { return goneG[i].LastSeen.After(goneG[j].LastSeen) })
	return append(out, goneG...)
}

// dateTrust dates a trusted folder from the first session in it, a date in its path,
// config backups and the config file's modification time, and counts its sessions.
func (c *collector) dateTrust(g *model.Grant, active bool) {
	path := g.Value
	var obs []timeline.Obs
	var first *session
	var sessions int
	var last time.Time
	for i := range c.sessions {
		s := &c.sessions[i]
		if !fsx.Within(s.F.Cwd, path) {
			continue
		}
		if s.F.Source != "subagent" {
			sessions++ // a subagent rollout belongs to its parent's session
		}
		if t := lastTime(s.F); t.After(last) {
			last = t
		}
		if ownedBelow(s.F.Cwd, path, c.trustSet) {
			continue // trust on a parent does not start with a session in a trusted child
		}
		if !s.F.Start.IsZero() && (first == nil || s.F.Start.Before(first.F.Start)) {
			first = s
		}
	}
	if first != nil {
		obs = append(obs, timeline.Obs{T: first.F.Start, Present: true, Approx: true, Source: "first Codex session in this folder", File: first.Path})
	}
	if day, ok := pathDay(path); ok {
		obs = append(obs, timeline.Obs{T: day, Present: false, Source: "date in the folder name"})
	}
	for _, b := range c.backups {
		obs = append(obs, timeline.Obs{T: b.Time, Present: b.Trusted[path], Source: "config backup", File: b.Path})
	}
	// The config's modification time says when the file as read now was written. It
	// says nothing about a file that did not parse: its content is unknown.
	if info, err := os.Stat(c.cfgPath); err == nil && !c.cfgBad {
		obs = append(obs, timeline.Obs{T: info.ModTime(), Present: active, Source: "config last changed", File: c.cfgPath})
	}
	res := timeline.Date(obs)
	g.Granted = res.Granted
	g.Evidence = res.Evidence
	if !active {
		g.LastSeen = res.LastSeen
		g.Removed = res.RemovedAt
	}
	g.Usage = model.Usage{Known: true, Count: sessions, Last: last, Since: c.since}
}

func lastTime(f RolloutFacts) time.Time {
	if !f.End.IsZero() {
		return f.End
	}
	return f.Start
}

// ownedBelow reports whether a trusted folder lies between p and dir, dir excluded.
func ownedBelow(p, dir string, trusted map[string]bool) bool {
	dir = filepath.Clean(dir)
	for q := filepath.Clean(p); q != dir; {
		if trusted[q] {
			return true
		}
		up := filepath.Dir(q)
		if up == q {
			break
		}
		q = up
	}
	return false
}

// withoutCompressedTwins drops x.jsonl.zst when x.jsonl is also listed. Codex
// compresses older sessions; while it does, both copies can exist for a moment.
func withoutCompressedTwins(files []string) []string {
	plain := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, ".jsonl") {
			plain[f] = true
		}
	}
	out := files[:0]
	for _, f := range files {
		if strings.HasSuffix(f, ".zst") && plain[strings.TrimSuffix(f, ".zst")] {
			continue
		}
		out = append(out, f)
	}
	return out
}
