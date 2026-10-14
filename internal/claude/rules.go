package claude

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/timeline"
)

// A snap is what one source says the allow list of a settings file held at one moment.
type snap struct {
	T      time.Time
	Rules  map[string]bool // normalized rules
	Source string
	Approx bool
	Ref    string // file the observation came from
	Birth  bool   // the file did not exist yet
}

// fileView is a settings file as read now.
type fileView struct {
	sf        *settingsFile
	state     fileState
	invalid   bool // exists but is not JSON grants can read
	doc       []byte
	allow     []string // permissions.allow now, without duplicates
	mtime     time.Time
	committed bool
}

const (
	srcHistory = "Claude Code file-history backup"
	srcEdit    = "settings edit in a session"
	srcBackup  = "backup file next to the settings"
	srcGit     = "git history"
	srcLive    = "settings file last changed"
	srcBirth   = "settings file created"
)

func (c *collector) ruleGrants(sf *settingsFile) {
	v := &fileView{sf: sf}
	v.doc, v.state = readFile(sf.Path)
	if v.state == stateBlocked {
		switch sf.Scope {
		case model.ScopeUser, model.ScopeManaged:
			c.note("warn", "Could not read %s, so its rules are not listed.", sf.Path)
		default:
			c.blocked[sf.Project] = true
		}
	}
	if v.state == stateOK {
		allow, err := parseAllow(v.doc)
		if err != nil {
			v.invalid = true
			c.note("warn", "Could not parse %s (not valid JSON), so its rules are not listed.", sf.Path)
		}
		v.allow = dedupe(allow)
		if fi, err := os.Stat(sf.Path); err == nil {
			v.mtime = fi.ModTime()
		}
	}
	if sf.Scope == model.ScopeProject && v.state == stateOK && !v.invalid {
		v.committed = isCommitted(sf)
	}
	snaps := c.snapshots(v)
	if len(v.allow) == 0 && !hasHistory(snaps) {
		return // nothing granted now, nothing to look back on
	}

	live := map[string]bool{}
	for _, r := range v.allow {
		live[normRule(r)] = true
	}
	lines := arrayLines(v.doc, []string{"permissions", "allow"})
	for _, r := range v.allow {
		g := c.newRule(v, r, lines[r])
		res := dateGrant(ruleObs(snaps, normRule(r)), true)
		g.Granted, g.Evidence = res.Granted, res.Evidence
		c.refineWithDecision(&g, sf, v.allow)
		g.Usage = c.ruleUsage(r, sf.Base, sf.Project, usageCutoff(snaps, g.Granted.After))
		c.rep.Grants = append(c.rep.Grants, g)
	}

	// Rules that history saw in this file but the file does not hold now.
	seen := map[string]bool{}
	for _, s := range snaps {
		for r := range s.Rules {
			if !live[r] {
				seen[r] = true
			}
		}
	}
	gone := make([]string, 0, len(seen))
	for r := range seen {
		gone = append(gone, r)
	}
	sort.Strings(gone)
	for _, r := range gone {
		res := dateGrant(ruleObs(snaps, r), false)
		if res.Granted.Before.IsZero() {
			continue
		}
		g := c.newRule(v, r, 0)
		g.Granted, g.Evidence, g.LastSeen = res.Granted, res.Evidence, res.LastSeen
		g.Usage = c.ruleUsage(r, sf.Base, sf.Project, usageCutoff(snaps, g.Granted.After))
		g.Location, g.Flags, g.Revocable = model.Location{}, nil, false
		switch {
		case v.state == stateMissing || (v.state == stateOK && !v.invalid):
			g.Status, g.RevokeNote, g.Removed = model.StatusGone, "Already removed.", res.RemovedAt
		default:
			g.Status, g.RevokeNote = model.StatusUnknown, "File not readable."
		}
		c.rep.Grants = append(c.rep.Grants, g)
	}
}

// newRule builds the grant for one rule string in a settings file.
func (c *collector) newRule(v *fileView, rule string, line int) model.Grant {
	sf := v.sf
	g := model.Grant{
		Key:     model.KeyClaudeRule(sf.Path, rule),
		Agent:   model.ClaudeCode,
		Kind:    model.KindRule,
		Value:   rule,
		Tool:    match.ParseClaudeRule(rule).Tool,
		Scope:   sf.Scope,
		Project: sf.Project,
		Location: model.Location{
			File: sf.Path, Pointer: "permissions.allow", Line: line,
		},
		Status:     model.StatusActive,
		Revocable:  sf.Scope != model.ScopeManaged,
		RevokeNote: "Claude Code applies it on the next tool call.",
	}
	if sf.Scope == model.ScopeManaged {
		g.RevokeNote = "Set by your organization."
	}
	if v.committed {
		g.Flags = append(g.Flags, model.FlagCommitted)
		g.RevokeNote += " The change will show in git."
	}
	return g
}

// usageCutoff is the time before which uses do not count. A file's birth time is a
// weak bound, because editors and tools replace a settings file with a new one that
// keeps the old rules, so a window that starts at a birth time does not cut off uses.
func usageCutoff(snaps []snap, after time.Time) time.Time {
	for _, s := range snaps {
		if s.Birth && s.T.Equal(after) {
			return time.Time{}
		}
	}
	return after
}

// hasHistory reports whether any snapshot comes from history rather than from the file itself.
func hasHistory(snaps []snap) bool {
	for _, s := range snaps {
		if s.Source != srcLive && s.Source != srcBirth {
			return true
		}
	}
	return false
}

func isCommitted(sf *settingsFile) bool {
	root := gitRoot(sf.Project)
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(root, sf.Path)
	return err == nil && gitTracked(root, filepath.ToSlash(rel))
}

// snapshots gathers every observation of the file's allow list from all sources.
func (c *collector) snapshots(v *fileView) []snap {
	var out []snap
	seen := map[string]bool{}
	add := func(s snap) {
		k := fmt.Sprintf("%d|%s|%s", s.T.UnixNano(), s.Source, setKey(s.Rules))
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	path := v.sf.Path

	for _, p := range c.paths {
		f := c.facts[p]
		for _, r := range f.FileHistory {
			if r.File != path {
				continue
			}
			if r.Backup == "" {
				add(snap{T: r.T, Rules: map[string]bool{}, Source: srcHistory, Ref: path})
				continue
			}
			if rules, ok := readRules(r.Backup); ok {
				add(snap{T: r.T, Rules: rules, Source: srcHistory, Ref: r.Backup})
			}
		}
		for _, s := range f.Snapshots {
			if s.File == path {
				add(snap{T: s.T, Rules: toSet(s.Allow), Source: srcEdit, Ref: p})
			}
		}
	}
	for _, b := range siblingBackups(path) {
		if rules, ok := readRules(b.Path); ok {
			add(snap{T: b.T, Rules: rules, Source: srcBackup, Ref: b.Path})
		}
	}
	if v.sf.Scope == model.ScopeProject && v.committed {
		if root := gitRoot(v.sf.Project); root != "" {
			if rel, err := filepath.Rel(root, path); err == nil {
				for _, gv := range gitVersions(root, filepath.ToSlash(rel)) {
					rules := map[string]bool{}
					if allow, err := parseAllow(gv.Data); err == nil {
						rules = toSet(normRules(allow))
					} else if len(gv.Data) > 0 {
						continue
					}
					add(snap{T: gv.T, Rules: rules, Source: srcGit, Approx: true, Ref: path})
				}
			}
		}
	}
	if v.state == stateOK && !v.invalid && !v.mtime.IsZero() {
		add(snap{T: v.mtime, Rules: toSet(normRules(v.allow)), Source: srcLive, Ref: path})
		if bt, ok := fsx.Birthtime(path); ok {
			add(snap{T: bt.Add(-time.Millisecond), Rules: map[string]bool{}, Source: srcBirth, Ref: path, Birth: true})
		}
	}
	return out
}

// ruleObs turns the snapshots into observations of one rule. A birth time is dropped
// when the rule was seen earlier: the file was then replaced (copied, or rewritten by
// a tool), not created.
func ruleObs(snaps []snap, rule string) []timeline.Obs {
	var firstSeen time.Time
	for _, s := range snaps {
		if !s.Birth && s.Rules[rule] && (firstSeen.IsZero() || s.T.Before(firstSeen)) {
			firstSeen = s.T
		}
	}
	obs := make([]timeline.Obs, 0, len(snaps))
	for _, s := range snaps {
		if s.Birth && !firstSeen.IsZero() && firstSeen.Before(s.T) {
			continue
		}
		obs = append(obs, timeline.Obs{T: s.T, Present: s.Rules[rule], Approx: s.Approx, Source: s.Source, File: s.Ref})
	}
	return obs
}

// readRules reads a settings backup and returns its normalized rules.
func readRules(path string) (map[string]bool, bool) {
	b, st := readFile(path)
	if st != stateOK {
		return nil, false
	}
	allow, err := parseAllow(b)
	if err != nil {
		return nil, false
	}
	return toSet(normRules(allow)), true
}

func toSet(rules []string) map[string]bool {
	m := make(map[string]bool, len(rules))
	for _, r := range rules {
		m[r] = true
	}
	return m
}

func setKey(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, "\x00")
}

// refineWithDecision narrows the window with a "don't ask again" answer that matches the
// rule and falls inside the window. An answer dates only the most specific rule of the
// file that it matches: it made that rule, not a broader one that happens to cover it.
func (c *collector) refineWithDecision(g *model.Grant, sf *settingsFile, allow []string) {
	rule := match.ParseClaudeRule(g.Value)
	if !rule.HasSpec && specTools[rule.Tool] {
		return // a bare Bash or Read rule is never the product of one command's answer
	}
	keys, ok := match.ClaudeRuleKeys(rule, sf.Base)
	if !ok {
		return
	}
	want := keySet(keys)
	// Keys of the rules in this file that are narrower than this one.
	var narrower []map[match.Key]bool
	mine := specificity(g.Value, sf.Base)
	for _, other := range allow {
		if other == g.Value || specificity(other, sf.Base) <= mine {
			continue
		}
		if ks, ok := match.ClaudeRuleKeys(match.ParseClaudeRule(other), sf.Base); ok {
			narrower = append(narrower, keySet(ks))
		}
	}
	var best *Decision
	var bestPath string
	for _, p := range c.paths {
		f := c.facts[p]
		if len(f.Decisions) == 0 {
			continue
		}
		if sf.Project != "" && !fsx.Within(f.Cwd, sf.Project) {
			continue
		}
		for i := range f.Decisions {
			d := &f.Decisions[i]
			if (!g.Granted.After.IsZero() && d.T.Before(g.Granted.After)) || (!g.Granted.Before.IsZero() && d.T.After(g.Granted.Before)) {
				continue
			}
			if !anyKey(d.Keys, want) || (best != nil && !d.T.Before(best.T)) || answeredByNarrower(d.Keys, narrower) {
				continue
			}
			best, bestPath = d, p
		}
	}
	if best == nil {
		return
	}
	g.Granted.Before, g.Granted.Approx = best.T, false
	g.Granted.Source = `you chose "don't ask again"`
	g.Evidence = append(g.Evidence, model.Evidence{Time: best.T, What: "approved-always", Detail: best.Tool + ": " + best.Summary, Source: bestPath})
	sort.SliceStable(g.Evidence, func(i, j int) bool { return g.Evidence[i].Time.Before(g.Evidence[j].Time) })
}

// specTools are the tools whose rules take a spec in parentheses.
var specTools = map[string]bool{
	"Bash": true, "Read": true, "Edit": true, "Write": true, "MultiEdit": true, "NotebookEdit": true, "WebFetch": true,
}

func keySet(keys []match.Key) map[match.Key]bool {
	m := make(map[match.Key]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func answeredByNarrower(keys []match.Key, narrower []map[match.Key]bool) bool {
	for _, n := range narrower {
		if anyKey(keys, n) {
			return true
		}
	}
	return false
}

// exactRank ranks a rule with no wildcard above every wildcard rule.
const exactRank = 1 << 20

// specificity ranks how narrow a rule is, so that of two rules that match one call the
// narrower ranks higher: an exact rule, then a longer command prefix or folder, then a
// shorter one, then a rule with no spec.
func specificity(rule string, base match.RuleBase) int {
	r := match.ParseClaudeRule(rule)
	spec := strings.TrimSpace(r.Spec)
	if !r.HasSpec || spec == "" || spec == "*" {
		return 0
	}
	switch {
	case r.Tool == "Bash":
		if p, ok := strings.CutSuffix(spec, ":*"); ok {
			return len(match.Tokens(p))
		}
		if p, ok := strings.CutSuffix(spec, " *"); ok {
			return len(match.Tokens(p))
		}
		return exactRank
	case r.Tool == "WebFetch":
		return 1
	}
	if dir, ok := strings.CutSuffix(spec, "/**"); ok {
		return len(match.ResolvePath(dir, base))
	}
	return exactRank
}

func anyKey(keys []match.Key, want map[match.Key]bool) bool {
	for _, k := range keys {
		if want[k] {
			return true
		}
	}
	return false
}
