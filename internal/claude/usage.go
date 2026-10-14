package claude

import (
	"time"

	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
)

// ruleUsage counts how often history matched a rule: transcripts whose working folder
// is inside project (all of them when project is empty) and that ended after the grant
// was made. Known is false for rules whose wildcards cannot be turned into keys.
func (c *collector) ruleUsage(rule string, base match.RuleBase, project string, after time.Time) model.Usage {
	u := model.Usage{Since: c.oldest}
	keys, ok := match.ClaudeRuleKeys(match.ParseClaudeRule(rule), base)
	if !ok {
		return u
	}
	u.Known = true
	var last int64
	for _, p := range c.paths {
		f := c.facts[p]
		if !c.countable(f, project, after) {
			continue
		}
		// One tool call can match several keys of a rule, so take the largest count.
		var n int32
		for _, k := range keys {
			use := f.Usage[k]
			n = max(n, use.Count)
			last = max(last, use.Last)
		}
		u.Count += int(n)
	}
	if last > 0 {
		u.Last = time.Unix(last, 0)
	}
	return u
}

// trustUsage counts the sessions that ran in a trusted folder and finds the latest one.
func (c *collector) trustUsage(dir string, after time.Time) model.Usage {
	u := model.Usage{Known: true, Since: c.oldest}
	sessions := map[string]bool{}
	for _, p := range c.paths {
		f := c.facts[p]
		if !c.countable(f, dir, after) {
			continue
		}
		id := f.SessionID
		if id == "" {
			id = p
		}
		sessions[id] = true
		if f.End.After(u.Last) {
			u.Last = f.End
		}
	}
	u.Count = len(sessions)
	return u
}

func (c *collector) countable(f *TranscriptFacts, project string, after time.Time) bool {
	if project != "" && !inside(f.Cwd, project) {
		return false
	}
	return after.IsZero() || !f.End.Before(after)
}
