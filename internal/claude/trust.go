package claude

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/timeline"
)

const (
	srcJSONBackup  = "~/.claude.json backup"
	srcFirstSeen   = "first Claude Code session in this folder"
	trustRevokeMsg = "Applies to new sessions. Running sessions may rewrite ~/.claude.json; close them first if you can."
)

// trustPointer and allowedPointer are the display forms of a location in ~/.claude.json.
func trustPointer(project string) string {
	return fmt.Sprintf("projects[%q].hasTrustDialogAccepted", project)
}

func allowedPointer(project string) string {
	return fmt.Sprintf("projects[%q].allowedTools", project)
}

// trustGrants lists the folders Claude Code trusts now, plus folders a backup of
// ~/.claude.json shows as trusted that are not trusted any more.
func (c *collector) trustGrants() {
	backups := c.jsonBackups()
	sessions := c.allSessions()

	dirs := map[string]bool{}
	for p, info := range c.cj.Projects {
		if info.Trusted {
			dirs[p] = true
		}
	}
	for _, b := range backups {
		for p, info := range b.Info.Projects {
			if info.Trusted {
				dirs[p] = true
			}
		}
	}
	list := make([]string, 0, len(dirs))
	for p := range dirs {
		list = append(list, p)
	}
	sort.Strings(list)

	for _, p := range list {
		active := c.cj.Projects[p].Trusted
		var obs []timeline.Obs
		if t, ok := earliestSession(sessions, p, dirs); ok {
			obs = append(obs, timeline.Obs{T: t, Present: true, Approx: true, Source: srcFirstSeen})
		}
		for _, b := range backups {
			obs = append(obs, timeline.Obs{T: b.T, Present: b.Info.Projects[p].Trusted, Source: srcJSONBackup})
		}
		res := dateGrant(obs, active)
		g := model.Grant{
			Key:      model.KeyClaudeTrust(p),
			Agent:    model.ClaudeCode,
			Kind:     model.KindTrust,
			Value:    p,
			Scope:    model.ScopeUser,
			Project:  p,
			Status:   model.StatusActive,
			Granted:  res.Granted,
			Evidence: res.Evidence,
		}
		if active {
			g.Location = model.Location{File: c.env.ClaudeJSON, Pointer: trustPointer(p), Line: c.trustLine(p)}
			g.Revocable, g.RevokeNote = true, trustRevokeMsg
		} else {
			c.markAbsent(&g, res)
		}
		g.Usage = c.trustUsage(p, g.Granted.After)
		c.rep.Grants = append(c.rep.Grants, g)
	}
}

// markAbsent sets a grant that ~/.claude.json does not hold now. When grants could not
// read that file, it says nothing about removal, so the grant is unknown and has no
// removal window.
func (c *collector) markAbsent(g *model.Grant, res timeline.Result) {
	g.Revocable = false
	g.LastSeen = res.LastSeen
	if c.cjState == stateBlocked {
		g.Status, g.RevokeNote = model.StatusUnknown, "File not readable."
		return
	}
	g.Status, g.RevokeNote = model.StatusGone, "Already removed."
	g.Removed = res.RemovedAt
}

func (c *collector) trustLine(project string) int {
	if c.cjState != stateOK {
		return 0
	}
	return valueLine(c.cjDoc, []string{"projects", project, "hasTrustDialogAccepted"})
}

// allSessions merges the first time each history source saw a folder in use.
func (c *collector) allSessions() []session {
	var out []session
	for _, p := range c.paths {
		f := c.facts[p]
		if f.Cwd != "" && !f.Start.IsZero() {
			out = append(out, session{T: f.Start, Dir: filepath.Clean(f.Cwd)})
		}
	}
	out = append(out, c.desktop...)
	return append(out, c.prompts...)
}

// legacyGrants lists the allowedTools that older Claude Code versions keep per project
// in ~/.claude.json, and the ones a backup shows that are gone now.
func (c *collector) legacyGrants() {
	backups := c.jsonBackups()
	type ref struct{ project, rule string }
	seen := map[ref]bool{}
	var refs []ref
	add := func(info map[string]projectInfo) {
		for p, pi := range info {
			for _, r := range pi.AllowedTools {
				if k := (ref{p, r}); !seen[k] {
					seen[k] = true
					refs = append(refs, k)
				}
			}
		}
	}
	add(c.cj.Projects)
	for _, b := range backups {
		add(b.Info.Projects)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].project != refs[j].project {
			return refs[i].project < refs[j].project
		}
		return refs[i].rule < refs[j].rule
	})
	for _, r := range refs {
		active := contains(c.cj.Projects[r.project].AllowedTools, r.rule)
		var obs []timeline.Obs
		for _, b := range backups {
			obs = append(obs, timeline.Obs{T: b.T, Present: contains(b.Info.Projects[r.project].AllowedTools, r.rule), Source: srcJSONBackup})
		}
		res := dateGrant(obs, active)
		base := match.RuleBase{Home: c.env.Home, Settings: r.project, Project: r.project}
		g := model.Grant{
			Key:      model.KeyClaudeRule(c.env.ClaudeJSON+"#"+r.project, r.rule),
			Agent:    model.ClaudeCode,
			Kind:     model.KindRule,
			Value:    r.rule,
			Tool:     match.ParseClaudeRule(r.rule).Tool,
			Scope:    model.ScopeLegacy,
			Project:  r.project,
			Status:   model.StatusActive,
			Granted:  res.Granted,
			Evidence: res.Evidence,
		}
		g.Usage = c.ruleUsage(r.rule, base, r.project, g.Granted.After)
		if active {
			g.Location = model.Location{File: c.env.ClaudeJSON, Pointer: allowedPointer(r.project)}
			if c.cjState == stateOK {
				g.Location.Line = arrayLines(c.cjDoc, []string{"projects", r.project, "allowedTools"})[r.rule]
			}
			g.Revocable, g.RevokeNote = true, "Claude Code applies it on the next tool call."
		} else {
			c.markAbsent(&g, res)
		}
		c.rep.Grants = append(c.rep.Grants, g)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// jsonBackups reads the ~/.claude.json backups once.
func (c *collector) jsonBackups() []jsonBackup {
	if !c.backupsRead {
		c.backups, c.backupsRead = claudeJSONBackups(c.env.ClaudeDir), true
	}
	return c.backups
}
