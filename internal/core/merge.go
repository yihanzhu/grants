package core

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
	"github.com/yihanzhu/grants/internal/store"
	"github.com/yihanzhu/grants/internal/timeline"
)

// firstSeen labels dates that come from grants' own history.
const firstSeen = "first seen by grants"

// merge turns the adapter reports into the final grant list. It records the active
// grants in obs, which the caller saves.
func merge(env model.Env, reports []model.Report, obs *store.Observations) []model.Grant {
	var grants []model.Grant
	for _, r := range reports {
		grants = append(grants, r.Grants...)
	}

	for i := range grants {
		g := &grants[i]
		// The key holds the rule text. It goes into grants' own history, so it must not
		// hold a credential.
		g.Key = risk.Redact(g.Key)
		risk.Assess(g, env, fsx.Exists)
		if g.Status != model.StatusActive {
			g.Flags = without(g.Flags, model.FlagDeadPath) // a removed grant points at nothing that matters
		}
		// Judge "unused" from the adapter's dates: a grant with no known date counts as
		// old, and the first-seen date added below must not make it look new.
		if unused(env, g) {
			g.Flags = append(g.Flags, model.FlagUnused)
		}
	}
	// Broad trusted folders need the whole list, so they come after the loop.
	markBroadTrust(grants, fsx.Exists, listSubdirs)

	var active []model.Grant
	reported := map[string]bool{}
	for _, g := range grants {
		reported[g.Key] = true
		if g.Status == model.StatusActive {
			active = append(active, g)
		}
	}
	for i := range active {
		active[i].Value = risk.Redact(active[i].Value) // grants' own history never holds a credential
	}
	obs.Record(env.Now, active)

	for i := range grants {
		g := &grants[i]
		switch g.Status {
		case model.StatusActive:
			if g.Granted.Before.IsZero() {
				g.Granted = firstSeenWindow(obs, g.Key)
			}
		case model.StatusGone:
			enrichGone(obs, g)
		}
	}
	found := map[model.Agent]bool{}
	unread := map[model.Agent][]string{}
	for _, r := range reports {
		found[r.Agent] = r.Found
		unread[r.Agent] = append(unread[r.Agent], r.Unread...)
	}
	grants = append(grants, goneFromStore(env, obs, reported, found, unread)...)

	assignIDs(grants, hexOf)
	sortGrants(grants)
	return grants
}

func without(flags []model.Flag, f model.Flag) []model.Flag {
	var out []model.Flag
	for _, x := range flags {
		if x != f {
			out = append(out, x)
		}
	}
	return out
}

// unused reports whether an active grant should get FlagUnused: its use is measured,
// history covers the whole window, nothing matched in the window, and the grant is
// older than the window (or has no known date).
func unused(env model.Env, g *model.Grant) bool {
	if g.Status != model.StatusActive || !g.Usage.Known || g.HasFlag(model.FlagUnused) {
		return false
	}
	cutoff := env.Now.Add(-env.UnusedAfter)
	if g.Usage.Since.IsZero() || g.Usage.Since.After(cutoff) {
		return false // history is too short to say
	}
	if g.Usage.Last.After(cutoff) {
		return false
	}
	return g.Granted.Before.IsZero() || !g.Granted.Before.After(cutoff)
}

// firstSeenWindow dates a grant from grants' own history: it was absent at the last
// run before the first sighting, and present at the first.
func firstSeenWindow(obs *store.Observations, key string) model.Window {
	s := obs.Grants[key]
	if s == nil {
		return model.Window{}
	}
	w := model.Window{Before: s.First, Source: firstSeen}
	for _, r := range obs.Runs {
		if r.Before(s.First) && r.After(w.After) {
			w.After = r
		}
	}
	return w
}

// enrichGone adds what grants saw to a grant the adapter reports as gone.
func enrichGone(obs *store.Observations, g *model.Grant) {
	o := obs.Obs(g.Key)
	if o == nil {
		return
	}
	res := timeline.Date(o)
	if res.LastSeen.After(g.LastSeen) {
		g.LastSeen = res.LastSeen
	}
	if g.Removed.Before.IsZero() {
		g.Removed = res.RemovedAt
	}
	if g.Granted.Before.IsZero() {
		g.Granted = res.Granted
	}
}

// goneFromStore builds gone grants for grants that an earlier run saw and no adapter
// reports now. An agent that is not found is skipped: its folder may just be missing
// from this machine for the moment, which says nothing about its grants. A key under
// an unread prefix is skipped too: the adapter could not read its source this run.
func goneFromStore(env model.Env, obs *store.Observations, reported map[string]bool, found map[model.Agent]bool, unread map[model.Agent][]string) []model.Grant {
	keys := make([]string, 0, len(obs.Grants))
	for k := range obs.Grants {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []model.Grant
	for _, key := range keys {
		s := obs.Grants[key]
		if reported[key] || !found[s.Agent] || s.Last.IsZero() || hasPrefix(key, unread[s.Agent]) {
			continue
		}
		g := model.Grant{
			Key: key, Agent: s.Agent, Kind: s.Kind, Value: s.Value, Project: s.Project,
			Scope: model.ScopeUser, Status: model.StatusGone, LastSeen: s.Last,
			RevokeNote: "Already removed.",
		}
		if s.Project != "" && s.Kind == model.KindRule {
			g.Scope = model.ScopeProject
		}
		switch {
		case s.Agent == model.Codex && s.Kind == model.KindRule:
			g.Tool = "exec"
		case s.Agent == model.ClaudeCode && s.Kind == model.KindRule:
			g.Tool = match.ParseClaudeRule(s.Value).Tool
		}
		res := timeline.Date(obs.Obs(key))
		g.Granted, g.Removed, g.Evidence = res.Granted, res.RemovedAt, res.Evidence
		risk.Assess(&g, env, fsx.Exists)
		g.Flags = without(g.Flags, model.FlagDeadPath)
		out = append(out, g)
	}
	return out
}

func hasPrefix(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// idLen is the shortest id; it matches model.MakeID.
const idLen = 7

// hexOf is the full hash that ids are cut from. model.MakeID uses its first 7 digits.
func hexOf(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// assignIDs gives every grant a short id from the hash of its key. When two grants
// get the same id, both get one more digit until all are different.
func assignIDs(grants []model.Grant, hash func(string) string) {
	n := idLen
	length := make([]int, len(grants))
	hashes := make([]string, len(grants))
	for i := range grants {
		length[i] = n
		hashes[i] = hash(grants[i].Key)
	}
	// Redaction can give two rules the same key (they differ only in a credential).
	// Their raw values still differ, so hash those too to keep the ids apart.
	count := map[string]int{}
	for _, h := range hashes {
		count[h]++
	}
	for i := range grants {
		if count[hashes[i]] > 1 {
			hashes[i] = hash(grants[i].Key + "\x00" + grants[i].Value)
		}
	}
	cut := func(i int) string {
		if length[i] > len(hashes[i]) {
			return hashes[i]
		}
		return hashes[i][:length[i]]
	}
	for {
		byID := map[string][]int{}
		for i := range grants {
			byID[cut(i)] = append(byID[cut(i)], i)
		}
		clash := false
		for _, idx := range byID {
			if len(idx) < 2 {
				continue
			}
			progress := false
			for _, i := range idx {
				if length[i] < len(hashes[i]) {
					length[i]++
					progress = true
				}
			}
			clash = clash || progress
		}
		if !clash {
			break
		}
	}
	for i := range grants {
		grants[i].ID = cut(i)
	}
}

// sortGrants puts active grants first, then riskier ones, then orders by agent, kind
// and value.
func sortGrants(grants []model.Grant) {
	rank := map[model.Status]int{model.StatusActive: 0, model.StatusUnknown: 1, model.StatusGone: 2}
	sort.SliceStable(grants, func(i, j int) bool {
		a, b := grants[i], grants[j]
		if ra, rb := rank[a.Status], rank[b.Status]; ra != rb {
			return ra < rb
		}
		if ra, rb := a.Risk.Level.Rank(), b.Risk.Level.Rank(); ra != rb {
			return ra > rb
		}
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		return a.Key < b.Key
	})
}
