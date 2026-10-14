package codex

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/fsx"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// PlanRevoke returns the file edits that revoke g, without writing anything.
//
// A rule loses its prefix_rule statement. A trusted folder that still exists is set to
// "untrusted" instead of deleted, because the Codex desktop app trusts a folder again
// on its next thread when no decision is on file. A folder that no longer exists loses
// its entry.
func PlanRevoke(env model.Env, g model.Grant) ([]edit.Change, error) {
	if g.Agent != model.Codex {
		return nil, fmt.Errorf("codex: grant %s belongs to %s", g.ID, g.Agent)
	}
	if g.Status != model.StatusActive {
		return nil, fmt.Errorf("codex: grant %s is %s: %s", g.ID, g.Status, g.RevokeNote)
	}
	if g.Scope == model.ScopeManaged || !g.Revocable {
		note := g.RevokeNote
		if note == "" {
			note = "not revocable"
		}
		return nil, fmt.Errorf("codex: grant %s cannot be revoked: %s", g.ID, note)
	}
	switch g.Kind {
	case model.KindRule:
		return planRule(g)
	case model.KindTrust:
		return planTrust(env, g)
	}
	return nil, fmt.Errorf("codex: unknown grant kind %q", g.Kind)
}

func planRule(g model.Grant) ([]edit.Change, error) {
	file := g.Location.File
	if file == "" {
		return nil, errors.New("codex: the rule has no file")
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("codex: read rules file: %w", err)
	}
	out, n, err := RemoveRule(src, g.Pattern, "allow")
	if err != nil {
		return nil, fmt.Errorf("codex: edit %s: %w", filepath.Base(file), err)
	}
	if n == 0 {
		return nil, fmt.Errorf("codex: rule %q is no longer in %s", PatternDisplay(g.Pattern), filepath.Base(file))
	}
	return []edit.Change{{
		File: file, Before: src, After: out, GrantID: g.ID,
		Summary: fmt.Sprintf("remove prefix_rule %s from %s", shorten(risk.Redact(PatternDisplay(g.Pattern)), 80), filepath.Base(file)),
	}}, nil
}

func planTrust(env model.Env, g model.Grant) ([]edit.Change, error) {
	file := g.Location.File
	if file == "" {
		file = filepath.Join(env.CodexHome, "config.toml")
	}
	path := g.Value
	if path == "" {
		return nil, errors.New("codex: the trusted folder has no path")
	}
	doc, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("codex: read config: %w", err)
	}
	table := []string{"projects", path}
	var out []byte
	var summary string
	if fsx.Exists(path) {
		out, err = edit.TOMLSetString(doc, table, "trust_level", "untrusted")
		summary = fmt.Sprintf("set trust_level to untrusted for %s", path)
	} else {
		out, err = edit.TOMLDeleteTable(doc, table)
		summary = fmt.Sprintf("remove trusted folder %s (folder no longer exists)", path)
	}
	if err != nil {
		return nil, fmt.Errorf("codex: edit config.toml: %w", err)
	}
	return []edit.Change{{File: file, Before: doc, After: out, GrantID: g.ID, Summary: summary}}, nil
}
