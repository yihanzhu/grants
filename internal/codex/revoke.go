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
	if err := checkRevocable(g); err != nil {
		return nil, err
	}
	file := revokeFile(env, g)
	if file == "" {
		return nil, errors.New("codex: the grant has no file")
	}
	doc, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("codex: read %s file: %w", map[model.Kind]string{model.KindRule: "rules", model.KindTrust: "config"}[g.Kind], err)
	}
	out, summary, err := RevokeDoc(env, g, doc)
	if err != nil {
		return nil, err
	}
	return []edit.Change{{File: file, Before: doc, After: out, GrantID: g.ID, Summary: summary}}, nil
}

// RevokeDoc applies the revoke of g to doc, the content of the file that holds it,
// and returns the new content with a one-line summary. It lets a caller chain several
// grants of one file on the same document.
func RevokeDoc(env model.Env, g model.Grant, doc []byte) (after []byte, summary string, err error) {
	if err := checkRevocable(g); err != nil {
		return nil, "", err
	}
	switch g.Kind {
	case model.KindRule:
		return revokeRule(g, doc)
	case model.KindTrust:
		return revokeTrust(g, doc)
	}
	return nil, "", fmt.Errorf("codex: unknown grant kind %q", g.Kind)
}

func checkRevocable(g model.Grant) error {
	if g.Agent != model.Codex {
		return fmt.Errorf("codex: grant %s belongs to %s", g.ID, g.Agent)
	}
	if g.Status != model.StatusActive {
		return fmt.Errorf("codex: grant %s is %s: %s", g.ID, g.Status, g.RevokeNote)
	}
	if g.Scope == model.ScopeManaged || !g.Revocable {
		note := g.RevokeNote
		if note == "" {
			note = "not revocable"
		}
		return fmt.Errorf("codex: grant %s cannot be revoked: %s", g.ID, note)
	}
	return nil
}

func revokeFile(env model.Env, g model.Grant) string {
	if g.Location.File != "" {
		return g.Location.File
	}
	if g.Kind == model.KindTrust {
		return filepath.Join(env.CodexHome, "config.toml")
	}
	return ""
}

func revokeRule(g model.Grant, src []byte) ([]byte, string, error) {
	out, n, err := RemoveRule(src, g.Pattern, "allow")
	if err != nil {
		return nil, "", fmt.Errorf("codex: edit rules file: %w", err)
	}
	if n == 0 {
		return nil, "", fmt.Errorf("codex: rule %q is no longer in its rules file", PatternDisplay(g.Pattern))
	}
	return out, fmt.Sprintf("remove prefix_rule %s", shorten(risk.Redact(PatternDisplay(g.Pattern)), 80)), nil
}

func revokeTrust(g model.Grant, doc []byte) ([]byte, string, error) {
	path := g.Value
	if path == "" {
		return nil, "", errors.New("codex: the trusted folder has no path")
	}
	table := []string{"projects", path}
	if fsx.Exists(path) {
		out, err := edit.TOMLSetString(doc, table, "trust_level", "untrusted")
		if err != nil {
			return nil, "", fmt.Errorf("codex: edit config.toml: %w", err)
		}
		return out, fmt.Sprintf("set trust_level to untrusted for %s", path), nil
	}
	out, err := edit.TOMLDeleteTable(doc, table)
	if err != nil {
		return nil, "", fmt.Errorf("codex: edit config.toml: %w", err)
	}
	return out, fmt.Sprintf("remove trusted folder %s (folder no longer exists)", path), nil
}
