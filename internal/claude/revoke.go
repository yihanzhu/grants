package claude

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// PlanRevoke returns the file edit that revokes g, without writing anything. A rule is
// removed from its allow array, and a trusted folder is set to not trusted.
func PlanRevoke(env model.Env, g model.Grant) ([]edit.Change, error) {
	if g.Agent != model.ClaudeCode {
		return nil, fmt.Errorf("grant %s belongs to %s, not Claude Code", g.ID, g.Agent)
	}
	if g.Scope == model.ScopeManaged {
		return nil, errors.New("this grant is set by your organization; grants never edits managed settings")
	}
	if g.Status != model.StatusActive {
		return nil, fmt.Errorf("grant %s is %s, so there is nothing to revoke", g.ID, g.Status)
	}
	file := g.Location.File
	if file == "" {
		file = env.ClaudeJSON
	}
	before, err := readChecked(file)
	if err != nil {
		return nil, err
	}
	var after []byte
	var summary string
	switch {
	case g.Kind == model.KindTrust:
		after, err = edit.SetBool(before, []string{"projects", g.Value, "hasTrustDialogAccepted"}, false)
		summary = fmt.Sprintf("set hasTrustDialogAccepted to false for %s", g.Value)
	case g.Scope == model.ScopeLegacy:
		var n int
		after, n, err = edit.RemoveArrayString(before, []string{"projects", g.Project, "allowedTools"}, g.Value)
		if err == nil && n == 0 {
			err = fmt.Errorf("%q is no longer in allowedTools for %s", risk.Redact(g.Value), g.Project)
		}
		summary = fmt.Sprintf("remove %q from allowedTools for %s", risk.Redact(g.Value), g.Project)
	case g.Kind == model.KindRule:
		var n int
		after, n, err = edit.RemoveArrayString(before, []string{"permissions", "allow"}, g.Value)
		if err == nil && n == 0 {
			err = fmt.Errorf("%q is no longer in permissions.allow of %s", risk.Redact(g.Value), filepath.Base(file))
		}
		summary = fmt.Sprintf("remove %q from permissions.allow", risk.Redact(g.Value))
	default:
		err = fmt.Errorf("unsupported grant kind %q", g.Kind)
	}
	if err != nil {
		return nil, fmt.Errorf("plan revoke of %s in %s: %w", g.ID, file, err)
	}
	return []edit.Change{{File: file, Before: before, After: after, GrantID: g.ID, Summary: summary}}, nil
}

func readChecked(path string) ([]byte, error) {
	b, st := readFile(path)
	switch st {
	case stateOK:
		return b, nil
	case stateMissing:
		return nil, fmt.Errorf("%s does not exist any more", path)
	}
	return nil, fmt.Errorf("cannot read %s", path)
}
