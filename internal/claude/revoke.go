package claude

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// RevokeDoc applies the revoke of g to doc, the content of the file that holds it,
// and returns the new content with a one-line summary. It lets a caller chain several
// grants of one file on the same document.
func RevokeDoc(env model.Env, g model.Grant, doc []byte) (after []byte, summary string, err error) {
	if err := checkRevocable(g); err != nil {
		return nil, "", err
	}
	switch {
	case g.Kind == model.KindTrust:
		after, err = edit.SetBool(doc, []string{"projects", g.Value, "hasTrustDialogAccepted"}, false)
		summary = fmt.Sprintf("set hasTrustDialogAccepted to false for %s", g.Value)
	case g.Scope == model.ScopeLegacy:
		var n int
		after, n, err = edit.RemoveArrayString(doc, []string{"projects", g.Project, "allowedTools"}, g.Value)
		if err == nil && n == 0 {
			err = fmt.Errorf("%q is no longer in allowedTools for %s", risk.Redact(g.Value), g.Project)
		}
		summary = fmt.Sprintf("remove %q from allowedTools for %s", risk.Redact(g.Value), g.Project)
	case g.Kind == model.KindRule:
		var n int
		after, n, err = edit.RemoveArrayString(doc, []string{"permissions", "allow"}, g.Value)
		if err == nil && n == 0 {
			err = fmt.Errorf("%q is no longer in permissions.allow of %s", risk.Redact(g.Value), filepath.Base(revokeFile(env, g)))
		}
		summary = fmt.Sprintf("remove %q from permissions.allow", risk.Redact(g.Value))
	default:
		err = fmt.Errorf("unsupported grant kind %q", g.Kind)
	}
	if err != nil {
		return nil, "", err
	}
	return after, summary, nil
}

// revokeFile is the file that holds g.
func revokeFile(env model.Env, g model.Grant) string {
	if g.Location.File != "" {
		return g.Location.File
	}
	return env.ClaudeJSON
}

func checkRevocable(g model.Grant) error {
	if g.Agent != model.ClaudeCode {
		return fmt.Errorf("grant %s belongs to %s, not Claude Code", g.ID, g.Agent)
	}
	if g.Scope == model.ScopeManaged {
		return errors.New("this grant is set by your organization; grants never edits managed settings")
	}
	if g.Status != model.StatusActive {
		return fmt.Errorf("grant %s is %s, so there is nothing to revoke", g.ID, g.Status)
	}
	return nil
}
