package codex

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/edit"
	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// planRevoke reads the file that holds g and applies RevokeDoc to it, the way the
// revoke package does, without writing anything.
func planRevoke(env model.Env, g model.Grant) ([]edit.Change, error) {
	if err := checkRevocable(g); err != nil {
		return nil, err
	}
	file := g.Location.File
	if file == "" && g.Kind == model.KindTrust {
		file = filepath.Join(env.CodexHome, "config.toml")
	}
	if file == "" {
		return nil, errors.New("codex: the grant has no file")
	}
	doc, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("codex: read rules file: %w", err)
	}
	out, summary, err := RevokeDoc(env, g, doc)
	if err != nil {
		return nil, err
	}
	return []edit.Change{{File: file, Before: doc, After: out, GrantID: g.ID, Summary: summary}}, nil
}

func hasGrant(rep model.Report, kind model.Kind, status model.Status, value string) bool {
	for _, g := range rep.Grants {
		if g.Kind == kind && g.Status == status && g.Value == value {
			return true
		}
	}
	return false
}

func TestRevokeRule(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	g := find(t, rep, model.KindRule, model.StatusActive, "make ship")
	before := mustRead(t, f.userRules)

	changes, err := planRevoke(f.env, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("changes = %d", len(changes))
	}
	c := changes[0]
	if c.File != f.userRules || c.GrantID != g.ID || !bytes.Equal(c.Before, before) || c.Summary == "" || strings.Contains(c.Summary, "\n") {
		t.Errorf("change = %+v", c)
	}
	want := strings.Replace(string(before), "prefix_rule(pattern=[\"make\", \"ship\"], decision=\"allow\")\n", "", 1)
	if string(c.After) != want {
		t.Errorf("after =\n%s\nwant\n%s", c.After, want)
	}
	if !bytes.Equal(mustRead(t, f.userRules), before) {
		t.Error("the planner wrote to the file")
	}

	// Apply, collect again, undo.
	if _, err := edit.Apply(f.env.StateDir, f.env.Now, changes); err != nil {
		t.Fatal(err)
	}
	if hasGrant(Collect(f.env, scan.Options{NoCache: true}), model.KindRule, model.StatusActive, "make ship") {
		t.Error("the rule is still listed after revoke")
	}
	if _, err := edit.Undo(f.env.StateDir, f.env.Now, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, f.userRules), before) {
		t.Error("undo did not restore the rules file")
	}
}

func TestRevokeRuleRemovesDuplicates(t *testing.T) {
	f := newFixture(t)
	g := find(t, Collect(f.env, scan.Options{}), model.KindRule, model.StatusActive, "npm test")
	changes, err := planRevoke(f.env, g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(changes[0].After), "npm") {
		t.Errorf("a duplicate statement was left: %s", changes[0].After)
	}
}

func TestRevokeProjectRule(t *testing.T) {
	f := newFixture(t)
	g := find(t, Collect(f.env, scan.Options{}), model.KindRule, model.StatusActive, "make deploy")
	changes, err := planRevoke(f.env, g)
	if err != nil {
		t.Fatal(err)
	}
	if changes[0].File != f.projRules || strings.Contains(string(changes[0].After), "deploy") || !strings.Contains(string(changes[0].After), "git") {
		t.Errorf("change = %+v", changes[0])
	}
}

func TestRevokeTrust(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})
	before := mustRead(t, f.configPath)

	// An existing folder is set to untrusted, not deleted.
	g := find(t, rep, model.KindTrust, model.StatusActive, f.app)
	changes, err := planRevoke(f.env, g)
	if err != nil {
		t.Fatal(err)
	}
	c := changes[0]
	if c.File != f.configPath || !bytes.Equal(c.Before, before) || !strings.Contains(c.Summary, "untrusted") {
		t.Errorf("change = %+v", c)
	}
	after := string(c.After)
	if !strings.Contains(after, "# folders") || !strings.Contains(after, f.app) || strings.Count(after, `"trusted"`) != 3 || strings.Count(after, `"untrusted"`) != 2 {
		t.Errorf("after =\n%s", after)
	}
	if _, err := edit.Apply(f.env.StateDir, f.env.Now, changes); err != nil {
		t.Fatal(err)
	}
	if hasGrant(Collect(f.env, scan.Options{NoCache: true}), model.KindTrust, model.StatusActive, f.app) {
		t.Error("the folder is still trusted after revoke")
	}

	// A missing folder loses its entry.
	g = find(t, rep, model.KindTrust, model.StatusActive, f.missing)
	changes, err = planRevoke(f.env, g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(changes[0].After), f.missing) || !strings.Contains(string(changes[0].After), f.vault) {
		t.Errorf("after =\n%s", changes[0].After)
	}
}

func TestRevokeRefusals(t *testing.T) {
	f := newFixture(t)
	rep := Collect(f.env, scan.Options{})

	managed := find(t, rep, model.KindRule, model.StatusActive, "ls")
	gone := find(t, rep, model.KindRule, model.StatusGone, "docker system prune")
	goneTrust := find(t, rep, model.KindTrust, model.StatusGone, f.removed)
	active := find(t, rep, model.KindRule, model.StatusActive, "make ship")

	otherAgent := active
	otherAgent.Agent = model.ClaudeCode
	missingRule := active
	missingRule.Pattern = [][]string{{"no"}, {"such"}, {"rule"}}
	noFile := active
	noFile.Location.File = ""
	badFile := active
	badFile.Location.File = f.userRules + ".missing"
	badKind := active
	badKind.Kind = "mode"

	tests := []struct {
		name string
		g    model.Grant
		want string
	}{
		{"managed", managed, "organization"},
		{"gone rule", gone, "gone"},
		{"gone trust", goneTrust, "gone"},
		{"other agent", otherAgent, "belongs to"},
		{"rule not in file", missingRule, "no longer in"},
		{"no file", noFile, "no file"},
		{"unreadable file", badFile, "read rules file"},
		{"unknown kind", badKind, "unknown grant kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes, err := planRevoke(f.env, tt.g)
			if err == nil || changes != nil {
				t.Fatalf("changes=%v err=%v", changes, err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}
