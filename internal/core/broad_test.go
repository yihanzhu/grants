package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/scan"
)

func trustGrant(agent model.Agent, dir string) model.Grant {
	g := model.Grant{Agent: agent, Kind: model.KindTrust, Value: dir, Status: model.StatusActive, Scope: model.ScopeUser, Risk: model.Risk{Level: model.RiskLow, Reasons: []string{"limited to one folder"}}}
	return g
}

// fakeFS answers exists and subdirs from a list of folders and git repositories.
func fakeFS(dirs []string, repos ...string) (func(string) bool, func(string) []string) {
	have := map[string]bool{}
	for _, d := range dirs {
		have[d] = true
	}
	for _, r := range repos {
		have[r], have[r+"/.git"] = true, true
	}
	exists := func(p string) bool { return have[p] }
	subdirs := func(dir string) []string {
		var out []string
		for p := range have {
			if filepath.Dir(p) == dir && !strings.HasSuffix(p, "/.git") {
				out = append(out, p)
			}
		}
		return out
	}
	return exists, subdirs
}

func TestBroadTrustCountsTrustedAndGitFolders(t *testing.T) {
	// /w holds two other trusted folders (one by Claude Code, one by Codex), one of them
	// two levels down, and one git repository. The same folder trusted twice counts once.
	dirs := []string{"/w", "/w/a", "/w/x/b", "/w/plain"}
	exists, subdirs := fakeFS(dirs, "/w/repo")
	grants := []model.Grant{
		trustGrant(model.Codex, "/w"),
		trustGrant(model.ClaudeCode, "/w"),
		trustGrant(model.ClaudeCode, "/w/a"),
		trustGrant(model.Codex, "/w/a"),
		trustGrant(model.Codex, "/w/x/b"),
	}
	markBroadTrust(grants, exists, subdirs)
	if g := grants[0]; g.Risk.Level != model.RiskHigh || g.Risk.Reasons[0] != "every project inside inherits trust (3 projects)" {
		t.Errorf("codex /w: %+v", g.Risk)
	}
	if g := grants[1]; g.Risk.Level != model.RiskMedium || g.Risk.Reasons[0] != "folders inside it share this trust (3 projects)" {
		t.Errorf("claude /w: %+v", g.Risk)
	}
	for _, g := range grants[2:] {
		if g.Risk.Level != model.RiskLow {
			t.Errorf("%s %s should stay low: %+v", g.Agent, g.Value, g.Risk)
		}
	}
}

func TestBroadTrustNeedsThreeProjects(t *testing.T) {
	exists, subdirs := fakeFS([]string{"/w", "/w/a"}, "/w/repo")
	grants := []model.Grant{trustGrant(model.Codex, "/w"), trustGrant(model.Codex, "/w/a")}
	markBroadTrust(grants, exists, subdirs)
	if grants[0].Risk.Level != model.RiskLow {
		t.Errorf("two projects made it broad: %+v", grants[0].Risk)
	}
}

func TestBroadTrustIgnoresMissingGoneAndRules(t *testing.T) {
	// /w/gone is trusted but deleted; /w/old is a gone grant; neither is a known project.
	exists, subdirs := fakeFS([]string{"/w", "/w/a"}, "/w/repo")
	gone := trustGrant(model.Codex, "/w/old")
	gone.Status = model.StatusGone
	rule := model.Grant{Agent: model.Codex, Kind: model.KindRule, Value: "/w/rule", Status: model.StatusActive, Risk: model.Risk{Level: model.RiskLow}}
	grants := []model.Grant{trustGrant(model.Codex, "/w"), trustGrant(model.Codex, "/w/a"), trustGrant(model.Codex, "/w/gone"), gone, rule}
	markBroadTrust(grants, exists, subdirs)
	if grants[0].Risk.Level != model.RiskLow {
		t.Errorf("missing and gone folders counted: %+v", grants[0].Risk)
	}
	// A deleted trusted folder is not rated at all.
	if grants[2].Risk.Level != model.RiskLow || grants[4].Risk.Level != model.RiskLow {
		t.Errorf("risk changed: %+v %+v", grants[2].Risk, grants[4].Risk)
	}
}

func TestBroadTrustOnDisk(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"p1/.git", "p2/.git", "p3/.git", "notes"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A worktree has a .git file; a plain file is not a project folder.
	if err := os.WriteFile(filepath.Join(root, "notes", ".git"), []byte("gitdir: x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env := codexHome(t, nil, []string{root})
	res, err := Run(env, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := byValue(t, res.Grants, root)
	if g.Risk.Level != model.RiskHigh || !strings.Contains(strings.Join(g.Risk.Reasons, ";"), "(4 projects)") {
		t.Errorf("risk = %+v, want high with 4 projects", g.Risk)
	}
	if got := listSubdirs(filepath.Join(root, "missing")); got != nil {
		t.Errorf("missing folder listed %v", got)
	}
}

func TestBroadTrustIgnoresAgentWorktrees(t *testing.T) {
	// A repository with several agent worktrees under .claude/worktrees is one project.
	dirs := []string{"/w/app", "/w/app/.claude/worktrees/a", "/w/app/.claude/worktrees/b", "/w/app/.claude/worktrees/c"}
	exists, subdirs := fakeFS(dirs, "/w/app/.hidden-repo")
	grants := []model.Grant{trustGrant(model.Codex, "/w/app")}
	for _, d := range dirs[1:] {
		grants = append(grants, trustGrant(model.ClaudeCode, d))
	}
	markBroadTrust(grants, exists, subdirs)
	if grants[0].Risk.Level != model.RiskLow {
		t.Errorf("worktrees made the repository broad: %+v", grants[0].Risk)
	}
}
