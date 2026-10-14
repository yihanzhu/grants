package core

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/yihanzhu/grants/internal/model"
	"github.com/yihanzhu/grants/internal/risk"
)

// maxRepoScan caps how many entries of one trusted folder are checked for git
// repositories, so a folder with a huge flat listing stays quick.
const maxRepoScan = 5000

// markBroadTrust raises the risk of trusted folders that hold several known projects.
// A project is another trusted folder of either agent inside the folder, or a git
// repository directly inside it. A trusted folder under a hidden folder (an agent
// worktree) counts as the folder that holds it; hidden git folders do not count. Only the whole grant list shows the first kind, so
// this runs after every grant is assessed. exists and subdirs are the file system.
func markBroadTrust(grants []model.Grant, exists func(string) bool, subdirs func(dir string) []string) {
	var trusted []string
	for _, g := range grants {
		if g.Kind == model.KindTrust && g.Status == model.StatusActive && g.Value != "" && exists(g.Value) {
			trusted = append(trusted, filepath.Clean(g.Value))
		}
	}
	for i := range grants {
		g := &grants[i]
		if g.Kind != model.KindTrust || g.Status != model.StatusActive || g.Value == "" || !exists(g.Value) {
			continue
		}
		dir := filepath.Clean(g.Value)
		projects := map[string]bool{}
		for _, t := range trusted {
			if t != dir && (dir == "/" || strings.HasPrefix(t, dir+"/")) {
				if p := visibleOwner(dir, t); p != dir {
					projects[p] = true
				}
			}
		}
		for _, sub := range subdirs(dir) {
			if !strings.HasPrefix(filepath.Base(sub), ".") && exists(filepath.Join(sub, ".git")) {
				projects[sub] = true
			}
		}
		risk.AssessBroadTrust(g, len(projects))
	}
}

// visibleOwner returns the folder that p counts as when judging dir: p itself, or
// the folder that holds the first hidden folder on the way down from dir. An agent
// worktree such as dir/app/.claude/worktrees/x counts as dir/app.
func visibleOwner(dir, p string) string {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return p
	}
	owner := dir
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(seg, ".") {
			break
		}
		owner = filepath.Join(owner, seg)
	}
	return owner
}

// listSubdirs lists the folders directly inside dir. A folder that cannot be read
// has none; symbolic links are not followed.
func listSubdirs(dir string) []string {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	entries, _ := f.ReadDir(maxRepoScan)
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
