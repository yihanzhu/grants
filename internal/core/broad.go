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
// repository directly inside it. Only the whole grant list shows the first kind, so
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
				projects[t] = true
			}
		}
		for _, sub := range subdirs(dir) {
			if exists(filepath.Join(sub, ".git")) {
				projects[sub] = true
			}
		}
		risk.AssessBroadTrust(g, len(projects))
	}
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
