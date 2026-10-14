package claude

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/model"
)

// managedRoots are the folders that hold organization settings. Tests replace it.
var managedRoots = defaultManagedRoots()

// OverrideManaged replaces the folders that hold organization settings and returns a
// function that puts the defaults back. It lets tests run on a machine that has
// real managed settings.
func OverrideManaged(dirs ...string) (restore func()) {
	old := managedRoots
	managedRoots = dirs
	return func() { managedRoots = old }
}

func defaultManagedRoots() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"/Library/Application Support/ClaudeCode"}
	case "linux":
		return []string{"/etc/claude-code"}
	}
	return nil
}

// settingsFile is one file that may hold permissions.allow.
type settingsFile struct {
	Path    string
	Scope   model.Scope
	Project string // folder the file limits its rules to; empty for user and managed files
	Base    match.RuleBase
}

func (c *collector) add(sf *settingsFile) {
	sf.Path = filepath.Clean(sf.Path)
	if _, dup := c.byPath[sf.Path]; dup {
		return
	}
	c.byPath[sf.Path] = sf
	c.files = append(c.files, sf)
}

// discoverFiles lists every settings file that exists, plus the ones history says
// existed in folders that may be gone now.
func (c *collector) discoverFiles() {
	c.byPath = map[string]*settingsFile{}
	home, claude := c.env.Home, c.env.ClaudeDir

	userBase := match.RuleBase{Home: home, Settings: claude, Project: home}
	c.add(&settingsFile{Path: filepath.Join(claude, "settings.json"), Scope: model.ScopeUser, Base: userBase})
	c.add(&settingsFile{Path: filepath.Join(claude, "settings.local.json"), Scope: model.ScopeLocal, Project: home,
		Base: match.RuleBase{Home: home, Settings: home, Project: home}})
	for _, root := range managedRoots {
		c.add(&settingsFile{Path: filepath.Join(root, "managed-settings.json"), Scope: model.ScopeManaged, Base: userBase})
		drop, _ := filepath.Glob(filepath.Join(root, "managed-settings.d", "*.json"))
		sort.Strings(drop)
		for _, p := range drop {
			c.add(&settingsFile{Path: p, Scope: model.ScopeManaged, Base: userBase})
		}
	}
	c.add(&settingsFile{Path: filepath.Join(claude, "remote-settings.json"), Scope: model.ScopeManaged, Base: userBase})

	for _, dir := range c.projectFolders() {
		c.addProjectFiles(dir)
		if root := gitRoot(dir); root != "" && root != dir && root != filepath.Clean(home) {
			c.addProjectFiles(root)
		}
	}

	// Files that only history knows: the folder may be deleted or unreadable by now.
	var extra []string
	for _, p := range c.paths {
		f := c.facts[p]
		for _, s := range f.Snapshots {
			extra = append(extra, s.File)
		}
		for _, r := range f.FileHistory {
			extra = append(extra, r.File)
		}
	}
	sort.Strings(extra)
	for _, p := range extra {
		if _, ok := c.byPath[filepath.Clean(p)]; !ok {
			if sf, ok := c.fileFromPath(p); ok {
				c.add(sf)
			}
		}
	}
}

func (c *collector) addProjectFiles(dir string) {
	base := match.RuleBase{Home: c.env.Home, Settings: dir, Project: dir}
	c.add(&settingsFile{Path: filepath.Join(dir, ".claude", "settings.json"), Scope: model.ScopeProject, Project: dir, Base: base})
	c.add(&settingsFile{Path: filepath.Join(dir, ".claude", "settings.local.json"), Scope: model.ScopeLocal, Project: dir, Base: base})
	// Older Claude Code versions kept worktrees inside the project's .claude folder.
	entries, err := os.ReadDir(filepath.Join(dir, ".claude", "worktrees"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		wt := filepath.Join(dir, ".claude", "worktrees", e.Name())
		wb := match.RuleBase{Home: c.env.Home, Settings: wt, Project: wt}
		c.add(&settingsFile{Path: filepath.Join(wt, ".claude", "settings.local.json"), Scope: model.ScopeLocal, Project: wt, Base: wb})
	}
}

// fileFromPath builds a settingsFile for a path seen in history.
func (c *collector) fileFromPath(p string) (*settingsFile, bool) {
	if !filepath.IsAbs(p) || !isSettingsPath(p) {
		return nil, false
	}
	p = filepath.Clean(p)
	dir := filepath.Dir(filepath.Dir(p))
	sf := &settingsFile{Path: p, Scope: model.ScopeProject, Project: dir,
		Base: match.RuleBase{Home: c.env.Home, Settings: dir, Project: dir}}
	if strings.HasSuffix(p, "settings.local.json") {
		sf.Scope = model.ScopeLocal
	}
	return sf, true
}

// projectFolders returns the existing folders any source names: the projects in
// ~/.claude.json, transcript working folders, desktop sessions and prompt history.
// Folders that cannot be checked are counted in c.blocked.
func (c *collector) projectFolders() []string {
	set := map[string]bool{}
	for p := range c.cj.Projects {
		set[p] = true
	}
	for _, p := range c.paths {
		if cwd := c.facts[p].Cwd; cwd != "" {
			set[filepath.Clean(cwd)] = true
		}
	}
	for _, ss := range [][]session{c.desktop, c.prompts} {
		for _, s := range ss {
			if s.Dir != "" {
				set[s.Dir] = true
			}
		}
	}
	var out []string
	for p := range set {
		if !filepath.IsAbs(p) {
			continue
		}
		dir, blocked := isDir(p)
		switch {
		case dir:
			out = append(out, p)
		case blocked:
			c.blocked[p] = true
		}
	}
	sort.Strings(out)
	return out
}
