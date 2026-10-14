package claude

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gitTimeout = 10 * time.Second

// gitRoot returns the folder that holds the .git entry at or above dir, or "".
func gitRoot(dir string) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if d == filepath.Dir(d) {
			return ""
		}
	}
}

// git runs one read-only git command in root. fsmonitor is switched off because it can
// run a program named by the repository's own config.
func git(root string, args ...string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	full := append([]string{"-C", root, "-c", "core.fsmonitor=false", "--no-optional-locks"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}

// gitTracked reports whether git tracks the file at rel inside root.
func gitTracked(root, rel string) bool {
	_, ok := git(root, "ls-files", "--error-unmatch", "--", rel)
	return ok
}

type gitVersion struct {
	T    time.Time
	Data []byte
}

// gitVersions returns up to 50 committed versions of the file at rel, newest first.
func gitVersions(root, rel string) []gitVersion {
	out, ok := git(root, "log", "--format=%H%x00%aI", "-n", "50", "--", rel)
	if !ok {
		return nil
	}
	var vs []gitVersion
	for _, line := range strings.Split(string(out), "\n") {
		sha, when, found := strings.Cut(strings.TrimSpace(line), "\x00")
		if !found {
			continue
		}
		t := parseTime(when)
		if t.IsZero() {
			continue
		}
		data, ok := git(root, "show", sha+":"+rel)
		vs = append(vs, gitVersion{T: t, Data: data})
		if !ok {
			vs[len(vs)-1].Data = nil // the file was deleted in this commit
		}
	}
	return vs
}
