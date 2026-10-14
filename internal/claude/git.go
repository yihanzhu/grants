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

// git runs one read-only git command in root. The repository's own config must not run
// anything: fsmonitor is switched off, and signature checks (log.showSignature) are
// switched off because they run the program named by gpg.program. GIT_NO_LAZY_FETCH
// stops a partial clone from fetching a missing blob over the network.
func git(root string, args ...string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	full := append([]string{"-C", root, "-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "--no-optional-locks"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1")
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

// isPartialClone reports whether the repository has a promisor remote.
func isPartialClone(root string) bool {
	out, ok := git(root, "config", "--get-regexp", `^(extensions\.partialclone|remote\..*\.promisor)$`)
	if !ok {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasSuffix(line, " false") {
			return true
		}
	}
	return false
}

type gitVersion struct {
	T    time.Time
	Data []byte
}

// gitVersions returns up to 50 committed versions of the file at rel, newest first.
//
// A partial clone has no history: its old blobs may live on a remote, and reading them
// could open a network connection.
func gitVersions(root, rel string) []gitVersion {
	if isPartialClone(root) {
		return nil
	}
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
