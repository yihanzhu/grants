package claude

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/jsonl"
	"github.com/yihanzhu/grants/internal/scan"
)

// session is one dated use of a folder, from any history source.
type session struct {
	T   time.Time
	Dir string
}

// desktopSessions reads the Claude desktop app's Code sessions. They reach back
// further than transcripts, which Claude Code deletes after cleanupPeriodDays.
func desktopSessions(home string) (out []session, files int) {
	root := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code-sessions")
	paths, _, _ := scan.Walk(root, func(p string) bool {
		b := filepath.Base(p)
		return strings.HasPrefix(b, "local_") && strings.HasSuffix(b, ".json")
	})
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var s struct {
			CreatedAt int64  `json:"createdAt"`
			Cwd       string `json:"cwd"`
			OriginCwd string `json:"originCwd"`
		}
		if !decode(b, &s) || s.CreatedAt <= 0 {
			continue
		}
		files++
		t := time.UnixMilli(s.CreatedAt)
		for _, d := range []string{s.Cwd, s.OriginCwd} {
			if d != "" {
				out = append(out, session{T: t, Dir: filepath.Clean(d)})
			}
		}
	}
	return out, files
}

// promptHistory reads history.jsonl: one record per prompt, with the project folder.
// It keeps the first prompt time for each folder, and the file's overall span.
func promptHistory(path string) (first []session, files int, from, to time.Time) {
	byDir := map[string]time.Time{}
	err := jsonl.EachFile(path, func(line []byte) error {
		if !bytes.Contains(line, []byte(`"timestamp":`)) {
			return nil
		}
		var r struct {
			Project   string `json:"project"`
			Timestamp int64  `json:"timestamp"`
		}
		if !decode(line, &r) || r.Timestamp <= 0 {
			return nil
		}
		t := time.UnixMilli(r.Timestamp)
		if from.IsZero() || t.Before(from) {
			from = t
		}
		if t.After(to) {
			to = t
		}
		if r.Project == "" {
			return nil
		}
		d := filepath.Clean(r.Project)
		if old, ok := byDir[d]; !ok || t.Before(old) {
			byDir[d] = t
		}
		return nil
	})
	if err != nil {
		return nil, 0, time.Time{}, time.Time{}
	}
	for d, t := range byDir {
		first = append(first, session{T: t, Dir: d})
	}
	return first, 1, from, to
}
