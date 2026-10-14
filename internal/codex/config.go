package codex

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// trustLevelTrusted is the trust_level value that makes a folder a grant.
const trustLevelTrusted = "trusted"

// trustEntry is one trusted folder in a config file.
type trustEntry struct {
	Path string
	Line int // 1-based line of the [projects."<path>"] header; 0 when not found
}

// parseTrusted reads config.toml text and returns the folders with trust_level
// "trusted", sorted by path.
func parseTrusted(doc []byte) ([]trustEntry, error) {
	var cfg struct {
		Projects map[string]struct {
			TrustLevel string `toml:"trust_level"`
		} `toml:"projects"`
	}
	if _, err := toml.NewDecoder(bytes.NewReader(doc)).Decode(&cfg); err != nil {
		return nil, err
	}
	lines := headerLines(doc)
	var out []trustEntry
	for p, v := range cfg.Projects {
		if v.TrustLevel == trustLevelTrusted {
			out = append(out, trustEntry{Path: p, Line: lines[p]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// headerLines maps the folder in each [projects."<path>"] header to its line number.
// It reads only the header form Codex writes; a folder defined another way gets no
// line, which is display-only.
func headerLines(doc []byte) map[string]int {
	out := map[string]int{}
	for i, l := range strings.Split(string(doc), "\n") {
		l = strings.TrimSpace(l)
		rest, ok := strings.CutPrefix(l, "[projects.")
		if !ok || rest == "" {
			continue
		}
		key, ok := readQuotedKey(rest)
		if ok {
			if _, dup := out[key]; !dup {
				out[key] = i + 1
			}
		}
	}
	return out
}

// readQuotedKey reads a basic ("...") or literal ('...') TOML key at the start of s
// that is followed by "]".
func readQuotedKey(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	q := s[0]
	switch q {
	case '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 || !strings.HasPrefix(strings.TrimSpace(s[end+2:]), "]") {
			return "", false
		}
		return s[1 : 1+end], true
	case '"':
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '"' {
				if !strings.HasPrefix(strings.TrimSpace(s[i+1:]), "]") {
					return "", false
				}
				k, err := strconv.Unquote(s[:i+1])
				if err != nil {
					// TOML allows escapes Go does not (\e, \uXXXX is shared); keep the raw text.
					return s[1:i], true
				}
				return k, true
			}
		}
	}
	return "", false
}

// backupFile is a config backup next to config.toml.
type backupFile struct {
	Path string
	Time time.Time
}

var stampRe = regexp.MustCompile(`(\d{4})(\d{2})(\d{2})[-_T]?(\d{2})(\d{2})(\d{2})?`)

// configBackups lists siblings of config named <config>.bak*, <config>.backup* and
// <config>~, with the time each was taken: a YYYYMMDD-HHMMSS stamp in the name (local
// time) when it has a time part, else the file's modification time.
func configBackups(config string) []backupFile {
	dir, base := filepath.Split(config)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []backupFile
	for _, e := range entries {
		n := e.Name()
		if !(strings.HasPrefix(n, base+".bak") || strings.HasPrefix(n, base+".backup") || n == base+"~") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		t := info.ModTime()
		if st, ok := stampTime(n[len(base):]); ok {
			t = st
		}
		out = append(out, backupFile{Path: filepath.Join(dir, n), Time: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// stampTime reads a YYYYMMDD-HHMMSS stamp (local time) from a file name suffix. It
// reports false when there is no stamp or the stamp has no time of day.
func stampTime(name string) (time.Time, bool) {
	m := stampRe.FindStringSubmatch(name)
	if m == nil || m[6] == "" {
		return time.Time{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	t := time.Date(n(m[1]), time.Month(n(m[2])), n(m[3]), n(m[4]), n(m[5]), n(m[6]), 0, time.Local)
	// Reject impossible dates, which time.Date silently normalizes.
	if t.Year() != n(m[1]) || int(t.Month()) != n(m[2]) || t.Day() != n(m[3]) {
		return time.Time{}, false
	}
	return t, true
}

var dayRe = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)

// pathDay returns the start (local time) of the latest YYYY-MM-DD segment in path.
// Codex names project folders after the day they were made, so the folder cannot have
// been trusted before that day.
func pathDay(path string) (time.Time, bool) {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		m := dayRe.FindStringSubmatch(segs[i])
		if m == nil {
			continue
		}
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		t := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.Local)
		if t.Year() == y && int(t.Month()) == mo && t.Day() == d && y >= 2000 {
			return t, true
		}
	}
	return time.Time{}, false
}
