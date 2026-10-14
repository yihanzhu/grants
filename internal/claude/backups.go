package claude

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var stampRE = regexp.MustCompile(`(\d{8})-(\d{6})`)

type fileBackup struct {
	Path string
	T    time.Time
}

// siblingBackups finds copies of a settings file kept next to it: <name>.bak*,
// <name>.backup* and <name>~. Their time comes from a YYYYMMDD-HHMMSS stamp in the
// name, read as local time, else from the modification time.
func siblingBackups(path string) []fileBackup {
	dir, base := filepath.Split(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []fileBackup
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base) || name == base {
			continue
		}
		suffix := name[len(base):]
		if suffix != "~" && !strings.HasPrefix(suffix, ".bak") && !strings.HasPrefix(suffix, ".backup") {
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, fileBackup{Path: filepath.Join(dir, name), T: backupTime(suffix, fi.ModTime())})
	}
	return out
}

func backupTime(suffix string, mtime time.Time) time.Time {
	if m := stampRE.FindStringSubmatch(suffix); m != nil {
		if t, err := time.ParseInLocation("20060102150405", m[1]+m[2], time.Local); err == nil {
			return t
		}
	}
	return mtime
}

type jsonBackup struct {
	T    time.Time
	Info claudeJSON
}

// claudeJSONBackups reads ClaudeDir/backups/.claude.json.backup.<epoch-ms>. Claude Code
// keeps the latest few. Only trust and allowedTools are decoded.
func claudeJSONBackups(claudeDir string) []jsonBackup {
	dir := filepath.Join(claudeDir, "backups")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	const prefix = ".claude.json.backup."
	var out []jsonBackup
	for _, e := range entries {
		ms, err := strconv.ParseInt(strings.TrimPrefix(e.Name(), prefix), 10, 64)
		if !strings.HasPrefix(e.Name(), prefix) || err != nil || ms <= 0 {
			continue
		}
		b, st := readFile(filepath.Join(dir, e.Name()))
		if st != stateOK {
			continue
		}
		info, err := parseClaudeJSON(b)
		if err != nil {
			continue
		}
		out = append(out, jsonBackup{T: time.UnixMilli(ms), Info: info})
	}
	return out
}
