package match

import (
	"hash/fnv"
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

// MaxPrefix is the longest command prefix (in tokens) that gets its own usage key.
const MaxPrefix = 8

// Key is a hashed usage key. History extractors store keys, never command text.
type Key = uint64

func hash(parts ...string) Key {
	h := fnv.New64a()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return h.Sum64()
}

func PrefixKey(tokens []string) Key  { return hash(append([]string{"prefix"}, tokens...)...) }
func ExactKey(tokens []string) Key   { return hash(append([]string{"exact"}, tokens...)...) }
func ToolKey(name string) Key        { return hash("tool", name) }
func HostKey(host string) Key        { return hash("host", strings.ToLower(host)) }
func MCPServerKey(server string) Key { return hash("mcp-server", server) }

// DirKey and FileKey are namespaced by "read" or "edit" so a Read rule only counts reads.
func DirKey(ns, dir string) Key   { return hash(ns, "dir", filepath.Clean(dir)) }
func FileKey(ns, file string) Key { return hash(ns, "file", filepath.Clean(file)) }

// CommandKeys returns the keys of one executed simple command: a prefix key for each
// prefix up to MaxPrefix tokens and one exact key. When the program is given as a
// path (/bin/zsh), the same keys are also added for its base name (zsh).
func CommandKeys(tokens []string) []Key {
	if len(tokens) == 0 {
		return nil
	}
	keys := commandKeys(tokens)
	if strings.Contains(tokens[0], "/") {
		alt := append([]string{path.Base(tokens[0])}, tokens[1:]...)
		keys = append(keys, commandKeys(alt)...)
	}
	return keys
}

func commandKeys(tokens []string) []Key {
	n := min(len(tokens), MaxPrefix)
	keys := make([]Key, 0, n+1)
	for k := 1; k <= n; k++ {
		keys = append(keys, PrefixKey(tokens[:k]))
	}
	return append(keys, ExactKey(tokens))
}

// LineKeys returns the keys of every simple command in a shell command line.
func LineKeys(line string) []Key {
	var keys []Key
	for _, c := range Commands(line) {
		keys = append(keys, CommandKeys(c)...)
	}
	return keys
}

// ArgvKeys returns the keys of a command recorded as an argv array. A shell wrapper
// such as [zsh -lc script] yields keys for the wrapper and for the script's commands.
func ArgvKeys(argv []string) []Key {
	if len(argv) == 0 {
		return nil
	}
	keys := CommandKeys(argv)
	if script, ok := shellScript(argv); ok {
		keys = append(keys, LineKeys(script)...)
	}
	return keys
}

// PathKeys returns a key for the file and for each folder above it.
func PathKeys(ns, file string) []Key {
	file = filepath.Clean(file)
	keys := []Key{FileKey(ns, file)}
	for d := filepath.Dir(file); ; d = filepath.Dir(d) {
		keys = append(keys, DirKey(ns, d))
		if d == "/" || d == "." || d == filepath.Dir(d) {
			break
		}
	}
	return keys
}

// Claude Code tools whose path rules use the read or edit namespace.
var (
	readTools = map[string]bool{"Read": true, "Glob": true, "Grep": true, "LS": true}
	editTools = map[string]bool{"Edit": true, "Write": true, "MultiEdit": true, "NotebookEdit": true}
)

// ClaudeToolUse describes one Claude Code tool call with the fields usage needs.
type ClaudeToolUse struct {
	Name     string // tool name, e.g. Bash, Read, mcp__server__tool
	Command  string // Bash command
	FilePath string // file tools: file_path, notebook_path or path
	URL      string // WebFetch url
}

// ClaudeToolKeys returns the usage keys of one Claude Code tool call.
func ClaudeToolKeys(u ClaudeToolUse) []Key {
	keys := []Key{ToolKey(u.Name)}
	switch {
	case u.Name == "Bash":
		keys = append(keys, LineKeys(u.Command)...)
	case readTools[u.Name] && u.FilePath != "":
		keys = append(keys, PathKeys("read", u.FilePath)...)
	case editTools[u.Name] && u.FilePath != "":
		keys = append(keys, PathKeys("edit", u.FilePath)...)
	case u.Name == "WebFetch" && u.URL != "":
		if p, err := url.Parse(u.URL); err == nil && p.Hostname() != "" {
			keys = append(keys, HostKey(p.Hostname()))
		}
	case strings.HasPrefix(u.Name, "mcp__"):
		if s, _, ok := strings.Cut(strings.TrimPrefix(u.Name, "mcp__"), "__"); ok {
			keys = append(keys, MCPServerKey(s))
		}
	}
	return keys
}
