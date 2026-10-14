package match

import (
	"path/filepath"
	"strings"
)

// ClaudeRule is a parsed Claude Code permission rule such as Bash(git push:*).
type ClaudeRule struct {
	Tool    string
	Spec    string // text inside the parentheses
	HasSpec bool
}

func ParseClaudeRule(s string) ClaudeRule {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '('); i > 0 && strings.HasSuffix(s, ")") {
		return ClaudeRule{Tool: s[:i], Spec: s[i+1 : len(s)-1], HasSpec: true}
	}
	return ClaudeRule{Tool: s}
}

// RuleBase holds the folders that relative paths in a Claude rule resolve against.
type RuleBase struct {
	Home     string // expands ~/
	Settings string // folder that "/path" is relative to: the project root for project files, ~/.claude for user files
	Project  string // folder that "path" and "./path" are relative to
}

// ClaudeRuleKeys returns the usage keys a rule matches; a tool call matches the rule
// when its keys share at least one key with these. ok is false when grants cannot
// measure the rule's usage (for example a wildcard in the middle of a command).
func ClaudeRuleKeys(r ClaudeRule, base RuleBase) (keys []Key, ok bool) {
	spec := strings.TrimSpace(r.Spec)
	if !r.HasSpec || spec == "*" || spec == "" {
		if strings.HasPrefix(r.Tool, "mcp__") {
			name := strings.TrimSuffix(strings.TrimPrefix(r.Tool, "mcp__"), "__*")
			if s, _, found := strings.Cut(name, "__"); !found {
				return []Key{MCPServerKey(s)}, true
			}
			if strings.Contains(r.Tool, "*") {
				return nil, false
			}
		}
		return []Key{ToolKey(r.Tool)}, true
	}
	switch {
	case r.Tool == "Bash":
		return bashRuleKeys(spec)
	case r.Tool == "Read" || editTools[r.Tool]:
		ns := "read"
		if r.Tool != "Read" {
			ns = "edit"
		}
		return pathRuleKeys(ns, spec, base)
	case r.Tool == "WebFetch":
		host, found := strings.CutPrefix(spec, "domain:")
		if !found || strings.ContainsAny(host, "*?") {
			return nil, false
		}
		return []Key{HostKey(host)}, true
	}
	return nil, false
}

func bashRuleKeys(spec string) ([]Key, bool) {
	prefix := false
	switch {
	case strings.HasSuffix(spec, ":*"):
		spec, prefix = strings.TrimSuffix(spec, ":*"), true
	case strings.HasSuffix(spec, " *"):
		spec, prefix = strings.TrimSuffix(spec, " *"), true
	}
	if strings.ContainsAny(spec, "*") {
		return nil, false
	}
	tokens := Tokens(spec)
	if len(tokens) == 0 {
		return nil, false
	}
	if !prefix {
		return []Key{ExactKey(tokens)}, true
	}
	if len(tokens) > MaxPrefix {
		return nil, false
	}
	return []Key{PrefixKey(tokens)}, true
}

func pathRuleKeys(ns, spec string, base RuleBase) ([]Key, bool) {
	dirGlob := false
	if strings.HasSuffix(spec, "/**") {
		spec, dirGlob = strings.TrimSuffix(spec, "/**"), true
	} else if spec == "**" {
		spec, dirGlob = ".", true
	}
	if strings.ContainsAny(spec, "*?[") {
		return nil, false
	}
	var abs string
	switch {
	case strings.HasPrefix(spec, "//"):
		abs = spec[1:]
	case spec == "~" || strings.HasPrefix(spec, "~/"):
		abs = filepath.Join(base.Home, strings.TrimPrefix(spec, "~"))
	case strings.HasPrefix(spec, "/"):
		abs = filepath.Join(base.Settings, spec)
	default:
		abs = filepath.Join(base.Project, spec)
	}
	if dirGlob {
		return []Key{DirKey(ns, abs)}, true
	}
	return []Key{FileKey(ns, abs), DirKey(ns, abs)}, true
}

// CodexPatternKeys returns the prefix keys of a Codex prefix_rule pattern. Each
// position lists its alternatives; most positions have exactly one.
func CodexPatternKeys(pattern [][]string) []Key {
	combos := [][]string{nil}
	for _, alts := range pattern {
		var next [][]string
		for _, c := range combos {
			for _, a := range alts {
				next = append(next, append(append([]string(nil), c...), a))
				if len(next) > 64 {
					break
				}
			}
		}
		combos = next
	}
	var keys []Key
	for _, c := range combos {
		if len(c) == 0 {
			continue
		}
		if len(c) <= MaxPrefix {
			keys = append(keys, PrefixKey(c))
		} else {
			keys = append(keys, ExactKey(c)) // only exact runs of long patterns are counted
		}
	}
	return keys
}
