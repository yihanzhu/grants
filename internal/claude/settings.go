package claude

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

// parseAllow returns the string elements of permissions.allow in a settings file.
// A file without that key has no rules. Only that one key is read.
func parseAllow(doc []byte) ([]string, error) {
	var s struct {
		Permissions json.RawMessage `json:"permissions"`
	}
	if err := json.Unmarshal(doc, &s); err != nil {
		return nil, err
	}
	if len(s.Permissions) == 0 {
		return nil, nil
	}
	var p struct {
		Allow json.RawMessage `json:"allow"`
	}
	if err := json.Unmarshal(s.Permissions, &p); err != nil {
		return nil, fmt.Errorf("permissions: %w", err)
	}
	return stringList(p.Allow), nil
}

// stringList decodes a JSON array and keeps its string elements. Anything else gives nil.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		var s string
		if len(it) > 0 && it[0] == '"' && json.Unmarshal(it, &s) == nil && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dedupe keeps the first copy of each string.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// claudeJSON holds the few facts read from ~/.claude.json. The file also holds account
// data, so nothing else is decoded, stored or returned.
type claudeJSON struct {
	FirstStart time.Time
	Projects   map[string]projectInfo
}

type projectInfo struct {
	Trusted      bool
	AllowedTools []string
}

// parseClaudeJSON decodes firstStartTime and, for each project, hasTrustDialogAccepted
// and allowedTools. Project keys are cleaned paths.
func parseClaudeJSON(doc []byte) (claudeJSON, error) {
	var raw struct {
		FirstStartTime string `json:"firstStartTime"`
		Projects       map[string]struct {
			HasTrust     json.RawMessage `json:"hasTrustDialogAccepted"`
			AllowedTools json.RawMessage `json:"allowedTools"`
		} `json:"projects"`
	}
	var out claudeJSON
	if err := json.Unmarshal(doc, &raw); err != nil {
		return out, err
	}
	out.FirstStart = parseTime(raw.FirstStartTime)
	out.Projects = make(map[string]projectInfo, len(raw.Projects))
	for p, v := range raw.Projects {
		if p == "" {
			continue
		}
		out.Projects[filepath.Clean(p)] = projectInfo{
			Trusted:      string(v.HasTrust) == "true",
			AllowedTools: dedupe(stringList(v.AllowedTools)),
		}
	}
	return out, nil
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
