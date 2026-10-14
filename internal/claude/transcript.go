package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/jsonl"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/risk"
)

// transcriptCacheName and transcriptCacheVersion identify the cached facts. Bump the
// version whenever the facts or the way they are computed change.
const (
	transcriptCacheName    = "claude-transcripts"
	transcriptCacheVersion = 1
)

// Use counts how often history matched one usage key.
type Use struct {
	Count int32
	Last  int64 // unix seconds
}

// TranscriptFacts is everything grants keeps from one transcript file. It holds hashed
// usage keys and short, redacted text, never conversation text.
type TranscriptFacts struct {
	Start, End  time.Time
	Cwd         string             // first non-empty cwd
	SessionID   string             //
	Snapshots   []SettingsSnapshot // allow lists seen in Edit/Write results on settings files
	FileHistory []FileHistoryRef   // file-history backups of settings files
	Decisions   []Decision         // "don't ask again" answers
	Usage       map[match.Key]Use
}

// SettingsSnapshot is the allow list of a settings file at one moment. Rules are
// stored redacted (see normRule), so a rule that holds a credential never reaches the cache.
type SettingsSnapshot struct {
	T     time.Time
	File  string
	Allow []string
}

// FileHistoryRef points at a copy of a settings file that Claude Code kept before an edit.
type FileHistoryRef struct {
	T      time.Time
	File   string
	Backup string // absolute path of the backup file; empty when the file did not exist then
}

// Decision is a "don't ask again" answer to a permission prompt.
type Decision struct {
	T       time.Time
	Tool    string
	Summary string // redacted, at most 120 characters
	Keys    []match.Key
}

// normRule is the form in which rules are compared and stored in the cache.
func normRule(rule string) string { return risk.Redact(rule) }

func normRules(rules []string) []string {
	out := make([]string, 0, len(rules))
	for _, r := range dedupe(rules) {
		out = append(out, normRule(r))
	}
	return out
}

var (
	keyTimestamp   = []byte(`"timestamp":"`)
	keyCwd         = []byte(`"cwd":"`)
	keySession     = []byte(`"sessionId":"`)
	keyToolUse     = []byte(`"type":"tool_use"`)
	keyToolResult  = []byte(`"toolUseResult":{`)
	keyPermanent   = []byte(`"source":"user_permanent"`)
	keyFileHistory = []byte(`"type":"file-history-`)
	keySettings    = []byte(`.claude/settings`)
)

// recentCap is how many recent tool calls are kept to join with permission answers.
const recentCap = 512

type recentUse struct {
	name  string
	keys  []match.Key
	short string
}

type extractor struct {
	f         *TranscriptFacts
	fhDir     string // ClaudeDir/file-history/<session>
	seenTool  map[string]struct{}
	cur, prev map[string]recentUse
	callKeys  map[match.Key]struct{}
}

// extractTranscript reads one transcript. projectsRoot is ClaudeDir/projects and
// historyRoot is ClaudeDir/file-history. Every line is checked with a cheap substring
// test before it is decoded, because transcripts are large.
func extractTranscript(path, projectsRoot, historyRoot string) (TranscriptFacts, error) {
	sess := sessionFolder(path, projectsRoot)
	x := &extractor{
		f:        &TranscriptFacts{Usage: map[match.Key]Use{}},
		fhDir:    filepath.Join(historyRoot, sess),
		seenTool: map[string]struct{}{},
		cur:      map[string]recentUse{},
		prev:     map[string]recentUse{},
		callKeys: map[match.Key]struct{}{},
	}
	err := jsonl.EachFile(path, func(line []byte) error {
		x.line(line)
		return nil
	})
	if err != nil {
		return TranscriptFacts{}, err
	}
	if x.f.SessionID == "" {
		x.f.SessionID = sess
	}
	return *x.f, nil
}

// sessionFolder returns the session id a transcript belongs to: the file name for a
// main transcript, or the parent session folder for a subagent file.
func sessionFolder(path, projectsRoot string) string {
	rel, err := filepath.Rel(projectsRoot, path)
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if err != nil || len(parts) < 2 || parts[0] == ".." {
		return strings.TrimSuffix(filepath.Base(path), ".jsonl")
	}
	if len(parts) == 2 {
		return strings.TrimSuffix(parts[1], ".jsonl")
	}
	return parts[1]
}

func (x *extractor) line(line []byte) {
	t := lineTime(line)
	if !t.IsZero() {
		if x.f.Start.IsZero() || t.Before(x.f.Start) {
			x.f.Start = t
		}
		if t.After(x.f.End) {
			x.f.End = t
		}
	}
	if x.f.Cwd == "" {
		x.f.Cwd = quotedAfterLast(line, keyCwd)
	}
	if x.f.SessionID == "" {
		x.f.SessionID = quotedAfterLast(line, keySession)
	}
	switch {
	case bytes.Contains(line, keyToolUse):
		x.toolUse(line, t)
	case bytes.Contains(line, keyFileHistory):
		if bytes.Contains(line, keySettings) {
			x.fileHistory(line)
		}
	case bytes.Contains(line, keyPermanent):
		x.decision(line, t)
	case bytes.Contains(line, keyToolResult) && bytes.Contains(line, keySettings) && hasSettingsPath(line):
		x.settingsEdit(line, t)
	}
}

type toolBlock struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Input struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Path         string `json:"path"`
		URL          string `json:"url"`
	} `json:"input"`
}

func (x *extractor) toolUse(line []byte, t time.Time) {
	var rec struct {
		UUID    string `json:"uuid"`
		Message struct {
			Content []toolBlock `json:"content"`
		} `json:"message"`
	}
	if !decode(line, &rec) {
		return
	}
	for _, b := range rec.Message.Content {
		if b.Type != "tool_use" || b.Name == "" {
			continue
		}
		if b.ID != "" {
			if _, dup := x.seenTool[b.ID]; dup {
				continue
			}
			x.seenTool[b.ID] = struct{}{}
		}
		in := b.Input
		use := match.ClaudeToolUse{Name: b.Name, Command: in.Command, URL: in.URL}
		use.FilePath = firstNonEmpty(in.FilePath, in.NotebookPath, in.Path)
		keys := match.ClaudeToolKeys(use)
		x.count(keys, t)
		ref := recentUse{name: b.Name, keys: keys, short: shorten(firstNonEmpty(in.Command, use.FilePath, in.URL), 400)}
		x.remember(b.ID, ref)
		x.remember(rec.UUID, ref)
	}
}

func (x *extractor) remember(id string, r recentUse) {
	if id == "" {
		return
	}
	if len(x.cur) >= recentCap {
		x.prev, x.cur = x.cur, map[string]recentUse{}
	}
	x.cur[id] = r
}

func (x *extractor) recall(id string) (recentUse, bool) {
	if r, ok := x.cur[id]; ok {
		return r, true
	}
	r, ok := x.prev[id]
	return r, ok
}

// count adds one use to every distinct key of a tool call.
func (x *extractor) count(keys []match.Key, t time.Time) {
	clear(x.callKeys)
	last := int64(0)
	if !t.IsZero() {
		last = t.Unix()
	}
	for _, k := range keys {
		if _, dup := x.callKeys[k]; dup {
			continue
		}
		x.callKeys[k] = struct{}{}
		u := x.f.Usage[k]
		u.Count++
		if last > u.Last {
			u.Last = last
		}
		x.f.Usage[k] = u
	}
}

func (x *extractor) decision(line []byte, t time.Time) {
	var rec struct {
		SourceUUID string `json:"sourceToolAssistantUUID"`
		Decision   struct {
			Decision string `json:"decision"`
			Source   string `json:"source"`
		} `json:"permissionDecision"`
		Message struct {
			Content []struct {
				ToolUseID string `json:"tool_use_id"`
			} `json:"content"`
		} `json:"message"`
	}
	if !decode(line, &rec) || rec.Decision.Source != "user_permanent" || rec.Decision.Decision != "accept" {
		return
	}
	var ref recentUse
	found := false
	for _, c := range rec.Message.Content {
		if ref, found = x.recall(c.ToolUseID); found {
			break
		}
	}
	if !found {
		ref, found = x.recall(rec.SourceUUID)
	}
	if !found || t.IsZero() {
		return
	}
	x.f.Decisions = append(x.f.Decisions, Decision{
		T:       t,
		Tool:    ref.name,
		Summary: shorten(risk.Redact(ref.short), 120),
		Keys:    ref.keys,
	})
}

type fhBackup struct {
	BackupFileName *string `json:"backupFileName"`
	BackupTime     string  `json:"backupTime"`
}

func (x *extractor) fileHistory(line []byte) {
	var rec struct {
		Type         string    `json:"type"`
		TrackingPath string    `json:"trackingPath"`
		Backup       *fhBackup `json:"backup"`
		Snapshot     *struct {
			Tracked map[string]fhBackup `json:"trackedFileBackups"`
		} `json:"snapshot"`
	}
	if !decode(line, &rec) {
		return
	}
	add := func(file string, b fhBackup) {
		if !isSettingsPath(file) {
			return
		}
		t := parseTime(b.BackupTime)
		if t.IsZero() {
			return
		}
		ref := FileHistoryRef{T: t, File: filepath.Clean(file)}
		if b.BackupFileName != nil && *b.BackupFileName != "" {
			ref.Backup = filepath.Join(x.fhDir, *b.BackupFileName)
		}
		x.f.FileHistory = append(x.f.FileHistory, ref)
	}
	if rec.Backup != nil {
		add(rec.TrackingPath, *rec.Backup)
	}
	if rec.Snapshot != nil {
		for file, b := range rec.Snapshot.Tracked {
			add(file, b)
		}
	}
}

// editResult is the part of a user record's toolUseResult that describes a file edit.
type editResult struct {
	FilePath     string     `json:"filePath"`
	Content      *string    `json:"content"` // Write
	OriginalFile *string    `json:"originalFile"`
	OldString    string     `json:"oldString"` // Edit
	NewString    string     `json:"newString"`
	ReplaceAll   bool       `json:"replaceAll"`
	Edits        []struct { // MultiEdit
		OldString  string `json:"oldString"`
		NewString  string `json:"newString"`
		ReplaceAll bool   `json:"replaceAll"`
	} `json:"edits"`
}

func (x *extractor) settingsEdit(line []byte, t time.Time) {
	if t.IsZero() {
		return
	}
	var rec struct {
		Result json.RawMessage `json:"toolUseResult"`
	}
	if !decode(line, &rec) || len(rec.Result) == 0 || rec.Result[0] != '{' {
		return // a failed edit stores an error string here
	}
	var r editResult
	if !decode(rec.Result, &r) || !isSettingsPath(r.FilePath) {
		return
	}
	file := filepath.Clean(r.FilePath)
	before, after, haveBefore, haveAfter := editStates(r)
	if haveBefore {
		if allow, err := parseAllow([]byte(before)); err == nil || before == "" {
			x.f.Snapshots = append(x.f.Snapshots, SettingsSnapshot{T: t.Add(-time.Millisecond), File: file, Allow: normRules(allow)})
		}
	}
	if haveAfter {
		if allow, err := parseAllow([]byte(after)); err == nil {
			x.f.Snapshots = append(x.f.Snapshots, SettingsSnapshot{T: t, File: file, Allow: normRules(allow)})
		}
	}
}

type editStep struct {
	old, new string
	all      bool
}

// editStates returns the file content before and after one edit, when the result says
// enough to rebuild them. A file that did not exist before a Write counts as empty.
func editStates(r editResult) (before, after string, haveBefore, haveAfter bool) {
	if r.Content != nil { // Write
		if r.OriginalFile != nil {
			before, haveBefore = *r.OriginalFile, true
		} else {
			haveBefore = true // created: nothing was allowed before
		}
		return before, *r.Content, haveBefore, true
	}
	if r.OriginalFile == nil {
		return "", "", false, false
	}
	before, haveBefore = *r.OriginalFile, true
	steps := []editStep{{r.OldString, r.NewString, r.ReplaceAll}}
	if len(r.Edits) > 0 {
		steps = steps[:0]
		for _, e := range r.Edits {
			steps = append(steps, editStep{e.OldString, e.NewString, e.ReplaceAll})
		}
	}
	after = before
	for _, e := range steps {
		if e.old == "" || !strings.Contains(after, e.old) {
			return before, "", haveBefore, false
		}
		n := 1
		if e.all {
			n = -1
		}
		after = strings.Replace(after, e.old, e.new, n)
	}
	return before, after, haveBefore, true
}

// isSettingsPath reports whether path names a Claude Code project or user settings file.
func isSettingsPath(p string) bool {
	return strings.HasSuffix(p, "/.claude/settings.json") || strings.HasSuffix(p, "/.claude/settings.local.json")
}

// hasSettingsPath reports whether the line has a filePath or file_path value that
// names a settings file. Skill listings and system text mention these names often, so
// the key matters.
func hasSettingsPath(line []byte) bool {
	for off := 0; ; {
		i := bytes.Index(line[off:], keySettings)
		if i < 0 {
			return false
		}
		i += off
		off = i + len(keySettings)
		rest := line[off:]
		if !bytes.HasPrefix(rest, []byte(`.json"`)) && !bytes.HasPrefix(rest, []byte(`.local.json"`)) {
			continue
		}
		j := bytes.LastIndexByte(line[:i], '"')
		if j < 0 {
			continue
		}
		head := line[:j+1]
		if bytes.HasSuffix(head, []byte(`filePath":"`)) || bytes.HasSuffix(head, []byte(`file_path":"`)) {
			return true
		}
	}
}

// decode unmarshals JSON and ignores fields of the wrong type, which agents' tools
// produce now and then.
func decode(b []byte, v any) bool {
	err := json.Unmarshal(b, v)
	var te *json.UnmarshalTypeError
	return err == nil || errors.As(err, &te)
}

// lineTime returns the last "timestamp" string in the line. Top-level fields come last
// in transcript records, and text inside strings has escaped quotes, so it never matches.
func lineTime(line []byte) time.Time {
	i := bytes.LastIndex(line, keyTimestamp)
	if i < 0 {
		return time.Time{}
	}
	rest := line[i+len(keyTimestamp):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 || end > 40 {
		return time.Time{}
	}
	return parseTime(string(rest[:end]))
}

// quotedAfterLast returns the JSON string that follows the last occurrence of key (a
// key and its opening quote).
func quotedAfterLast(line, key []byte) string {
	i := bytes.LastIndex(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key)-1:]
	for j := 1; j < len(rest); j++ {
		switch rest[j] {
		case '\\':
			j++
		case '"':
			var s string
			if json.Unmarshal(rest[:j+1], &s) != nil {
				return ""
			}
			return s
		}
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// shorten cuts s to at most n runes.
func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
