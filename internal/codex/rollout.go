package codex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yihanzhu/grants/internal/jsonl"
	"github.com/yihanzhu/grants/internal/match"
	"github.com/yihanzhu/grants/internal/risk"
)

// rolloutVersion is part of the cache key. Bump it whenever RolloutFacts or the code
// that fills it changes, so old cache entries are not reused.
const rolloutVersion = 1

// cacheName is the scan cache file name stem for rollout facts.
const cacheName = "codex-rollouts"

// Use counts how often one usage key was seen in a session.
type Use struct {
	Count int32
	Last  int64 // unix seconds
}

// RolloutFacts is what grants keeps from one Codex session file. It holds hashed usage
// keys and short redacted text, never full commands or conversation.
type RolloutFacts struct {
	Start, End  time.Time         // first and last line timestamps
	Cwd         string            // session_meta payload cwd
	Source      string            // session source if present (cli, vscode, exec, subagent ...)
	Prefixes    []PrefixRun       // approved-prefix snapshots, consecutive identical sets merged
	Escalations []Escalation      // agent asked to leave the sandbox, with a proposed prefix_rule
	Usage       map[match.Key]Use // executed commands, one count per command per key
}

// PrefixRun says the approved command prefixes were exactly this set from From to To.
type PrefixRun struct {
	From, To time.Time
	Prefixes [][]string
}

// Escalation is a request to run a command outside the sandbox, with the prefix_rule
// the agent proposed to approve it for good.
type Escalation struct {
	T             time.Time
	Prefix        []string
	Justification string // redacted, at most 160 characters
	Ran           bool   // the command ran after the request
}

const (
	maxEscalations   = 200
	maxJustification = 160
)

// ExtractRollout reads one rollout file. It is exported for tests and tools; Collect
// calls it through the scan cache.
func ExtractRollout(path string) (facts RolloutFacts, err error) {
	// This runs in scan worker goroutines, where a panic would end the program.
	defer func() {
		if r := recover(); r != nil {
			facts, err = RolloutFacts{}, fmt.Errorf("codex: reading %s: %v", filepath.Base(path), r)
		}
	}()
	x := &extractor{
		usage:   map[match.Key]Use{},
		counted: map[string]bool{},
		pending: map[string]*pendingCall{},
	}
	if err := jsonl.EachFile(path, func(line []byte) error {
		x.line(line)
		return nil
	}); err != nil {
		return RolloutFacts{}, fmt.Errorf("codex: read rollout: %w", err)
	}
	return x.finish(), nil
}

type pendingCall struct {
	esc  int // index in escalations, or -1
	keys []match.Key
	t    time.Time
}

type extractor struct {
	firstTS, lastTS []byte
	cwd, source     string
	haveMeta        bool

	runs    []PrefixRun
	runKey  string
	escs    []Escalation
	usage   map[match.Key]Use
	counted map[string]bool // call ids already counted, so each command counts once
	pending map[string]*pendingCall
}

type envelope struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

var (
	tsPrefix       = []byte(`{"timestamp":"`)
	sigApproved    = []byte("Approved command prefixes")
	sigApprovedKey = []byte("approved_command_prefixes")
	sigCall        = []byte(`"type":"function_call"`)
	sigCallOut     = []byte(`"type":"function_call_output"`)
	sigLocalShell  = []byte(`"type":"local_shell_call"`)
	sigCmdItem     = []byte(`"CommandExecution"`)
	sigExecName    = []byte(`"name":"exec_command"`)
	sigShellName   = []byte(`"name":"shell"`)
	sigMeta        = []byte(`"type":"session_meta"`)
	sigWorld       = []byte(`"type":"world_state"`)
	sigMessage     = []byte(`"type":"message"`)
)

func (x *extractor) line(b []byte) {
	if bytes.HasPrefix(b, tsPrefix) {
		rest := b[len(tsPrefix):]
		if n := bytes.IndexByte(rest[:min(len(rest), 48)], '"'); n > 0 {
			if x.firstTS == nil {
				x.firstTS = append([]byte(nil), rest[:n]...)
			}
			x.lastTS = append(x.lastTS[:0], rest[:n]...)
		}
	}
	head := b[:min(len(b), 240)]
	switch {
	case !x.haveMeta && bytes.Contains(head, sigMeta):
		x.sessionMeta(b)
	case bytes.Contains(head, sigWorld):
		if bytes.Contains(b, sigApprovedKey) {
			x.worldState(b)
		}
	case bytes.Contains(b, sigApproved) && bytes.Contains(b, sigMessage):
		x.developerMessage(b)
	case bytes.Contains(b, sigCallOut):
		if len(x.pending) > 0 {
			x.callOutput(b)
		}
	case bytes.Contains(b, sigCall):
		if bytes.Contains(b, sigExecName) || bytes.Contains(b, sigShellName) {
			x.functionCall(b)
		}
	case bytes.Contains(b, sigLocalShell):
		x.localShell(b)
	case bytes.Contains(b, sigCmdItem):
		x.commandItem(b)
	}
}

func (x *extractor) finish() RolloutFacts {
	// A request with no recorded output has an unknown outcome; count its command.
	for id, p := range x.pending {
		x.count(p.keys, p.t)
		x.counted[id] = true
	}
	f := RolloutFacts{
		Cwd:         x.cwd,
		Source:      x.source,
		Prefixes:    x.runs,
		Escalations: x.escs,
		Usage:       x.usage,
	}
	f.Start = parseTime(string(x.firstTS))
	f.End = parseTime(string(x.lastTS))
	return f
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (x *extractor) decode(b []byte) (envelope, bool) {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return e, false
	}
	return e, true
}

func (x *extractor) sessionMeta(b []byte) {
	e, ok := x.decode(b)
	if !ok || e.Type != "session_meta" {
		return
	}
	var p struct {
		Cwd    string          `json:"cwd"`
		Source json.RawMessage `json:"source"`
	}
	if json.Unmarshal(e.Payload, &p) != nil {
		return
	}
	x.haveMeta = true
	x.cwd = p.Cwd
	x.source = sourceName(p.Source)
}

// sourceName turns the session source into one word: "vscode" for a string, the key
// for an object such as {"subagent": {...}}.
func sourceName(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			return keys[0]
		}
	}
	return ""
}

func (x *extractor) worldState(b []byte) {
	e, ok := x.decode(b)
	if !ok || e.Type != "world_state" {
		return
	}
	var p struct {
		State struct {
			Permissions struct {
				Approved *[][]string `json:"approved_command_prefixes"`
			} `json:"permissions"`
		} `json:"state"`
	}
	if json.Unmarshal(e.Payload, &p) != nil || p.State.Permissions.Approved == nil {
		return
	}
	x.snapshot(parseTime(e.Timestamp), *p.State.Permissions.Approved)
}

func (x *extractor) developerMessage(b []byte) {
	e, ok := x.decode(b)
	if !ok || e.Type != "response_item" {
		return
	}
	var p struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(e.Payload, &p) != nil || p.Type != "message" || p.Role != "developer" {
		return
	}
	for _, c := range p.Content {
		if i := strings.Index(c.Text, "## Approved command prefixes"); i >= 0 {
			x.snapshot(parseTime(e.Timestamp), parsePrefixList(c.Text[i:]))
		}
	}
}

// parsePrefixList reads the list under the "## Approved command prefixes" heading.
// The first entry follows the introduction sentence on the same line; later entries
// are lines that start with "- [".
func parsePrefixList(text string) [][]string {
	var out [][]string
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if i == 0 {
			continue
		}
		l = strings.TrimRight(l, "\r")
		start := -1
		if strings.HasPrefix(l, "- [") {
			start = 2
		} else if i == 1 {
			if j := strings.Index(l, "- ["); j >= 0 {
				start = j + 2
			}
		}
		if start < 0 {
			if i == 1 {
				continue // introduction with an empty list
			}
			break
		}
		var tokens []string
		if json.Unmarshal([]byte(l[start:]), &tokens) == nil && len(tokens) > 0 {
			out = append(out, tokens)
		}
	}
	return out
}

// snapshot records the approved prefix set at t. An empty set from a subagent is
// ignored: subagents run with their own, often empty, rules and say nothing about
// what the user approved.
func (x *extractor) snapshot(t time.Time, prefixes [][]string) {
	if t.IsZero() {
		return
	}
	if len(prefixes) == 0 && x.source == "subagent" {
		return
	}
	clean := make([][]string, 0, len(prefixes))
	keys := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if len(p) == 0 {
			continue
		}
		clean = append(clean, p)
		keys = append(keys, PatternJSON(toPositions(p)))
	}
	sort.Strings(keys)
	key := strings.Join(keys, "\x00")
	if n := len(x.runs); n > 0 && x.runKey == key {
		if t.After(x.runs[n-1].To) {
			x.runs[n-1].To = t
		}
		return
	}
	x.runKey = key
	x.runs = append(x.runs, PrefixRun{From: t, To: t, Prefixes: clean})
}

func toPositions(tokens []string) [][]string {
	out := make([][]string, len(tokens))
	for i, t := range tokens {
		out[i] = []string{t}
	}
	return out
}

// callArgs are the arguments of an exec_command or shell function call.
type callArgs struct {
	Cmd                string          `json:"cmd"`
	Command            json.RawMessage `json:"command"`
	SandboxPermissions string          `json:"sandbox_permissions"`
	PrefixRule         json.RawMessage `json:"prefix_rule"`
	Justification      string          `json:"justification"`
}

func (x *extractor) functionCall(b []byte) {
	e, ok := x.decode(b)
	if !ok || e.Type != "response_item" {
		return
	}
	var p struct {
		Type      string `json:"type"`
		Name      string `json:"name"`
		CallID    string `json:"call_id"`
		Arguments string `json:"arguments"`
	}
	if json.Unmarshal(e.Payload, &p) != nil || p.Type != "function_call" || (p.Name != "exec_command" && p.Name != "shell") {
		return
	}
	var a callArgs
	if json.Unmarshal([]byte(p.Arguments), &a) != nil {
		return
	}
	t := parseTime(e.Timestamp)
	keys := a.keys()
	if a.SandboxPermissions != "require_escalated" {
		x.countOnce(p.CallID, keys, t)
		return
	}
	pc := &pendingCall{esc: -1, keys: keys, t: t}
	var prefix []string
	if json.Unmarshal(a.PrefixRule, &prefix) == nil && len(prefix) > 0 && len(x.escs) < maxEscalations {
		pc.esc = len(x.escs)
		x.escs = append(x.escs, Escalation{T: t, Prefix: prefix, Justification: shorten(risk.Redact(a.Justification), maxJustification)})
	}
	if p.CallID == "" {
		// No id to match the output with; assume it ran.
		if pc.esc >= 0 {
			x.escs[pc.esc].Ran = true
		}
		x.count(keys, t)
		return
	}
	x.pending[p.CallID] = pc
}

// keys returns the usage keys of the command in the arguments.
func (a callArgs) keys() []match.Key {
	if a.Cmd != "" {
		return dedupeKeys(match.LineKeys(a.Cmd))
	}
	return commandKeys(a.Command)
}

// commandKeys reads a command given as an argv array or a string.
func commandKeys(raw json.RawMessage) []match.Key {
	var argv []string
	if json.Unmarshal(raw, &argv) == nil && len(argv) > 0 {
		return dedupeKeys(match.ArgvKeys(argv))
	}
	var line string
	if json.Unmarshal(raw, &line) == nil && line != "" {
		return dedupeKeys(match.LineKeys(line))
	}
	return nil
}

func (x *extractor) localShell(b []byte) {
	e, ok := x.decode(b)
	if !ok || e.Type != "response_item" {
		return
	}
	var p struct {
		Type   string `json:"type"`
		CallID string `json:"call_id"`
		ID     string `json:"id"`
		Action struct {
			Command json.RawMessage `json:"command"`
		} `json:"action"`
	}
	if json.Unmarshal(e.Payload, &p) != nil || p.Type != "local_shell_call" {
		return
	}
	id := p.CallID
	if id == "" {
		id = p.ID
	}
	x.countOnce(id, commandKeys(p.Action.Command), parseTime(e.Timestamp))
}

// commandItem handles event_msg item_completed records for executed commands.
func (x *extractor) commandItem(b []byte) {
	e, ok := x.decode(b)
	if !ok || e.Type != "event_msg" {
		return
	}
	var p struct {
		Type string `json:"type"`
		Item struct {
			Type    string          `json:"type"`
			ID      string          `json:"id"`
			Status  string          `json:"status"`
			Command json.RawMessage `json:"command"`
		} `json:"item"`
	}
	if json.Unmarshal(e.Payload, &p) != nil || p.Type != "item_completed" || p.Item.Type != "CommandExecution" {
		return
	}
	if p.Item.Status == "declined" {
		return
	}
	t := parseTime(e.Timestamp)
	if pc, ok := x.pending[p.Item.ID]; ok && p.Item.ID != "" {
		// The command ran, so an escalation that asked for it was approved.
		if pc.esc >= 0 {
			x.escs[pc.esc].Ran = true
		}
		delete(x.pending, p.Item.ID)
		x.countOnce(p.Item.ID, pc.keys, pc.t)
		return
	}
	x.countOnce(p.Item.ID, commandKeys(p.Item.Command), t)
}

// failureMarkers start the output of a command that was refused or never started.
var failureMarkers = []string{"exec_command failed", "aborted by user", "rejected by user", "command was rejected"}

func (x *extractor) callOutput(b []byte) {
	var hit string
	for id := range x.pending {
		if bytes.Contains(b, []byte(id)) {
			hit = id
			break
		}
	}
	if hit == "" {
		return
	}
	e, ok := x.decode(b)
	if !ok || e.Type != "response_item" {
		return
	}
	var p struct {
		Type   string          `json:"type"`
		CallID string          `json:"call_id"`
		Output json.RawMessage `json:"output"`
	}
	if json.Unmarshal(e.Payload, &p) != nil || p.Type != "function_call_output" {
		return
	}
	pc, ok := x.pending[p.CallID]
	if !ok {
		return
	}
	delete(x.pending, p.CallID)
	var out string
	_ = json.Unmarshal(p.Output, &out) // a non-string output counts as success
	ran := true
	for _, m := range failureMarkers {
		if strings.HasPrefix(out, m) {
			ran = false
		}
	}
	if pc.esc >= 0 {
		x.escs[pc.esc].Ran = ran
	}
	if ran {
		x.countOnce(p.CallID, pc.keys, pc.t)
	} else {
		x.counted[p.CallID] = true // a refused command never ran, so it is not use
	}
}

// countOnce counts a command unless its call id was counted already. A command can
// appear as a function call and again as a completed item with the same id.
func (x *extractor) countOnce(id string, keys []match.Key, t time.Time) {
	if id != "" {
		if x.counted[id] {
			return
		}
		x.counted[id] = true
	}
	x.count(keys, t)
}

func (x *extractor) count(keys []match.Key, t time.Time) {
	ts := t.Unix()
	for _, k := range keys {
		u := x.usage[k]
		u.Count++
		if ts > u.Last {
			u.Last = ts
		}
		x.usage[k] = u
	}
}

// dedupeKeys removes repeats, so a command counts once per key.
func dedupeKeys(keys []match.Key) []match.Key {
	if len(keys) < 2 {
		return keys
	}
	seen := make(map[match.Key]struct{}, len(keys))
	out := keys[:0]
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
