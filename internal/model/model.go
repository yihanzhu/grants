// Package model holds the types shared by every part of grants.
//
// A Grant is a standing permission an AI agent holds: a rule that lets it act
// without asking, or a folder it trusts. Adapters (one per agent) find grants in
// config files, date them from local history, and measure how often they were used.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Agent string

const (
	ClaudeCode Agent = "claude-code"
	Codex      Agent = "codex"
)

type Kind string

const (
	KindRule  Kind = "rule"  // a pattern the agent may run or use without asking
	KindTrust Kind = "trust" // a folder the agent trusts
)

type Scope string

const (
	ScopeUser    Scope = "user"    // applies in every project for this user
	ScopeProject Scope = "project" // shared project settings, often committed to git
	ScopeLocal   Scope = "local"   // per-user project settings
	ScopeManaged Scope = "managed" // admin or org policy; never revoked by grants
	ScopeLegacy  Scope = "legacy"  // old location the agent still reads
)

type Status string

const (
	StatusActive  Status = "active"  // present in config now
	StatusGone    Status = "gone"    // seen in history, not in config now
	StatusUnknown Status = "unknown" // seen in history; the config that may hold it cannot be read now
)

type Level string

const (
	RiskLow    Level = "low"
	RiskMedium Level = "medium"
	RiskHigh   Level = "high"
)

// Rank orders levels for sorting: high > medium > low.
func (l Level) Rank() int {
	switch l {
	case RiskHigh:
		return 2
	case RiskMedium:
		return 1
	}
	return 0
}

type Flag string

const (
	FlagDeadPath  Flag = "dead-path" // points to a file or folder that no longer exists
	FlagOneOff    Flag = "one-off"   // looks like a single approval that was kept forever
	FlagUnused    Flag = "unused"    // no matching use within the unused window
	FlagSecret    Flag = "secret"    // the rule text contains a credential-like string
	FlagCommitted Flag = "committed" // lives in a git-tracked team file
)

type Grant struct {
	ID       string     `json:"id"`  // short stable id derived from Key
	Key      string     `json:"key"` // correlation key; see the Key* helpers
	Agent    Agent      `json:"agent"`
	Kind     Kind       `json:"kind"`
	Value    string     `json:"value"`             // display form: Claude rule, Codex pattern as shell words, or folder path
	Pattern  [][]string `json:"pattern,omitempty"` // Codex rules: one entry per token position, listing its alternatives
	Tool     string     `json:"tool,omitempty"`    // Claude tool name (Bash, Read, Edit, WebFetch, mcp__x__y ...); "exec" for Codex rules
	Scope    Scope      `json:"scope"`
	Project  string     `json:"project,omitempty"` // folder the grant is limited to; empty means everywhere
	Location Location   `json:"location"`          // where it lives now; empty File for gone grants
	Status   Status     `json:"status"`

	Revocable  bool   `json:"revocable"`
	RevokeNote string `json:"revoke_note,omitempty"` // why not revocable, or what the user must do after (e.g. restart Codex)

	Granted  Window     `json:"granted"`
	LastSeen time.Time  `json:"last_seen,omitempty"` // last time history showed it present (gone and unknown grants)
	Usage    Usage      `json:"usage"`
	Risk     Risk       `json:"risk"`
	Flags    []Flag     `json:"flags,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"` // oldest first; short and redacted
}

func (g *Grant) HasFlag(f Flag) bool {
	for _, x := range g.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// Location says where a grant lives. Revoke re-finds the grant by Kind and Value or
// Pattern inside File at revoke time, so Pointer and Line are for display only.
type Location struct {
	File    string `json:"file,omitempty"`
	Pointer string `json:"pointer,omitempty"` // e.g. permissions.allow, projects."/x".trust_level, prefix_rule
	Line    int    `json:"line,omitempty"`    // 1-based; 0 when unknown
}

// Window brackets when a grant was created: after After, at or before Before.
// A zero time means that bound is unknown.
type Window struct {
	After  time.Time `json:"after,omitempty"`
	Before time.Time `json:"before,omitempty"`
	Approx bool      `json:"approx,omitempty"` // Before is an estimate, e.g. the first session in a trusted folder
	Source string    `json:"source,omitempty"` // what dated it, in plain words
}

// Exact reports whether the window is narrow enough to show as one moment.
func (w Window) Exact() bool {
	return !w.After.IsZero() && !w.Before.IsZero() && w.Before.Sub(w.After) <= time.Minute
}

// Usage counts history records that a grant matched.
type Usage struct {
	Known bool      `json:"known"` // false when usage cannot be measured for this grant
	Count int       `json:"count"`
	Last  time.Time `json:"last,omitempty"`
	Since time.Time `json:"since,omitempty"` // oldest history record scanned for this agent
}

type Risk struct {
	Level   Level    `json:"level"`
	Reasons []string `json:"reasons,omitempty"`
}

type Evidence struct {
	Time   time.Time `json:"time"`
	What   string    `json:"what"`             // present, absent, added, removed, approved-always, proposed, first-session, file-created
	Detail string    `json:"detail,omitempty"` // short and redacted
	Source string    `json:"source,omitempty"` // file path, optionally with :line
}

// Report is what one agent adapter returns.
type Report struct {
	Agent    Agent      `json:"agent"`
	Found    bool       `json:"found"` // the agent's home folder exists on this machine
	Grants   []Grant    `json:"grants"`
	Notes    []Note     `json:"notes,omitempty"`
	Coverage []Coverage `json:"coverage,omitempty"`
}

type Note struct {
	Level string `json:"level"` // info or warn
	Text  string `json:"text"`
}

// Coverage describes one history source an adapter read.
type Coverage struct {
	Source string    `json:"source"` // e.g. "session transcripts"
	Files  int       `json:"files"`
	From   time.Time `json:"from,omitempty"`
	To     time.Time `json:"to,omitempty"`
}

// Env holds every machine-specific input, so tests can point grants at a fake home.
type Env struct {
	Home        string // user home folder
	ClaudeDir   string // ~/.claude, or $CLAUDE_CONFIG_DIR
	ClaudeJSON  string // ~/.claude.json
	CodexHome   string // ~/.codex, or $CODEX_HOME
	StateDir    string // where grants keeps its cache, snapshots and backups
	Now         time.Time
	UnusedAfter time.Duration // a grant with no matching use for this long gets FlagUnused
}

// Keys correlate the same grant across config files and history.
func KeyClaudeRule(file, rule string) string { return "claude-code|rule|" + file + "|" + rule }
func KeyClaudeTrust(path string) string      { return "claude-code|trust|" + path }

// KeyCodexRule uses the JSON encoding of the pattern tokens. History snapshots do not
// say which rules file a prefix came from, so the file is not part of the key.
func KeyCodexRule(patternJSON string) string { return "codex|rule|" + patternJSON }
func KeyCodexTrust(path string) string       { return "codex|trust|" + path }

// MakeID returns the short id shown to users.
func MakeID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:7]
}
